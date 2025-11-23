#!/usr/bin/env python3
"""
privEsc Bootstrapper

A quality-of-life tool for cybersecurity certifications (OSCP, CPTS, etc.) that
automates the download and organization of commonly used certification tools.

Author: rzz0 (https://github.com/rzz0)
"""

import argparse
import logging
import os
import shutil
import stat
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
import tarfile
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

LOGGER = logging.getLogger("bootstrap")


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )


def validate_relative(target: str) -> Path:
    p = Path(target)
    if p.is_absolute() or any(part == ".." for part in p.parts):
        raise ValueError(f"Invalid target path: {target}")
    return p


def safe_write(path: Path, data: bytes) -> None:
    if not data:
        raise ValueError(f"Refusing to write empty file: {path}")

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass

    fd, tmp = tempfile.mkstemp(prefix="dl", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def checksum_path_for(base: Path, rel: Path) -> Path:
    cdir = base / "core" / "checksums" / rel.parent
    try:
        cdir.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    return cdir / (rel.name + ".sha256")


def write_checksum(path: Path, sha_value: str) -> None:
    path.write_text(sha_value + "\n", encoding="utf-8")


def load_checksum(path: Path) -> Optional[str]:
    if not path.exists():
        return None
    return path.read_text(encoding="utf-8").strip()


def download(url: str, timeout: int = 15) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "privEsc-bootstrap/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
            if not data:
                raise RuntimeError(f"Empty response from {url}")
            return data
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
        raise RuntimeError(f"Failed to download {url}: {exc}") from exc


def make_executable(path: Path) -> None:
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def extract_zip_full(zip_bytes: bytes, base_target: Path, dry_run: bool) -> None:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp_zip:
        tmp_zip.write(zip_bytes)
        tmp_zip_path = Path(tmp_zip.name)

    try:
        with zipfile.ZipFile(tmp_zip_path, "r") as zf:
            for member in zf.infolist():

                if member.is_dir():
                    continue

                member_path = Path(member.filename)

                if any(part == ".." for part in member_path.parts):
                    LOGGER.warning("Skipping unsafe ZIP entry: %s", member.filename)
                    continue

                out_path = base_target / member_path

                if dry_run:
                    LOGGER.info("[dry-run] Would extract ZIP -> %s", out_path)
                    continue

                data = zf.read(member)
                safe_write(out_path, data)
                LOGGER.debug("Extracted -> %s", out_path)

    finally:
        tmp_zip_path.unlink()


def extract_tar_gz_full(tar_gz_bytes: bytes, base_target: Path, dry_run: bool) -> None:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".tar.gz") as tmp_tar:
        tmp_tar.write(tar_gz_bytes)
        tmp_tar_path = Path(tmp_tar.name)

    try:
        with tarfile.open(tmp_tar_path, "r:gz") as tf:
            for member in tf.getmembers():

                if member.isdir():
                    continue

                member_path = Path(member.name)

                if any(part == ".." for part in member_path.parts):
                    LOGGER.warning("Skipping unsafe TAR entry: %s", member.name)
                    continue

                out_path = base_target / member_path

                if dry_run:
                    LOGGER.info("[dry-run] Would extract TAR.GZ -> %s", out_path)
                    continue

                extracted = tf.extractfile(member)
                if extracted:
                    data = extracted.read()
                    safe_write(out_path, data)
                    LOGGER.debug("Extracted -> %s", out_path)

    finally:
        tmp_tar_path.unlink()


def load_assets_from_yaml(catalog_path: Path) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    try:
        import yaml
    except ImportError:
        raise SystemExit("PyYAML not installed. Install via: pip install pyyaml")

    data = yaml.safe_load(catalog_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "assets" not in data:
        raise ValueError("Invalid catalog format: missing 'assets'")
    return data["assets"], data.get("post_copy", [])


def process_asset(base: Path, asset: Dict[str, Any], dry_run: bool, force: bool = False) -> None:
    name = asset["name"]
    url = asset["url"]
    rel = validate_relative(asset["target"])
    dst = base / rel
    executable = bool(asset.get("postchmod_x", False))

    is_zip = url.lower().endswith(".zip") or dst.name.lower().endswith(".zip")
    is_tar_gz = url.lower().endswith(".tar.gz") or url.lower().endswith(".tgz") or dst.name.lower().endswith(".tar.gz") or dst.name.lower().endswith(".tgz")

    checksum_path = checksum_path_for(base, rel)

    if dst.exists() and not is_zip and not is_tar_gz and not force:
        old_hash = load_checksum(checksum_path)
        if old_hash:
            try:
                current_hash = compute_sha256(dst)
                if current_hash == old_hash:
                    LOGGER.info("%s is up-to-date (sha256 match) → skipping", name)
                    return
                else:
                    LOGGER.warning(
                        "%s changed (sha mismatch: %s != %s). Re-downloading.",
                        name, current_hash, old_hash
                    )
            except Exception as exc:
                LOGGER.warning("Failed to hash %s: %s. Redownloading.", dst, exc)

    if dry_run:
        if force:
            LOGGER.info("[dry-run] Would force re-download %s → %s", name, dst)
        elif is_zip:
            LOGGER.info("[dry-run] Would download ZIP %s → extract into %s", name, dst.parent)
        elif is_tar_gz:
            LOGGER.info("[dry-run] Would download TAR.GZ %s → extract into %s", name, dst.parent)
        else:
            LOGGER.info("[dry-run] Would download %s → %s", name, dst)

        if executable:
            LOGGER.info("[dry-run] Would chmod +x %s", dst)
        return

    if force:
        LOGGER.info("Force re-downloading %s from %s", name, url)
    else:
        LOGGER.info("Downloading %s from %s", name, url)
    data = download(url)

    if is_zip:
        LOGGER.debug("ZIP detected — extracting full contents…")
        extract_zip_full(data, base / rel.parent, dry_run=False)

        sha_value = hashlib.sha256(data).hexdigest()
        write_checksum(checksum_path, sha_value)
        return

    if is_tar_gz:
        LOGGER.debug("TAR.GZ detected — extracting full contents…")
        extract_tar_gz_full(data, base / rel.parent, dry_run=False)

        sha_value = hashlib.sha256(data).hexdigest()
        write_checksum(checksum_path, sha_value)
        return

    safe_write(dst, data)

    sha_value = hashlib.sha256(data).hexdigest()
    write_checksum(checksum_path, sha_value)

    if executable:
        make_executable(dst)
        LOGGER.debug("Marked executable")

    LOGGER.info("OK → %s", dst)


def process_post_copy(base: Path, copy_item: Dict[str, Any], dry_run: bool) -> None:
    source_rel = validate_relative(copy_item["source"])
    dest_rel = validate_relative(copy_item["destination"])
    
    source_path = base / source_rel
    dest_path = base / dest_rel
    
    if not source_path.exists():
        LOGGER.warning("Source not found: %s → skipping", source_path)
        return
    
    if dry_run:
        LOGGER.info("[dry-run] Would copy %s → %s", source_path, dest_path)
        return
    
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_path, dest_path)
    LOGGER.info("Copied %s → %s", source_path, dest_path)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Minimal privEsc bootstrapper")
    p.add_argument("--base-dir", default="~/privEsc", help="Destination directory")
    p.add_argument("--verbose", action="store_true", help="Enable debug logging")
    p.add_argument("--dry-run", action="store_true", help="Show planned actions")
    p.add_argument("--force", action="store_true", help="Force re-download even if file exists and hash matches")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    setup_logging(args.verbose)

    base = Path(args.base_dir).expanduser().resolve()
    base.mkdir(parents=True, exist_ok=True)

    script_dir = Path(__file__).parent.resolve()
    catalog_path = script_dir / "bootstrapper_catalog.yaml"

    try:
        assets, post_copy = load_assets_from_yaml(catalog_path)
    except Exception as exc:
        LOGGER.error("Failed to load catalog: %s", exc)
        return 1

    max_workers = min(8, os.cpu_count() or 4)
    LOGGER.info("Using %d workers for parallel downloads", max_workers)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(process_asset, base, asset, args.dry_run, args.force): asset
            for asset in assets
        }

        for future in as_completed(futures):
            asset = futures[future]
            try:
                future.result()
            except Exception as exc:
                LOGGER.error("Failed processing %s: %s", asset.get("name"), exc)

    for copy_item in post_copy:
        try:
            process_post_copy(base, copy_item, args.dry_run)
        except Exception as exc:
            LOGGER.error("Failed post-copy: %s", exc)

    return 0


if __name__ == "__main__":
    sys.exit(main())
