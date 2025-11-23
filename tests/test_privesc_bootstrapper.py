#!/usr/bin/env python3
"""Unit tests for privesc_bootstrapper.py"""

import hashlib
import logging
import stat
import tempfile
import urllib.error
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch, mock_open, MagicMock
from concurrent.futures import as_completed

import pytest

import privesc_bootstrapper


class TestValidateRelative:
    """Tests for validate_relative function"""

    def test_valid_relative_path(self):
        """Test valid relative paths"""
        assert privesc_bootstrapper.validate_relative("win_enum/tool.exe") == Path("win_enum/tool.exe")
        assert privesc_bootstrapper.validate_relative("tool.exe") == Path("tool.exe")

    def test_absolute_path_raises(self):
        """Test that absolute paths raise ValueError"""
        with pytest.raises(ValueError, match="Invalid target path"):
            privesc_bootstrapper.validate_relative("/absolute/path")

    def test_path_traversal_raises(self):
        """Test that paths with .. raise ValueError"""
        with pytest.raises(ValueError, match="Invalid target path"):
            privesc_bootstrapper.validate_relative("../etc/passwd")
        with pytest.raises(ValueError, match="Invalid target path"):
            privesc_bootstrapper.validate_relative("win_enum/../../etc/passwd")


class TestSafeWrite:
    """Tests for safe_write function"""

    def test_write_file(self, tmp_path):
        """Test writing a file"""
        test_file = tmp_path / "test.txt"
        data = b"test content"
        privesc_bootstrapper.safe_write(test_file, data)
        assert test_file.exists()
        assert test_file.read_bytes() == data

    def test_empty_file_raises(self, tmp_path):
        """Test that empty files raise ValueError"""
        test_file = tmp_path / "empty.txt"
        with pytest.raises(ValueError, match="Refusing to write empty file"):
            privesc_bootstrapper.safe_write(test_file, b"")

    def test_creates_parent_directories(self, tmp_path):
        """Test that parent directories are created"""
        test_file = tmp_path / "subdir" / "nested" / "file.txt"
        data = b"content"
        privesc_bootstrapper.safe_write(test_file, data)
        assert test_file.exists()
        assert test_file.read_bytes() == data


class TestComputeSHA256:
    """Tests for compute_sha256 function"""

    def test_compute_hash(self, tmp_path):
        """Test SHA-256 computation"""
        test_file = tmp_path / "test.txt"
        content = b"test content"
        test_file.write_bytes(content)

        expected_hash = hashlib.sha256(content).hexdigest()
        actual_hash = privesc_bootstrapper.compute_sha256(test_file)

        assert actual_hash == expected_hash

    def test_hash_consistency(self, tmp_path):
        """Test that same content produces same hash"""
        test_file = tmp_path / "test.txt"
        content = b"same content"
        test_file.write_bytes(content)

        hash1 = privesc_bootstrapper.compute_sha256(test_file)
        hash2 = privesc_bootstrapper.compute_sha256(test_file)

        assert hash1 == hash2


class TestChecksumPath:
    """Tests for checksum_path_for function"""

    def test_checksum_path_generation(self, tmp_path):
        """Test checksum path generation"""
        base = tmp_path
        rel = Path("win_enum/tool.exe")
        checksum_path = privesc_bootstrapper.checksum_path_for(base, rel)

        expected = base / "core" / "checksums" / "win_enum" / "tool.exe.sha256"
        assert checksum_path == expected

    def test_checksum_directory_created(self, tmp_path):
        """Test that checksum directory is created"""
        base = tmp_path
        rel = Path("nested/path/file.exe")
        checksum_path = privesc_bootstrapper.checksum_path_for(base, rel)

        assert checksum_path.parent.exists()


class TestChecksumIO:
    """Tests for write_checksum and load_checksum functions"""

    def test_write_and_load_checksum(self, tmp_path):
        """Test writing and loading checksum"""
        checksum_file = tmp_path / "test.sha256"
        hash_value = "abc123def456"

        privesc_bootstrapper.write_checksum(checksum_file, hash_value)
        assert checksum_file.exists()

        loaded = privesc_bootstrapper.load_checksum(checksum_file)
        assert loaded == hash_value

    def test_load_nonexistent_checksum(self, tmp_path):
        """Test loading non-existent checksum returns None"""
        checksum_file = tmp_path / "nonexistent.sha256"
        assert privesc_bootstrapper.load_checksum(checksum_file) is None


class TestDownload:
    """Tests for download function"""

    @patch("urllib.request.urlopen")
    def test_successful_download(self, mock_urlopen):
        """Test successful download"""
        mock_response = Mock()
        mock_response.read.return_value = b"test data"
        mock_urlopen.return_value.__enter__.return_value = mock_response

        data = privesc_bootstrapper.download("https://example.com/file")
        assert data == b"test data"

    @patch("urllib.request.urlopen")
    def test_empty_response_raises(self, mock_urlopen):
        """Test that empty response raises RuntimeError"""
        mock_response = Mock()
        mock_response.read.return_value = b""
        mock_urlopen.return_value.__enter__.return_value = mock_response

        with pytest.raises(RuntimeError, match="Empty response"):
            privesc_bootstrapper.download("https://example.com/file")

    @patch("urllib.request.urlopen")
    def test_download_error_raises(self, mock_urlopen):
        """Test that download errors raise RuntimeError"""
        mock_urlopen.side_effect = urllib.error.URLError("Connection failed")

        with pytest.raises(RuntimeError, match="Failed to download"):
            privesc_bootstrapper.download("https://example.com/file")


class TestExtractZipFull:
    """Tests for extract_zip_full function"""

    def test_extract_zip(self, tmp_path):
        """Test ZIP extraction"""

        zip_data = self._create_test_zip()

        extract_dir = tmp_path / "extract"
        privesc_bootstrapper.extract_zip_full(zip_data, extract_dir, dry_run=False)


        assert (extract_dir / "file1.txt").exists()
        assert (extract_dir / "subdir" / "file2.txt").exists()
        assert (extract_dir / "file1.txt").read_text() == "content1"
        assert (extract_dir / "subdir" / "file2.txt").read_text() == "content2"

    def test_extract_zip_dry_run(self, tmp_path):
        """Test ZIP extraction in dry-run mode"""
        zip_data = self._create_test_zip()
        extract_dir = tmp_path / "extract"

        privesc_bootstrapper.extract_zip_full(zip_data, extract_dir, dry_run=True)


        assert not (extract_dir / "file1.txt").exists()

    def test_extract_zip_skips_unsafe_paths(self, tmp_path):
        """Test that ZIP extraction skips unsafe paths"""

        zip_data = self._create_unsafe_zip()

        extract_dir = tmp_path / "extract"
        privesc_bootstrapper.extract_zip_full(zip_data, extract_dir, dry_run=False)


        assert not (tmp_path / "etc" / "passwd").exists()

    def _create_test_zip(self) -> bytes:
        """Helper to create a test ZIP file in memory"""
        import io
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("file1.txt", "content1")
            zf.writestr("subdir/file2.txt", "content2")
        return zip_buffer.getvalue()

    def _create_unsafe_zip(self) -> bytes:
        """Helper to create a ZIP with unsafe paths"""
        import io
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("../../etc/passwd", "unsafe content")
            zf.writestr("safe.txt", "safe content")
        return zip_buffer.getvalue()


class TestLoadAssetsFromYaml:
    """Tests for load_assets_from_yaml function"""

    def test_load_valid_yaml(self, tmp_path):
        """Test loading valid YAML catalog"""
        catalog_file = tmp_path / "catalog.yaml"
        catalog_file.write_text("""
assets:
  - name: "test.exe"
    target: "win_enum/test.exe"
    url: "https://example.com/test.exe"
    note: "Test tool"
""")

        assets, post_copy = privesc_bootstrapper.load_assets_from_yaml(catalog_file)
        assert len(assets) == 1
        assert assets[0]["name"] == "test.exe"
        assert assets[0]["target"] == "win_enum/test.exe"
        assert post_copy == []

    def test_invalid_yaml_format_raises(self, tmp_path):
        """Test that invalid YAML format raises an error"""
        import yaml
        catalog_file = tmp_path / "catalog.yaml"
        catalog_file.write_text("invalid: yaml: content")


        with pytest.raises((ValueError, yaml.scanner.ScannerError)):
            privesc_bootstrapper.load_assets_from_yaml(catalog_file)

    def test_missing_assets_key_raises(self, tmp_path):
        """Test that missing 'assets' key raises ValueError"""
        catalog_file = tmp_path / "catalog.yaml"
        catalog_file.write_text("other_key: value")

        with pytest.raises(ValueError, match="Invalid catalog format"):
            privesc_bootstrapper.load_assets_from_yaml(catalog_file)

    def test_load_yaml_with_post_copy(self, tmp_path):
        """Test loading YAML catalog with post_copy section"""
        catalog_file = tmp_path / "catalog.yaml"
        catalog_file.write_text("""
assets:
  - name: "test.exe"
    target: "win_enum/test.exe"
    url: "https://example.com/test.exe"
post_copy:
  - source: "source/file.exe"
    destination: "dest/file.exe"
""")

        assets, post_copy = privesc_bootstrapper.load_assets_from_yaml(catalog_file)
        assert len(assets) == 1
        assert len(post_copy) == 1
        assert post_copy[0]["source"] == "source/file.exe"
        assert post_copy[0]["destination"] == "dest/file.exe"


class TestProcessAsset:
    """Tests for process_asset function"""

    @patch("privesc_bootstrapper.download")
    def test_process_asset_downloads_file(self, mock_download, tmp_path):
        """Test processing a regular asset"""
        mock_download.return_value = b"file content"
        asset = {
            "name": "test.exe",
            "target": "win_enum/test.exe",
            "url": "https://example.com/test.exe",
            "postchmod_x": False,
        }

        privesc_bootstrapper.process_asset(tmp_path, asset, dry_run=False, force=False)

        mock_download.assert_called_once()
        assert (tmp_path / "win_enum" / "test.exe").exists()
        assert (tmp_path / "win_enum" / "test.exe").read_bytes() == b"file content"

    def test_process_asset_dry_run(self, tmp_path):
        """Test processing asset in dry-run mode"""
        asset = {
            "name": "test.exe",
            "target": "win_enum/test.exe",
            "url": "https://example.com/test.exe",
        }


        privesc_bootstrapper.process_asset(tmp_path, asset, dry_run=True, force=False)

        assert not (tmp_path / "win_enum" / "test.exe").exists()

    @patch("privesc_bootstrapper.download")
    def test_process_asset_skips_existing_file(self, mock_download, tmp_path):
        """Test that existing file with matching hash is skipped"""

        test_file = tmp_path / "win_enum" / "test.exe"
        test_file.parent.mkdir(parents=True)
        content = b"existing content"
        test_file.write_bytes(content)

        checksum_path = tmp_path / "core" / "checksums" / "win_enum" / "test.exe.sha256"
        checksum_path.parent.mkdir(parents=True)
        hash_value = hashlib.sha256(content).hexdigest()
        checksum_path.write_text(hash_value)

        asset = {
            "name": "test.exe",
            "target": "win_enum/test.exe",
            "url": "https://example.com/test.exe",
        }

        privesc_bootstrapper.process_asset(tmp_path, asset, dry_run=False, force=False)


        mock_download.assert_not_called()

    @patch("privesc_bootstrapper.download")
    def test_process_asset_force_re_downloads(self, mock_download, tmp_path):
        """Test that --force re-downloads even if file exists"""
        test_file = tmp_path / "win_enum" / "test.exe"
        test_file.parent.mkdir(parents=True)
        test_file.write_bytes(b"old content")

        mock_download.return_value = b"new content"
        asset = {
            "name": "test.exe",
            "target": "win_enum/test.exe",
            "url": "https://example.com/test.exe",
        }

        privesc_bootstrapper.process_asset(tmp_path, asset, dry_run=False, force=True)

        mock_download.assert_called_once()
        assert test_file.read_bytes() == b"new content"

    @patch("privesc_bootstrapper.download")
    def test_process_asset_zip_extraction(self, mock_download, tmp_path):
        """Test processing ZIP asset"""

        import io
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("extracted.txt", "zip content")
        zip_data = zip_buffer.getvalue()

        mock_download.return_value = zip_data
        asset = {
            "name": "archive.zip",
            "target": "win_enum/archive.zip",
            "url": "https://example.com/archive.zip",
        }

        privesc_bootstrapper.process_asset(tmp_path, asset, dry_run=False, force=False)


        assert (tmp_path / "win_enum" / "extracted.txt").exists()
        assert (tmp_path / "win_enum" / "extracted.txt").read_text() == "zip content"

    @patch("privesc_bootstrapper.download")
    def test_process_asset_tar_gz_extraction(self, mock_download, tmp_path):
        """Test processing TAR.GZ asset"""
        import tarfile
        import io
        import gzip
        

        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w") as tf:
            file_info = tarfile.TarInfo(name="extracted.txt")
            file_info.size = len(b"tar content")
            tf.addfile(file_info, io.BytesIO(b"tar content"))
        
        tar_data = tar_buffer.getvalue()
        gz_buffer = io.BytesIO()
        with gzip.GzipFile(fileobj=gz_buffer, mode="wb") as gz:
            gz.write(tar_data)
        tar_gz_data = gz_buffer.getvalue()

        mock_download.return_value = tar_gz_data
        asset = {
            "name": "archive.tar.gz",
            "target": "xplat_tun/ligolo/archive.tar.gz",
            "url": "https://example.com/archive.tar.gz",
        }

        privesc_bootstrapper.process_asset(tmp_path, asset, dry_run=False, force=False)


        assert (tmp_path / "xplat_tun" / "ligolo" / "extracted.txt").exists()
        assert (tmp_path / "xplat_tun" / "ligolo" / "extracted.txt").read_text() == "tar content"


class TestParseArgs:
    """Tests for parse_args function"""

    @patch("sys.argv", ["script"])
    def test_default_args(self):
        """Test default arguments"""
        args = privesc_bootstrapper.parse_args()
        assert args.base_dir == "~/privEsc"
        assert args.verbose is False
        assert args.dry_run is False
        assert args.force is False

    @patch("sys.argv", ["script", "--base-dir", "/custom/path"])
    def test_custom_base_dir(self):
        """Test custom base directory"""
        args = privesc_bootstrapper.parse_args()
        assert args.base_dir == "/custom/path"

    @patch("sys.argv", ["script", "--verbose", "--dry-run", "--force"])
    def test_flags(self):
        """Test flag arguments"""
        args = privesc_bootstrapper.parse_args()
        assert args.verbose is True
        assert args.dry_run is True
        assert args.force is True


class TestMakeExecutable:
    """Tests for make_executable function"""

    def test_make_executable(self, tmp_path):
        """Test making file executable"""
        test_file = tmp_path / "script.sh"
        test_file.write_text("#!/bin/bash\necho test")


        initial_mode = test_file.stat().st_mode

        privesc_bootstrapper.make_executable(test_file)


        new_mode = test_file.stat().st_mode
        assert new_mode != initial_mode
        assert new_mode & stat.S_IXUSR
        assert new_mode & stat.S_IXGRP
        assert new_mode & stat.S_IXOTH


class TestSetupLogging:
    """Tests for setup_logging function"""

    @patch("logging.basicConfig")
    def test_setup_logging_info(self, mock_basic_config):
        """Test logging setup with INFO level"""
        privesc_bootstrapper.setup_logging(verbose=False)
        mock_basic_config.assert_called_once()
        call_kwargs = mock_basic_config.call_args[1]
        assert call_kwargs["level"] == logging.INFO

    @patch("logging.basicConfig")
    def test_setup_logging_debug(self, mock_basic_config):
        """Test logging setup with DEBUG level"""
        privesc_bootstrapper.setup_logging(verbose=True)
        mock_basic_config.assert_called_once()
        call_kwargs = mock_basic_config.call_args[1]
        assert call_kwargs["level"] == logging.DEBUG


class TestSafeWriteEdgeCases:
    """Tests for edge cases in safe_write"""

    @patch("pathlib.Path.mkdir")
    def test_safe_write_oserror_handling(self, mock_mkdir, tmp_path):
        """Test that OSError in mkdir is handled gracefully"""
        mock_mkdir.side_effect = OSError("Permission denied")
        test_file = tmp_path / "test.txt"
        data = b"content"
        
        privesc_bootstrapper.safe_write(test_file, data)
        assert test_file.exists()

    @patch("os.replace")
    @patch("os.path.exists")
    def test_safe_write_cleanup_on_error(self, mock_exists, mock_replace, tmp_path):
        """Test that temp file is cleaned up on error"""
        mock_replace.side_effect = OSError("Replace failed")
        mock_exists.return_value = True
        
        test_file = tmp_path / "test.txt"
        data = b"content"
        
        with pytest.raises(OSError):
            privesc_bootstrapper.safe_write(test_file, data)


class TestChecksumPathEdgeCases:
    """Tests for edge cases in checksum_path_for"""

    @patch("pathlib.Path.mkdir")
    def test_checksum_path_oserror_handling(self, mock_mkdir, tmp_path):
        """Test that OSError in mkdir is handled gracefully"""
        mock_mkdir.side_effect = OSError("Permission denied")
        base = tmp_path
        rel = Path("test.exe")
        
        result = privesc_bootstrapper.checksum_path_for(base, rel)
        assert result == base / "core" / "checksums" / "test.exe.sha256"


class TestExtractTarGzFull:
    """Tests for extract_tar_gz_full function"""

    def test_extract_tar_gz(self, tmp_path):
        """Test TAR.GZ extraction"""
        import tarfile
        import io
        import gzip
        
        tar_data = self._create_test_tar_gz()
        
        extract_dir = tmp_path / "extract"
        privesc_bootstrapper.extract_tar_gz_full(tar_data, extract_dir, dry_run=False)
        
        assert (extract_dir / "file1.txt").exists()
        assert (extract_dir / "subdir" / "file2.txt").exists()
        assert (extract_dir / "file1.txt").read_text() == "content1"
        assert (extract_dir / "subdir" / "file2.txt").read_text() == "content2"

    def test_extract_tar_gz_dry_run(self, tmp_path):
        """Test TAR.GZ extraction in dry-run mode"""
        tar_data = self._create_test_tar_gz()
        extract_dir = tmp_path / "extract"
        
        privesc_bootstrapper.extract_tar_gz_full(tar_data, extract_dir, dry_run=True)
        
        assert not (extract_dir / "file1.txt").exists()

    def test_extract_tar_gz_skips_unsafe_paths(self, tmp_path):
        """Test that TAR.GZ extraction skips unsafe paths"""
        tar_data = self._create_unsafe_tar_gz()
        
        extract_dir = tmp_path / "extract"
        privesc_bootstrapper.extract_tar_gz_full(tar_data, extract_dir, dry_run=False)
        
        assert not (tmp_path / "etc" / "passwd").exists()

    def test_extract_tar_gz_skips_directories(self, tmp_path):
        """Test that TAR.GZ directories are skipped"""
        import tarfile
        import io
        import gzip
        
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w") as tf:
            file_info = tarfile.TarInfo(name="file.txt")
            file_info.size = len(b"content")
            tf.addfile(file_info, io.BytesIO(b"content"))
            
            dir_info = tarfile.TarInfo(name="subdir/")
            dir_info.type = tarfile.DIRTYPE
            tf.addfile(dir_info)
        
        tar_data = tar_buffer.getvalue()
        
        gz_buffer = io.BytesIO()
        with gzip.GzipFile(fileobj=gz_buffer, mode="wb") as gz:
            gz.write(tar_data)
        tar_gz_data = gz_buffer.getvalue()
        
        extract_dir = tmp_path / "extract"
        privesc_bootstrapper.extract_tar_gz_full(tar_gz_data, extract_dir, dry_run=False)
        
        assert (extract_dir / "file.txt").exists()
        assert not (extract_dir / "subdir").is_file()

    def _create_test_tar_gz(self) -> bytes:
        """Helper to create a test TAR.GZ file in memory"""
        import tarfile
        import io
        import gzip
        
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w") as tf:

            file1_info = tarfile.TarInfo(name="file1.txt")
            file1_info.size = len(b"content1")
            tf.addfile(file1_info, io.BytesIO(b"content1"))
            
            file2_info = tarfile.TarInfo(name="subdir/file2.txt")
            file2_info.size = len(b"content2")
            tf.addfile(file2_info, io.BytesIO(b"content2"))
        
        tar_data = tar_buffer.getvalue()
        
        gz_buffer = io.BytesIO()
        with gzip.GzipFile(fileobj=gz_buffer, mode="wb") as gz:
            gz.write(tar_data)
        return gz_buffer.getvalue()

    def _create_unsafe_tar_gz(self) -> bytes:
        """Helper to create a TAR.GZ with unsafe paths"""
        import tarfile
        import io
        import gzip
        
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w") as tf:
            unsafe_info = tarfile.TarInfo(name="../etc/passwd")
            unsafe_info.size = len(b"unsafe")
            tf.addfile(unsafe_info, io.BytesIO(b"unsafe"))
        
        tar_data = tar_buffer.getvalue()
        
        gz_buffer = io.BytesIO()
        with gzip.GzipFile(fileobj=gz_buffer, mode="wb") as gz:
            gz.write(tar_data)
        return gz_buffer.getvalue()


class TestExtractZipFullEdgeCases:
    """Tests for edge cases in extract_zip_full"""

    def test_extract_zip_skips_directories(self, tmp_path):
        """Test that ZIP directories are skipped"""
        import io
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("file.txt", "content")
            zf.writestr("subdir/", "")
        
        extract_dir = tmp_path / "extract"
        privesc_bootstrapper.extract_zip_full(zip_buffer.getvalue(), extract_dir, dry_run=False)
        
        assert (extract_dir / "file.txt").exists()
        assert not (extract_dir / "subdir").is_file()


class TestLoadAssetsFromYamlEdgeCases:
    """Tests for edge cases in load_assets_from_yaml"""

    @patch("builtins.__import__", side_effect=ImportError("No module named 'yaml'"))
    def test_load_assets_yaml_import_error(self, mock_import, tmp_path):
        """Test that ImportError raises SystemExit"""
        catalog_file = tmp_path / "catalog.yaml"
        catalog_file.write_text("assets: []")
        
        with pytest.raises(SystemExit):
            privesc_bootstrapper.load_assets_from_yaml(catalog_file)


class TestProcessAssetEdgeCases:
    """Tests for edge cases in process_asset"""

    @patch("privesc_bootstrapper.download")
    def test_process_asset_hash_mismatch_warning(self, mock_download, tmp_path):
        """Test that hash mismatch triggers warning and re-download"""
        test_file = tmp_path / "win_enum" / "test.exe"
        test_file.parent.mkdir(parents=True)
        test_file.write_bytes(b"old content")
        
        checksum_path = tmp_path / "core" / "checksums" / "win_enum" / "test.exe.sha256"
        checksum_path.parent.mkdir(parents=True)
        checksum_path.write_text("different_hash")
        
        mock_download.return_value = b"new content"
        asset = {
            "name": "test.exe",
            "target": "win_enum/test.exe",
            "url": "https://example.com/test.exe",
        }
        
        privesc_bootstrapper.process_asset(tmp_path, asset, dry_run=False, force=False)
        
        mock_download.assert_called_once()

    @patch("privesc_bootstrapper.download")
    @patch("privesc_bootstrapper.compute_sha256")
    def test_process_asset_hash_computation_error(self, mock_compute, mock_download, tmp_path):
        """Test that hash computation error triggers re-download"""
        test_file = tmp_path / "win_enum" / "test.exe"
        test_file.parent.mkdir(parents=True)
        test_file.write_bytes(b"old content")
        
        checksum_path = tmp_path / "core" / "checksums" / "win_enum" / "test.exe.sha256"
        checksum_path.parent.mkdir(parents=True)
        checksum_path.write_text("some_hash")
        
        mock_compute.side_effect = OSError("Permission denied")
        mock_download.return_value = b"new content"
        asset = {
            "name": "test.exe",
            "target": "win_enum/test.exe",
            "url": "https://example.com/test.exe",
        }
        
        privesc_bootstrapper.process_asset(tmp_path, asset, dry_run=False, force=False)
        
        mock_download.assert_called_once()

    @patch("privesc_bootstrapper.download")
    def test_process_asset_executable_flag(self, mock_download, tmp_path):
        """Test that executable flag makes file executable"""
        mock_download.return_value = b"#!/bin/bash\necho test"
        asset = {
            "name": "script.sh",
            "target": "lin_enum/script.sh",
            "url": "https://example.com/script.sh",
            "postchmod_x": True,
        }
        
        privesc_bootstrapper.process_asset(tmp_path, asset, dry_run=False, force=False)
        
        test_file = tmp_path / "lin_enum" / "script.sh"
        assert test_file.exists()
        assert test_file.stat().st_mode & stat.S_IXUSR

    def test_process_asset_dry_run_zip(self, tmp_path):
        """Test dry-run for ZIP assets"""
        asset = {
            "name": "archive.zip",
            "target": "win_enum/archive.zip",
            "url": "https://example.com/archive.zip",
        }
        
        privesc_bootstrapper.process_asset(tmp_path, asset, dry_run=True, force=False)
        assert not (tmp_path / "win_enum" / "archive.zip").exists()

    def test_process_asset_dry_run_force(self, tmp_path):
        """Test dry-run with force flag"""
        asset = {
            "name": "test.exe",
            "target": "win_enum/test.exe",
            "url": "https://example.com/test.exe",
        }
        
        privesc_bootstrapper.process_asset(tmp_path, asset, dry_run=True, force=True)
        assert not (tmp_path / "win_enum" / "test.exe").exists()

    def test_process_asset_dry_run_executable(self, tmp_path):
        """Test dry-run with executable flag"""
        asset = {
            "name": "script.sh",
            "target": "lin_enum/script.sh",
            "url": "https://example.com/script.sh",
            "postchmod_x": True,
        }
        
        privesc_bootstrapper.process_asset(tmp_path, asset, dry_run=True, force=False)

    def test_process_asset_dry_run_tar_gz(self, tmp_path):
        """Test dry-run for TAR.GZ assets"""
        asset = {
            "name": "archive.tar.gz",
            "target": "xplat_tun/ligolo/archive.tar.gz",
            "url": "https://example.com/archive.tar.gz",
        }
        
        privesc_bootstrapper.process_asset(tmp_path, asset, dry_run=True, force=False)
        assert not (tmp_path / "xplat_tun" / "ligolo" / "archive.tar.gz").exists()


class TestProcessPostCopy:
    """Tests for process_post_copy function"""

    def test_process_post_copy_success(self, tmp_path):
        """Test successful post-copy operation"""
        source_file = tmp_path / "source" / "file.exe"
        source_file.parent.mkdir(parents=True)
        source_file.write_bytes(b"file content")
        
        copy_item = {
            "source": "source/file.exe",
            "destination": "dest/file.exe"
        }
        
        privesc_bootstrapper.process_post_copy(tmp_path, copy_item, dry_run=False)
        
        dest_file = tmp_path / "dest" / "file.exe"
        assert dest_file.exists()
        assert dest_file.read_bytes() == b"file content"

    def test_process_post_copy_dry_run(self, tmp_path):
        """Test post-copy in dry-run mode"""
        source_file = tmp_path / "source" / "file.exe"
        source_file.parent.mkdir(parents=True)
        source_file.write_bytes(b"file content")
        
        copy_item = {
            "source": "source/file.exe",
            "destination": "dest/file.exe"
        }
        
        privesc_bootstrapper.process_post_copy(tmp_path, copy_item, dry_run=True)
        
        dest_file = tmp_path / "dest" / "file.exe"
        assert not dest_file.exists()

    def test_process_post_copy_missing_source(self, tmp_path):
        """Test post-copy with missing source file"""
        copy_item = {
            "source": "source/nonexistent.exe",
            "destination": "dest/file.exe"
        }
        
        privesc_bootstrapper.process_post_copy(tmp_path, copy_item, dry_run=False)
        
        dest_file = tmp_path / "dest" / "file.exe"
        assert not dest_file.exists()

    def test_process_post_copy_invalid_source_path(self, tmp_path):
        """Test post-copy with invalid source path"""
        copy_item = {
            "source": "../etc/passwd",
            "destination": "dest/file.exe"
        }
        
        with pytest.raises(ValueError, match="Invalid target path"):
            privesc_bootstrapper.process_post_copy(tmp_path, copy_item, dry_run=False)

    def test_process_post_copy_invalid_dest_path(self, tmp_path):
        """Test post-copy with invalid destination path"""
        source_file = tmp_path / "source" / "file.exe"
        source_file.parent.mkdir(parents=True)
        source_file.write_bytes(b"file content")
        
        copy_item = {
            "source": "source/file.exe",
            "destination": "../../etc/passwd"
        }
        
        with pytest.raises(ValueError, match="Invalid target path"):
            privesc_bootstrapper.process_post_copy(tmp_path, copy_item, dry_run=False)


class TestMain:
    """Tests for main function"""

    @patch("privesc_bootstrapper.process_post_copy")
    @patch("privesc_bootstrapper.process_asset")
    @patch("privesc_bootstrapper.load_assets_from_yaml")
    @patch("privesc_bootstrapper.setup_logging")
    @patch("privesc_bootstrapper.parse_args")
    def test_main_success(self, mock_parse, mock_logging, mock_load, mock_process, mock_post_copy, tmp_path):
        """Test successful main execution"""
        mock_args = Mock()
        mock_args.base_dir = str(tmp_path)
        mock_args.verbose = False
        mock_args.dry_run = False
        mock_args.force = False
        mock_parse.return_value = mock_args
        
        asset = {"name": "test.exe", "target": "win_enum/test.exe", "url": "https://example.com/test.exe"}
        copy_item = {"source": "source/file.exe", "destination": "dest/file.exe"}
        mock_load.return_value = ([asset], [copy_item])
        
        result = privesc_bootstrapper.main()
        assert result == 0
        mock_process.assert_called_once()
        mock_post_copy.assert_called_once()

    @patch("privesc_bootstrapper.load_assets_from_yaml")
    @patch("privesc_bootstrapper.setup_logging")
    @patch("privesc_bootstrapper.parse_args")
    def test_main_catalog_error(self, mock_parse, mock_logging, mock_load, tmp_path):
        """Test main with catalog loading error"""
        mock_args = Mock()
        mock_args.base_dir = str(tmp_path)
        mock_args.verbose = False
        mock_parse.return_value = mock_args
        
        mock_load.side_effect = ValueError("Invalid catalog")
        
        result = privesc_bootstrapper.main()
        assert result == 1

    @patch("privesc_bootstrapper.process_post_copy")
    @patch("privesc_bootstrapper.process_asset")
    @patch("privesc_bootstrapper.load_assets_from_yaml")
    @patch("privesc_bootstrapper.setup_logging")
    @patch("privesc_bootstrapper.parse_args")
    def test_main_asset_processing_error(self, mock_parse, mock_logging, mock_load, mock_process, mock_post_copy, tmp_path):
        """Test main with asset processing error"""
        mock_args = Mock()
        mock_args.base_dir = str(tmp_path)
        mock_args.verbose = False
        mock_args.dry_run = False
        mock_args.force = False
        mock_parse.return_value = mock_args
        
        asset = {"name": "test.exe", "target": "win_enum/test.exe", "url": "https://example.com/test.exe"}
        mock_load.return_value = ([asset], [])
        
        mock_process.side_effect = RuntimeError("Download failed")
        
        result = privesc_bootstrapper.main()
        assert result == 0

    @patch("privesc_bootstrapper.process_post_copy")
    @patch("privesc_bootstrapper.process_asset")
    @patch("privesc_bootstrapper.load_assets_from_yaml")
    @patch("privesc_bootstrapper.setup_logging")
    @patch("privesc_bootstrapper.parse_args")
    def test_main_post_copy_error(self, mock_parse, mock_logging, mock_load, mock_process, mock_post_copy, tmp_path):
        """Test main with post-copy error"""
        mock_args = Mock()
        mock_args.base_dir = str(tmp_path)
        mock_args.verbose = False
        mock_args.dry_run = False
        mock_args.force = False
        mock_parse.return_value = mock_args
        
        asset = {"name": "test.exe", "target": "win_enum/test.exe", "url": "https://example.com/test.exe"}
        copy_item = {"source": "source/file.exe", "destination": "dest/file.exe"}
        mock_load.return_value = ([asset], [copy_item])
        
        mock_post_copy.side_effect = RuntimeError("Copy failed")
        
        result = privesc_bootstrapper.main()
        assert result == 0

