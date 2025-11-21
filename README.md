# privEsc Bootstrapper

A quality-of-life tool for cybersecurity certifications (OSCP, CPTS, etc.) that automates the download and organization of commonly used certification tools.

**All downloads come directly from official sources** - files are fetched from their original repositories (GitHub releases, official websites) with no intermediaries or mirrors.

**Author:** [rzz0](https://github.com/rzz0)

## Features

- **Parallel Downloads**: Downloads multiple assets simultaneously using thread pools (4-8 workers)
- **ZIP Extraction**: Automatically extracts ZIP archives with full directory structure preservation
- **SHA-256 Caching**: Verifies file integrity and skips re-downloading unchanged files
- **Dry-Run Mode**: Preview what will be downloaded without making changes
- **Force Re-download**: Override cache and force fresh downloads when needed

## Installation

### Requirements

- Python 3.6+
- PyYAML

### Setup

```bash
# Clone the repository
git clone https://github.com/rzz0/privesc-bootstrapper.git
cd privesc-bootstrapper

# Install dependencies
pip install -r requirements.txt

```

## Usage

### Basic Usage

```bash
# Download all assets to default directory (~/privEsc)
python3 privesc_bootstrapper.py

# Specify a custom destination directory
python3 privesc_bootstrapper.py --base-dir /path/to/tools

# Preview what will be downloaded (dry-run)
python3 privesc_bootstrapper.py --dry-run

# Force re-download all files (ignore cache)
python3 privesc_bootstrapper.py --force

# Enable verbose logging
python3 privesc_bootstrapper.py --verbose
```

## Directory Structure

Assets are organized in a structured directory layout:

```
~/privEsc/
├── win_enum/           # Windows enumeration tools
├── win_priv/           # Windows privilege escalation tools
├── win_cred/           # Windows credential tools
├── win_move/           # Windows lateral movement tools
├── win_tun/            # Windows tunneling tools
├── win_coll/           # Windows tool collections
├── lin_enum/           # Linux enumeration tools
├── lin_priv/           # Linux privilege escalation tools
├── lin_mon/            # Linux monitoring tools
├── lin_tun/            # Linux tunneling tools
├── web_php/            # PHP web shells
├── web_aspx/           # ASPX web shells
├── web_jsp/            # JSP web shells
├── xplat_tun/          # Cross-platform tunneling tools
├── xplat_utils/        # Cross-platform utilities
└── core/
    └── checksums/      # SHA-256 checksum cache
```

## Catalog Configuration

The `bootstrapper_catalog.yaml` file defines all assets to be downloaded. Each asset entry includes:

### Example Entry

```yaml
- name: "linpeas.sh"
  target: "lin_enum/linpeas.sh"
  url: "https://github.com/peass-ng/PEASS-ng/releases/download/20251101-a416400b/linpeas.sh"
  note: "Linux privesc"
  postchmod_x: true
```

## Troubleshooting

### PyYAML Not Installed

```bash
pip install pyyaml
```

## License

See [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is intended for educational purposes and authorized security testing only. Users are responsible for ensuring they have proper authorization before using any downloaded tools in their activities.

