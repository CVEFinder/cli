# CVEFinder CLI

Official command-line interface for [CVEFinder.io](https://cvefinder.io) API.

Scan websites for CVEs, vulnerabilities, and technology stacks directly from your terminal.

## Features

- 🔍 **Scan websites** for CVEs and vulnerabilities
- 📊 **Get scan results** with detailed CVE information
- 📦 **Dependency analysis** in `scan get` (summary by default, full list with `--full`)
- 🔑 **Manage API keys** (create, list, revoke, rotate)
- 📈 **Export data** to JSON, CSV, or table formats
- 🎨 **Rich terminal output** with colors and tables
- ⚙️ **Simple configuration** with API key via command or environment
- 🚀 **Fast and lightweight** - pure Python implementation

## Installation

### From PyPI (Recommended)

```bash
pip install cvefinder-cli
```

### From Source

```bash
git clone https://github.com/cvefinder/cli.git
cd cvefinder-cli
pip install -e .
```

## Quick Start

### 1. Get Your API Key

Sign up at [cvefinder.io](https://cvefinder.io) and upgrade to Pro to get an API key.

### 2. Configure Your API Key

```bash
# Set your API key
cvefinder configure

# Or use environment variable
export CVEFINDER_API_KEY="your-api-key-here"
```

### 3. Scan a Website

```bash
# Basic scan
cvefinder scan run https://example.com

# Scan and save to file
cvefinder scan run https://example.com --output results.json

# Scan with specific output format
cvefinder scan run https://example.com --format table
```

## Usage

### Configuration

```bash
# Configure interactively
cvefinder configure

# Set specific values
cvefinder configure --api-key YOUR_API_KEY

# Show current configuration
cvefinder configure --show
```

### Scanning

```bash
# Basic scan
cvefinder scan run https://example.com

# Scan with options
cvefinder scan run https://example.com \
  --format json \
  --output scan.json \
  --severity critical,high

# Get scan result by ID
cvefinder scan get SCAN_ID

# Include full dependency package list
cvefinder scan get SCAN_ID --full

# List recent scans
cvefinder scan list --limit 10

# Show page 2
cvefinder scan list --limit 10 --page 2

# Bulk scan commands (Pro)
cvefinder bulk scan --url https://a.com --url https://b.com
cvefinder bulk list
cvefinder bulk get BULK_SCAN_ID

# Export scan reports (Pro)
cvefinder export SCAN_ID --json
cvefinder export SCAN_ID --pdf

# Show account usage and limits
cvefinder account

# Search CVEs, products, and vendors
cvefinder search wordpress --severity critical,high --published-year 2024

# Get exploit data for a CVE
cvefinder exploit CVE-2021-24176

# Monitor scans (Pro)
cvefinder monitor add
cvefinder monitor list
cvefinder monitor check --scan-id 123
```

### API Key Management

```bash
# Create new API key
cvefinder api-keys create --name "CI/CD Pipeline"

# List all API keys
cvefinder api-keys list

# Revoke an API key
cvefinder api-keys revoke KEY_ID

# Rotate an API key
cvefinder api-keys rotate KEY_ID
```

### Output Formats

```bash
# JSON output (default)
cvefinder scan run https://example.com --format json

# Table output (human-readable)
cvefinder scan run https://example.com --format table

# CSV output (for spreadsheets)
cvefinder scan run https://example.com --format csv

# Compact output (minimal)
cvefinder scan run https://example.com --format compact
```

### Advanced Usage

```bash
# Verbose output for debugging
cvefinder --verbose scan run https://example.com

# Quiet mode (errors only)
cvefinder --quiet scan run https://example.com
```

## Configuration File

CVEFinder CLI stores configuration in `~/.cvefinder/config.yaml`:

```yaml
default_profile: default

profiles:
  default:
    api_key: your-api-key-here
```

## Environment Variables

```bash
# API key
export CVEFINDER_API_KEY="your-api-key"

```

## Examples

### CI/CD Integration

```bash
#!/bin/bash
# Scan production website and fail if critical CVEs found

RESULT=$(cvefinder scan run https://example.com --format json)
CRITICAL=$(echo "$RESULT" | jq '.severity_counts.critical')

if [ "$CRITICAL" -gt 0 ]; then
  echo "❌ Critical CVEs found: $CRITICAL"
  exit 1
fi

echo "✅ No critical CVEs found"
```

### Scanning Multiple URLs

```bash
#!/bin/bash
# Scan multiple websites

URLS=(
  "https://example.com"
  "https://api.example.com"
  "https://staging.example.com"
)

for url in "${URLS[@]}"; do
  echo "Scanning $url..."
  cvefinder scan run "$url" --format table
done
```

### Export to CSV

```bash
# Scan and export to CSV
cvefinder scan run https://example.com --format csv > results.csv

# Open in Excel/Sheets
open results.csv
```

## Commands Reference

### Global Options

```
--api-key KEY        Override API key
--verbose, -v        Verbose output
--quiet, -q          Quiet mode (errors only)
--help, -h           Show help message
--version            Show version
```

### Commands

| Command | Description |
|---------|-------------|
| `configure` | Configure API key and show current config |
| `scan run URL` | Scan a website for CVEs |
| `scan get ID` | Get scan results + dependency analysis summary |
| `scan list` | List recent scans |
| `export ID --json/--pdf` | Export a scan report as JSON or PDF |
| `account` | Show account details and daily scan usage |
| `search [QUERY]` | Search CVEs, products, and vendors |
| `exploit CVE_ID` | Get exploit information for a CVE |
| `bulk scan` | Start a bulk scan for multiple URLs |
| `bulk get ID` | Get bulk scan status/results |
| `bulk list` | List recent bulk scans |
| `monitor add` | Add/enable monitoring for a scan |
| `monitor list` | List monitored scans |
| `monitor check --scan-id ID` | Check monitoring status for a scan |
| `monitor enable` | Enable an existing monitored scan |
| `monitor disable` | Disable an existing monitored scan |
| `api-keys create` | Create new API key |
| `api-keys list` | List all API keys |
| `api-keys revoke ID` | Revoke an API key |
| `api-keys rotate ID` | Rotate an API key |

## Requirements

- Python 3.7 or higher
- Pro subscription on [cvefinder.io](https://cvefinder.io) for API access

## Plan Notes

- Free/guest users can run core scan commands.
- Pro is required for: `bulk *`, `export --json/--pdf`, and full dependency package details.

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

- 📧 Email: support@cvefinder.io
- 🐛 Issues: [GitHub Issues](https://github.com/cvefinder/cli/issues)
- 📚 Documentation: [docs.cvefinder.io](https://docs.cvefinder.io)
- 💬 Twitter: [@CVEFinder_io](https://twitter.com/CVEFinder_io)

## Links

- Website: https://cvefinder.io
- API Documentation: https://docs.cvefinder.io/api-reference
- GitHub: https://github.com/cvefinder/cli
