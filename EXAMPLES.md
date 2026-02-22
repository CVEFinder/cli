# CVEFinder CLI - Usage Examples

## Installation

```bash
# Install from PyPI
pip install cvefinder-io

# Or install from source
git clone https://github.com/CVEFinder/cli.git
cd cli
pip install -e .
```

## Configuration

### Basic Setup

```bash
# Interactive configuration
cvefinder configure
# Enter your API key when prompted

# Or set directly
cvefinder configure --api-key YOUR_API_KEY_HERE
```

### Environment Variables

```bash
# Set API key via environment
export CVEFINDER_API_KEY="your-api-key-here"

# Now you can use CLI without configure
cvefinder scan run https://example.com
```

### Configuration Notes

```bash
# Show current configured API key
cvefinder configure --show
```

## Scanning Websites

### Basic Scan

```bash
# Scan a website
cvefinder scan run https://example.com

# Output shows:
# - URL and domain
# - Total CVEs found
# - Severity breakdown (Critical, High, Medium, Low)
# - Top CVEs with details
# - Detected technologies
```

### Save Results

```bash
# Save as JSON
cvefinder scan run https://example.com --output results.json

# Save as CSV (for Excel/Sheets)
cvefinder scan run https://example.com --format csv --output results.csv

# Compact text output
cvefinder scan run https://example.com --format compact
```

### Filter by Severity

```bash
# Only show critical CVEs
cvefinder scan run https://example.com --severity critical

# Show critical and high
cvefinder scan run https://example.com --severity critical,high
```

## Listing Recent Scans

```bash
# Show 10 most recent scans in table format
cvefinder scan list

# Show up to 10 scans in JSON
cvefinder scan list --limit 10 --format json

# Fetch page 3
cvefinder scan list --limit 10 --page 3
```

## Account Details and Daily Usage

```bash
# Show account details as table
cvefinder account

# Compact output for scripts
cvefinder account --format compact

# Full JSON payload
cvefinder account --format json
```

## Search CVEs, Products, and Vendors

```bash
# Basic search
cvefinder search wordpress

# Search with filters
cvefinder search openssl \
  --severity critical,high \
  --published-year 2024 \
  --sort-by cvss_score \
  --sort-order desc

# Use independent pagination per result type
cvefinder search apache --page-cves 2 --page-products 1 --page-vendors 1

# JSON output for automation
cvefinder search nginx --format json --output search-results.json
```

## Exploits By CVE

```bash
# Get exploit data for a CVE
cvefinder exploit CVE-2021-24176

# Compact mode
cvefinder exploit cve-2021-24176 --format compact

# Full JSON output
cvefinder exploit CVE-2021-24176 --format json
```

## Monitoring Scans (Pro)

```bash
# Add monitoring and choose scan interactively
cvefinder monitor add

# In the interactive menu:
# - type n / p for next/previous page of your scans
# - type fn / fp for next/previous page of public scans
# - type q to cancel

# Add monitoring for a specific scan ID
cvefinder monitor add --scan-id 123

# List monitored scans
cvefinder monitor list

# Check monitoring status for one scan
cvefinder monitor check --scan-id 123

# Enable/disable existing monitored scans
cvefinder monitor enable --scan-id 123
cvefinder monitor disable --scan-id 123
```

## Getting Scan Results

```bash
# Get scan by ID
cvefinder scan get abc123def456

# Save to file
cvefinder scan get abc123def456 --output scan.json

# Different formats
cvefinder scan get abc123def456 --format table
cvefinder scan get abc123def456 --format csv
cvefinder scan get abc123def456 --format json

# Dependency analysis is included by default:
# - summary counts
# - vulnerable packages
# - internal packages
cvefinder scan get abc123def456 --format table

# Show all remaining packages too
cvefinder scan get abc123def456 --full
```

## Dependency Analysis Details

```bash
# Compact summary includes dependency counts
cvefinder scan get abc123def456 --format compact

# Table output shows:
# - total packages
# - vulnerable packages
# - internal packages
# - vulnerable/internal package tables
cvefinder scan get abc123def456 --format table

# Add --full to include remaining packages table too
cvefinder scan get abc123def456 --full
```

## Bulk Scan (Pro)

```bash
# Start bulk scan with repeated --url
cvefinder bulk scan --url https://example.com --url https://api.example.com

# Start from file (one URL per line)
cvefinder bulk scan --input-file urls.txt

# Start and wait for completion
cvefinder bulk scan --input-file urls.txt --wait

# Get bulk scan status
cvefinder bulk get 123

# List recent bulk scans
cvefinder bulk list
```

## Export Scan Report (Pro)

```bash
# Export JSON report
cvefinder export 123 --json

# Export PDF report
cvefinder export 123 --pdf

# Custom output filename
cvefinder export 123 --pdf --output report.pdf
```

## Managing API Keys

### Create API Key

```bash
# Create new key
cvefinder api-keys create --name "Production Server"

# Output shows:
# - Key ID
# - API Key (save this securely!)
```

### List API Keys

```bash
# List all your API keys
cvefinder api-keys list

# Shows table with:
# - ID
# - Name
# - Status (Active/Inactive)
# - Created date
```

### Revoke API Key

```bash
# Revoke a key
cvefinder api-keys revoke 123

# Confirms before revoking
```

### Rotate API Key

```bash
# Rotate key (generates new key, keeps same ID)
cvefinder api-keys rotate 123

# Output shows new API key
# Old key stops working immediately
```

## CI/CD Integration Examples

### GitHub Actions

```yaml
name: Security Scan

on:
  schedule:
    - cron: '0 0 * * *'  # Daily at midnight
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Install CVEFinder CLI
        run: pip install cvefinder-io

      - name: Scan website
        env:
          CVEFINDER_API_KEY: ${{ secrets.CVEFINDER_API_KEY }}
        run: |
          cvefinder scan run https://example.com --format json > scan.json

      - name: Check for critical CVEs
        run: |
          CRITICAL=$(jq '.severity_counts.critical' scan.json)
          if [ "$CRITICAL" -gt 0 ]; then
            echo "❌ Found $CRITICAL critical CVEs"
            exit 1
          fi
          echo "✅ No critical CVEs found"

      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: scan-results
          path: scan.json
```

### GitLab CI

```yaml
security-scan:
  image: python:3.11
  script:
    - pip install cvefinder-io
    - cvefinder scan run https://example.com --format json > scan.json
    - |
      CRITICAL=$(jq '.severity_counts.critical' scan.json)
      if [ "$CRITICAL" -gt 0 ]; then
        echo "❌ Critical CVEs found"
        exit 1
      fi
  artifacts:
    paths:
      - scan.json
    expire_in: 30 days
  only:
    - schedules
    - web
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any

    environment {
        CVEFINDER_API_KEY = credentials('cvefinder-api-key')
    }

    stages {
        stage('Install') {
            steps {
                sh 'pip install cvefinder-io'
            }
        }

        stage('Scan') {
            steps {
                sh 'cvefinder scan run https://example.com --format json > scan.json'
            }
        }

        stage('Check Results') {
            steps {
                script {
                    def critical = sh(
                        script: "jq '.severity_counts.critical' scan.json",
                        returnStdout: true
                    ).trim().toInteger()

                    if (critical > 0) {
                        error("Found ${critical} critical CVEs")
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'scan.json'
        }
    }
}
```

## Shell Scripting Examples

### Scan Multiple URLs

```bash
#!/bin/bash
# scan-urls.sh - Scan multiple websites

URLS=(
  "https://example.com"
  "https://api.example.com"
  "https://admin.example.com"
)

for url in "${URLS[@]}"; do
  echo "========================================
"
  echo "Scanning: $url"
  echo "========================================"

  cvefinder scan run "$url" --format table

  # Save JSON results
  filename=$(echo "$url" | sed 's|https://||' | sed 's|/|_|g')
  cvefinder scan run "$url" --format json > "scan_${filename}.json"
done

echo "All scans complete!"
```

### Check for New CVEs

```bash
#!/bin/bash
# check-new-cves.sh - Alert on new CVEs

SCAN_URL="https://example.com"
PREV_SCAN="previous-scan.json"
CURR_SCAN="current-scan.json"

# Run new scan
cvefinder scan run "$SCAN_URL" --format json > "$CURR_SCAN"

# Compare with previous scan
if [ -f "$PREV_SCAN" ]; then
  PREV_COUNT=$(jq '.total_cves' "$PREV_SCAN")
  CURR_COUNT=$(jq '.total_cves' "$CURR_SCAN")

  if [ "$CURR_COUNT" -gt "$PREV_COUNT" ]; then
    NEW_CVES=$((CURR_COUNT - PREV_COUNT))
    echo "⚠️  ALERT: $NEW_CVES new CVEs detected!"

    # Send notification (example with Slack)
    curl -X POST YOUR_SLACK_WEBHOOK \
      -d "{\"text\": \"🚨 $NEW_CVES new CVEs found on $SCAN_URL\"}"
  fi
fi

# Save as previous for next run
cp "$CURR_SCAN" "$PREV_SCAN"
```

### Export to CSV for Reporting

```bash
#!/bin/bash
# export-report.sh - Generate CSV report

DATE=$(date +%Y-%m-%d)
OUTPUT="cve-report-${DATE}.csv"

cvefinder scan run https://example.com --format csv > "$OUTPUT"

echo "Report generated: $OUTPUT"

# Optional: Email the report
# mail -s "CVE Report - $DATE" -a "$OUTPUT" security@example.com < /dev/null
```

## Advanced Usage

### Verbose Debugging

```bash
# Enable verbose output for troubleshooting
cvefinder --verbose scan https://example.com
```

### Quiet Mode

```bash
# Only show errors (useful for scripts)
cvefinder --quiet scan run https://example.com
```

### Combine Options

```bash
# Scan with all options
cvefinder --verbose \
  scan run https://example.com \
  --format json \
  --output results.json \
  --severity critical,high
```

## Tips & Best Practices

### 1. Secure Your API Key

```bash
# Never commit API keys to git
# Use environment variables or CI/CD secrets

# Good
export CVEFINDER_API_KEY="your-key"

# Bad
cvefinder --api-key your-key-here  # visible in shell history!
```

### 2. Automate Regular Scans

```bash
# Add to crontab for daily scans
0 0 * * * /usr/local/bin/cvefinder scan run https://example.com --format json > /var/log/cvefinder-scan.json
```

### 3. Monitor Critical Changes

```bash
# Set up alerts for critical severity
CRITICAL=$(cvefinder scan run https://example.com --format json | jq '.severity_counts.critical')

if [ "$CRITICAL" -gt 0 ]; then
  # Send alert (email, Slack, PagerDuty, etc.)
  echo "Critical CVEs detected!" | mail -s "Security Alert" team@example.com
fi
```

### 4. Version Control Your Scans

```bash
# Track scan results over time
cvefinder scan run https://example.com --format json > "scans/$(date +%Y-%m-%d).json"
git add scans/
git commit -m "Daily CVE scan"
```

## Troubleshooting

### Authentication Errors

```bash
# Verify API key is configured
cvefinder configure --show

# Test with explicit key
cvefinder --api-key YOUR_KEY scan https://example.com
```

### Rate Limiting

```bash
# If you hit rate limits, spread out scans
for url in "${URLS[@]}"; do
  cvefinder scan run "$url"
  sleep 60  # Wait 1 minute between scans
done
```

### Connection Issues

```bash
# Check API connectivity
curl -H "Authorization: Bearer YOUR_KEY" https://cvefinder.io/api/account-data

# Use verbose mode to debug
cvefinder --verbose scan https://example.com
```

## Getting Help

```bash
# Show main help
cvefinder --help

# Show command-specific help
cvefinder scan --help
cvefinder api-keys --help
cvefinder configure --help
```

## More Resources

- 📚 Documentation: https://docs.cvefinder.io
- 🐛 Report Issues: https://github.com/CVEFinder/cli/issues
- 💬 Support: support@cvefinder.io
- 🌐 Website: https://cvefinder.io
