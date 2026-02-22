#!/bin/bash
# Quick test script for CVEFinder CLI

echo "Testing CVEFinder CLI installation..."

# Check Python version
python3 --version || { echo "Python 3 required"; exit 1; }

# Install in development mode
pip install -e . --break-system-packages

# Test import
python3 -c "import cvefinder; print('✓ Package import successful')"

# Test CLI command
cvefinder --version

# Test help
cvefinder --help

echo ""
echo "✓ Installation test complete!"
echo ""
echo "Next steps:"
echo "1. Get your API key from https://cvefinder.io"
echo "2. Run: cvefinder configure"
echo "3. Run: cvefinder scan run https://example.com"
