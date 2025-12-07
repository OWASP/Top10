#!/bin/bash
set -e

# Activate virtual environment
source venv/bin/activate

# Clean previous builds
rm -rf build/

# Build 2021 site to build/2021
echo "Building 2021 site..."
cd 2021
mkdocs build --site-dir ../build/2021
cd ..

# Build 2025 site to build/2025
echo "Building 2025 site..."
cd 2025
mkdocs build --site-dir ../build/2025
cd ..

# Copy root redirect page
echo "Creating root redirect page..."
cp scripts/index-redirect.html build/index.html

# Generate HTML redirects for backward compatibility
echo "Generating HTML redirects..."
./scripts/generate-redirects.sh

echo "Build complete. Output in ./build/"
echo "  - 2021 site: build/2021/"
echo "  - 2025 site: build/2025/"
echo "  - Root redirects to 2021"
echo "  - Language redirects created for backward compatibility"
