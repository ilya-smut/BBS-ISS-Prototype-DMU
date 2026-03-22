#!/usr/bin/env bash
# setup.sh - Automated installation script for BBS-ISS-Prototype-DMU

set -e

echo "Setting up BBS-ISS-Prototype-DMU..."

echo "1. Initializing Git Submodules..."
git submodule update --init --recursive

echo "2. Creating Virtual Environment (.venv)..."
python3 -m venv .venv

# Activate the venv for the rest of the script
source .venv/bin/activate

echo "3. Upgrading pip..."
pip install --upgrade pip

echo "4. Building vendored cryptographic library from source..."
cd vendor/ffi-bbs-signatures
cargo build --release
OS_NAME=$(uname -s)
if [[ "$OS_NAME" == "Darwin" ]]; then
    cp target/release/libbbs.dylib wrappers/python/ursa_bbs_signatures/
elif [[ "$OS_NAME" == "Linux" ]]; then
    cp target/release/libbbs.so wrappers/python/ursa_bbs_signatures/
else
    echo "Warning: Unrecognized OS $OS_NAME. You may need to manually copy the built library (.dll) from vendor/ffi-bbs-signatures/target/release/ to vendor/ffi-bbs-signatures/wrappers/python/ursa_bbs_signatures/."
fi
cd ../..

echo "5. Installing vendored cryptographic library..."
pip install -e ./vendor/ffi-bbs-signatures/wrappers/python

echo "6. Installing main project and development dependencies..."
pip install -e .[dev]

echo "--------------------------------------------------------"
echo "Setup complete! To start using the project, run:"
echo "source .venv/bin/activate"
echo "--------------------------------------------------------"
