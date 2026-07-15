#!/usr/bin/env bash
# setup.sh - Automated installation script for BBS-ISS-Prototype-DMU

set -e

# This script should NOT be run with sudo — nothing here requires root.
# Running with sudo creates root-owned files that break subsequent runs.
if [ "$(id -u)" -eq 0 ]; then
  echo "ERROR: Do not run this script with sudo."
  echo "If a previous sudo run left root-owned files, fix them first with:"
  echo "  sudo chown -R \$(whoami) ."
  echo "Then re-run:  ./setup.sh"
  exit 1
fi

echo "Setting up BBS-ISS-Prototype-DMU..."

echo "1. Initializing Git Submodules..."
git submodule update --init --recursive

echo "2. Creating Virtual Environment (.venv)..."
python3 -m venv .venv

# Activate the venv for the rest of the script
source .venv/bin/activate

echo "3. Upgrading pip..."
pip install --upgrade pip

echo "4. Building native BBS signatures library (requires Rust)..."
# Source cargo env if it exists (needed in a fresh shell after rustup install)
if [ -f "$HOME/.cargo/env" ]; then
  . "$HOME/.cargo/env"
fi

if ! command -v cargo &> /dev/null; then
  echo "ERROR: Rust toolchain (cargo) is not installed."
  echo "Install it with: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
  exit 1
fi
(cd vendor/ffi-bbs-signatures && cargo build --release)

echo "5. Installing vendored cryptographic library..."
LIB_SRC="vendor/ffi-bbs-signatures/target/release/libbbs.so"
LIB_DST="vendor/ffi-bbs-signatures/wrappers/python/ursa_bbs_signatures/libbbs.so"
if [ ! -f "$LIB_SRC" ]; then
  echo "ERROR: Native library build failed — $LIB_SRC not found."
  exit 1
fi
cp "$LIB_SRC" "$LIB_DST"
echo "  Copied libbbs.so into Python package."
pip install -e ./vendor/ffi-bbs-signatures/wrappers/python

echo "6. Installing main project and development dependencies..."
pip install -e .[dev]

echo "--------------------------------------------------------"
echo "Setup complete! To start using the project, run:"
echo "source .venv/bin/activate"
echo "--------------------------------------------------------"
