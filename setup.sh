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

echo "4. Installing vendored cryptographic library..."
pip install -e ./vendor/ffi-bbs-signatures/wrappers/python

echo "5. Installing main project and development dependencies..."
pip install -e .[dev]

echo "--------------------------------------------------------"
echo "Setup complete! To start using the project, run:"
echo "source .venv/bin/activate"
echo "--------------------------------------------------------"
