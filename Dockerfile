FROM python:3.10-slim

WORKDIR /app

# Copy vendored cryptographic library first (changes rarely, good cache layer)
COPY vendor/ vendor/

# Install the vendored ursa_bbs_signatures (pre-built libbbs.so, no Rust needed)
RUN pip install --no-cache-dir ./vendor/ffi-bbs-signatures/wrappers/python

# Copy project metadata and install dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir .

# Copy the full source tree
COPY src/ src/

# Re-install in editable mode so the entrypoint scripts can import bbs_iss
RUN pip install --no-cache-dir -e .
