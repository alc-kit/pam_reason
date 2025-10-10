# Use the official Ubuntu 24.04 LTS image as the base
FROM ubuntu:24.04

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install all necessary build dependencies
# - build-essential: Provides gcc, make, etc.
# - libpam0g-dev:   Crucial for PAM C headers and development libraries.
# - man-db:         Provides 'mandb' for managing man pages.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        # C toolchain
        gcc make libc6-dev libpam-dev gzip pandoc \
        # Rust toolchain from Ubuntu's repository
        rustc cargo \
        # Debian Packaging
        debhelper devscripts \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container.
# This is where your source code will be mounted.
WORKDIR /usr/src/app

