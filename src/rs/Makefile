# Makefile for the Rust version of pam_purpose

# This Makefile is primarily for providing a consistent `install` target
# that packaging tools can call. The build itself is handled by Cargo.

# Build directories (relative to this Makefile)
BUILD_DIR = ../../build/rs
TARGET_DIR = target # Cargo's build output directory

# Source target file from Cargo
TARGET_SO = $(TARGET_DIR)/release/libpam_purpose_rs.so

# Installation directories
INSTALL_DIR_LIB_RHEL = /lib64/security
INSTALL_DIR_LIB_DEB = /lib/x86_64-linux-gnu/security

# Default target
all:
	@cargo build --release

# Installation target (respects DESTDIR)
install: all
	@echo "Installing Rust module..."
	@if [ -d "$(DESTDIR)/lib64" ]; then \
		install -D -m 644 $(TARGET_SO) $(DESTDIR)$(INSTALL_DIR_LIB_RHEL)/pam_purpose_rs.so; \
	else \
		install -D -m 644 $(TARGET_SO) $(DESTDIR)$(INSTALL_DIR_LIB_DEB)/pam_purpose_rs.so; \
	fi

clean:
	@cargo clean

.PHONY: all install clean

