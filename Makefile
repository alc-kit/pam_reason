# Top-level Makefile to orchestrate C and Rust builds

# Build directory for final artifacts
BUILD_DIR = build
C_TARGET = $(BUILD_DIR)/pam_purpose_c.so
RUST_TARGET = $(BUILD_DIR)/pam_purpose_rs.so
MAN_TARGET = $(BUILD_DIR)/pam_purpose.8.gz

.PHONY: all c rust doc clean install-c install-rust

# Default target: build everything
all: c rust doc

# Build the C version
c:
	@echo "--- Building C Module ---"
	@$(MAKE) -C src/c
	@mkdir -p $(BUILD_DIR)
	@cp src/c/build/pam_purpose.so $(C_TARGET)
	@echo "C module available at $(C_TARGET)"

# Build the Rust version
rust:
	@echo "--- Building Rust Module ---"
	@(cd src/rs && cargo build --release)
	@mkdir -p $(BUILD_DIR)
	@cp src/rs/target/release/libpam_purpose_rs.so $(RUST_TARGET)
	@echo "Rust module available at $(RUST_TARGET)"

# Build the documentation using the C project's Makefile
doc:
	@echo "--- Building Documentation ---"
	@$(MAKE) -C src/c doc
	@mkdir -p $(BUILD_DIR)
	@cp src/c/build/pam_purpose.8.gz $(MAN_TARGET)

# Clean all subprojects
clean:
	@echo "--- Cleaning all projects ---"
	@$(MAKE) -C src/c clean
	@(cd src/rs && cargo clean)
	@rm -rf $(BUILD_DIR)

# Installation targets
install-c: c doc
	@$(MAKE) -C src/c install

install-rust: rust doc
	@echo "Installing Rust module..."
	@if [ -d /lib/x86_64-linux-gnu/ ]; then \
		sudo install -m 644 $(RUST_TARGET) /lib/x86_64-linux-gnu/security/pam_purpose.so; \
	else \
		sudo install -m 644 $(RUST_TARGET) /lib64/security/pam_purpose.so; \
	fi
	@echo "Installing man page..."
	@sudo install -m 644 $(MAN_TARGET) /usr/share/man/man8/
	@sudo mandb

