# Top-level Makefile to orchestrate C and Rust builds

# Build directory for final artifacts
BUILD_DIR = build
C_TARGET = $(BUILD_DIR)/pam_purpose_c.so
RUST_TARGET = $(BUILD_DIR)/pam_purpose_rs.so
MAN_TARGET = $(BUILD_DIR)/pam_purpose.8.gz

.PHONY: all c rust doc clean package-deb package-rpm

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

# --- Packaging Targets ---

# Build Debian packages for both C and Rust versions
package-deb: c rust doc
	@echo "--- Building Debian Packages ---"
	# Create a temporary directory for packaging
	@rm -rf $(BUILD_DIR)/deb_temp
	@mkdir -p $(BUILD_DIR)/deb_temp
	# Copy source and packaging files
	@cp -r src $(BUILD_DIR)/deb_temp/
	@cp -r packaging/debian $(BUILD_DIR)/deb_temp/
	# Build C package inside the container
	@docker compose run --rm build-env-debian /bin/bash -c "cd /usr/src/app/build/deb_temp && dpkg-buildpackage -us -uc -b -Ppam-purpose-c"
	# Build Rust package inside the container
	@docker compose run --rm build-env-debian /bin/bash -c "cd /usr/src/app/build/deb_temp && dpkg-buildpackage -us -uc -b -Ppam-purpose-rs"
	@echo "Debian packages are available in $(BUILD_DIR)/"
	@mv $(BUILD_DIR)/deb_temp/*.deb $(BUILD_DIR)/


# Build RPM packages for both C and Rust versions
package-rpm: c rust doc
	@echo "--- Building RPM Packages ---"
	# Build C package
	@docker compose run --rm build-env-rhel /bin/bash -c "rpmbuild -bb --define '_sourcedir /usr/src/app' --define '_specdir /usr/src/app/packaging/rpm' --define '_builddir /usr/src/app/build' --define '_rpmdir /usr/src/app/build' --define 'build_c 1' packaging/rpm/pam_purpose.spec"
	# Build Rust package
	@docker compose run --rm build-env-rhel /bin/bash -c "rpmbuild -bb --define '_sourcedir /usr/src/app' --define '_specdir /usr/src/app/packaging/rpm' --define '_builddir /usr/src/app/build' --define '_rpmdir /usr/src/app/build' --define 'build_rust 1' packaging/rpm/pam_purpose.spec"
	@echo "RPM packages are available in $(BUILD_DIR)/x86_64/"

