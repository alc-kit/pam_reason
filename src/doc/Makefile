# Makefile for the man page

# Tools
PANDOC = pandoc
GZIP = gzip

# Directories (relative to this Makefile)
SRC_DIR = .
BUILD_DIR = build

# Source and target files
MAN_SRC_MD = $(SRC_DIR)/pam_purpose.8.md
MAN_TARGET_GROFF = $(BUILD_DIR)/pam_purpose.8
MAN_TARGET_GZ = $(MAN_TARGET_GROFF).gz

# Installation directory
INSTALL_DIR_MAN = /usr/share/man/man8

# Default target
all: $(MAN_TARGET_GZ)

# Rule to convert Markdown to groff
$(MAN_TARGET_GROFF): $(MAN_SRC_MD)
	@echo "PANDOC  $@"
	@mkdir -p $(BUILD_DIR)
	@$(PANDOC) -s -t man $< -o $@

# Rule to compress the man page
$(MAN_TARGET_GZ): $(MAN_TARGET_GROFF)
	@echo "GZIP    $@"
	@$(GZIP) -c -9 $< > $@

# Installation target (respects DESTDIR)
install: all
	@echo "Installing man page..."
	@install -D -m 644 $(MAN_TARGET_GZ) $(DESTDIR)$(INSTALL_DIR_MAN)/pam_purpose.8.gz

# Clean up build artifacts
clean:
	@echo "Cleaning up doc build artifacts..."
	@rm -f $(MAN_TARGET_GROFF) $(MAN_TARGET_GZ)
	@rmdir $(BUILD_DIR)

.PHONY: all install clean

