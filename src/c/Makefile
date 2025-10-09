# Makefile for pam_purpose PAM module

# Compiler and flags
CC = gcc
# Compiler flags: -fPIC for shared libs, -Wall/-Wextra for warnings, -Werror to treat warnings as errors.
# Hardening flags: -fstack-protector-strong, -D_FORTIFY_SOURCE=2
CFLAGS = -fPIC -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2

# Linker and flags
# Hardening flags: -z,relro and -z,now for security
LDFLAGS = -shared -Wl,-z,relro -Wl,-z,now
LDLIBS = -lpam

# Pandoc for man page conversion
PANDOC = pandoc

# Source and build directories
SRC_DIR = src
BUILD_DIR = build

# Source files
C_SRC = $(SRC_DIR)/pam_purpose.c
MAN_SRC_MD = $(SRC_DIR)/pam_purpose.8.md

# Object and target files
OBJ = $(BUILD_DIR)/pam_purpose.o
TARGET = $(BUILD_DIR)/pam_purpose.so
MAN_TARGET_GROFF = $(BUILD_DIR)/pam_purpose.8
MAN_TARGET_GZ = $(MAN_TARGET_GROFF).gz

# Default target
all: $(TARGET) $(MAN_TARGET_GZ)

# Rule to build the shared library
$(TARGET): $(OBJ)
	@echo "LD  $@"
	@$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS)

# Rule to compile the C source file
$(OBJ): $(C_SRC)
	@echo "CC  $@"
	@mkdir -p $(BUILD_DIR) # Ensure build directory exists
	@$(CC) $(CFLAGS) -c -o $@ $<

# Rule to convert Markdown man page to groff format
$(MAN_TARGET_GROFF): $(MAN_SRC_MD)
	@echo "PANDOC $@"
	@mkdir -p $(BUILD_DIR) # Ensure build directory exists
	@$(PANDOC) -s -t man $< -o $@

# Rule to compress the man page
$(MAN_TARGET_GZ): $(MAN_TARGET_GROFF)
	@echo "GZIP $@"
	@gzip -c -9 $< > $@

# Installation targets
INSTALL_DIR_LIB_DEB = /lib/x86_64-linux-gnu/security
INSTALL_DIR_LIB_RHEL = /lib64/security
INSTALL_DIR_MAN = /usr/share/man/man8

install: all
	@echo "Installing module..."
	@if [ -d /lib/x86_64-linux-gnu/ ]; then \
		sudo install -m 644 $(TARGET) $(INSTALL_DIR_LIB_DEB)/; \
	else \
		sudo install -m 644 $(TARGET) $(INSTALL_DIR_LIB_RHEL)/; \
	fi
	@echo "Installing man page to $(INSTALL_DIR_MAN)..."
	@sudo install -m 644 $(MAN_TARGET_GZ) $(INSTALL_DIR_MAN)/
	@echo "Updating man-db..."
	@sudo mandb

uninstall:
	@echo "Uninstalling module..."
	@if [ -d /lib/x86_64-linux-gnu/ ]; then \
		sudo rm -f $(INSTALL_DIR_LIB_DEB)/pam_purpose.so; \
	else \
		sudo rm -f $(INSTALL_DIR_LIB_RHEL)/pam_purpose.so; \
	fi
	@echo "Uninstalling man page..."
	@sudo rm -f $(INSTALL_DIR_MAN)/pam_purpose.8.gz
	@echo "Updating man-db..."
	@sudo mandb

# Clean target
clean:
	@echo "Cleaning up build artifacts..."
	@rm -rf $(BUILD_DIR)

.PHONY: all install uninstall clean

