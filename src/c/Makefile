# Makefile for pam_purpose PAM module

# --- Directories ---
SRC_DIR = src
BUILD_DIR = build

# --- Variables ---
# Tools
CC = gcc
INSTALL = install
GZIP = gzip
MANDB = mandb

# Compiler flags (including hardening)
CFLAGS = -fPIC -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2

# Linker flags (including hardening)
LDFLAGS = -shared -Wl,-z,relro -Wl,-z,now

# Libraries
LIBS = -lpam

# Filenames
SOURCE_C = $(SRC_DIR)/pam_purpose.c
OBJECT_C = $(BUILD_DIR)/pam_purpose.o
TARGET_SO = $(BUILD_DIR)/pam_purpose.so

SOURCE_MAN = $(SRC_DIR)/pam_purpose.8
TARGET_MAN = $(BUILD_DIR)/pam_purpose.8.gz

# Installation paths
# PREFIX can be overridden, e.g., `make install PREFIX=/usr/local`
PREFIX ?= /usr
# Default PAM module path for 64-bit Debian/Ubuntu-based systems
PAM_DIR = $(DESTDIR)/lib/x86_64-linux-gnu/security
MAN_DIR = $(DESTDIR)$(PREFIX)/share/man/man8


# --- Rules ---

# Default rule: Build everything
all: $(TARGET_SO) $(TARGET_MAN)

# Rule for building the shared object (.so file)
$(TARGET_SO): $(OBJECT_C)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

# Rule for compiling the C source code into an object file (.o)
# Creates the build directory if it doesn't exist.
$(OBJECT_C): $(SOURCE_C)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Rule for compressing the man page
# Creates the build directory if it doesn't exist.
$(TARGET_MAN): $(SOURCE_MAN)
	@mkdir -p $(BUILD_DIR)
	$(GZIP) -c $< > $@

# Rule for installing the files on the system
# NOTE: This command must be run with sudo
install: all
	@echo "Installing PAM module and man page..."
	$(INSTALL) -d -m 755 $(PAM_DIR)
	$(INSTALL) -m 644 $(TARGET_SO) $(PAM_DIR)/
	@echo "PAM module installed in $(PAM_DIR)/$(notdir $(TARGET_SO))"
	
	$(INSTALL) -d -m 755 $(MAN_DIR)
	$(INSTALL) -m 644 $(TARGET_MAN) $(MAN_DIR)/
	@echo "Man page installed in $(MAN_DIR)/$(notdir $(TARGET_MAN))"
	
	@echo "Updating man database..."
	$(MANDB)
	@echo "Installation complete."

# Rule for uninstalling
# NOTE: This command must be run with sudo
uninstall:
	@echo "Uninstalling PAM module and man page..."
	rm -f $(PAM_DIR)/$(notdir $(TARGET_SO))
	rm -f $(MAN_DIR)/$(notdir $(TARGET_MAN))
	@echo "Updating man database..."
	$(MANDB)
	@echo "Uninstallation complete."

# Rule for cleaning up build files
clean:
	@echo "Cleaning up..."
	rm -rf $(BUILD_DIR)

# Tell 'make' that these targets are not files
.PHONY: all install uninstall clean


