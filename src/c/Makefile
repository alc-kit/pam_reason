# Makefile for the C version of pam_purpose

# Compiler and flags
CC = gcc
# Added -O2 optimization flag, which is required for _FORTIFY_SOURCE to work correctly on RHEL-based systems
CFLAGS = -fPIC -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2 -O2

# Linker and flags
LDFLAGS = -shared -Wl,-z,relro -Wl,-z,now
LDLIBS = -lpam

# Source and build directories
SRC_DIR = src
BUILD_DIR = build

# Source files
C_SRC = $(SRC_DIR)/pam_purpose.c

# Object and target files
OBJ = $(BUILD_DIR)/pam_purpose.o
TARGET = $(BUILD_DIR)/pam_purpose.so

# --- Installation Directory (auto-detected via /etc/os-release) ---
# Source /etc/os-release and get the ID
OS_ID := $(shell . /etc/os-release && echo $$ID)

# Set the library path based on the OS ID
ifeq ($(filter $(OS_ID),ubuntu debian),$(OS_ID))
    INSTALL_DIR_LIB = /lib/x86_64-linux-gnu/security
else
    INSTALL_DIR_LIB = /lib64/security
endif

# Default target
all: $(TARGET)

# Rule to build the shared library
$(TARGET): $(OBJ)
	@echo "LD  $@"
	@$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS)

# Rule to compile the C source file
$(OBJ): $(C_SRC)
	@echo "CC  $@"
	@mkdir -p $(BUILD_DIR)
	@$(CC) $(CFLAGS) -c -o $@ $<
# Installation target (respects DESTDIR for packaging tools like rpmbuild)

# Installation target (respects DESTDIR for packaging tools)
# This rule is called by the packaging process and is platform-aware.
install: all
	@echo "Installing C module for packaging..."
	@echo "Detected OS_ID: $(OS_ID), installing to $(INSTALL_DIR_LIB)"
	@# The DESTDIR variable is prefixed to the install path by the packaging tool.
	@install -D -m 644 $(TARGET) $(DESTDIR)$(INSTALL_DIR_LIB)/pam_purpose.so

# Clean target
clean:
	@echo "Cleaning up C build artifacts..."
	@rm -rf $(BUILD_DIR)

.PHONY: all clean

