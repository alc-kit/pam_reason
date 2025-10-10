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

# Clean target
clean:
	@echo "Cleaning up C build artifacts..."
	@rm -rf $(BUILD_DIR)

.PHONY: all clean

