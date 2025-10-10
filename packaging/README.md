# Packaging for pam_purpose

This directory contains the necessary files to build `.deb` (Debian/Ubuntu) and `.rpm` (Red Hat/AlmaLinux) packages for the `pam_purpose` module.

## Prerequisites

For these packaging scripts to work, your project's Makefiles must support a standard `install` target that respects the `DESTDIR` variable. This allows the packaging tools to install the compiled files into a temporary staging directory instead of the live root filesystem.

### Example `install` rule in `src/c/Makefile`:

Your `install` rule in `src/c/Makefile` should look similar to this:

```makefile
# Note the use of $(DESTDIR) before the installation path
install: all
	@echo "Installing module..."
	@if [ -d $(DESTDIR)/lib/x86_64-linux-gnu/ ]; then \
		sudo install -D -m 644 $(TARGET) $(DESTDIR)$(INSTALL_DIR_LIB_DEB)/pam_purpose.so; \
	else \
		sudo install -D -m 644 $(TARGET) $(DESTDIR)$(INSTALL_DIR_LIB_RHEL)/pam_purpose.so; \
	fi
	@echo "Installing man page..."
	@sudo install -D -m 644 $(MAN_TARGET_GZ) $(DESTDIR)$(INSTALL_DIR_MAN)/pam_purpose.8.gz
```

The `install -D` command ensures that the destination directories are created if they don't exist.

## How to Build

### Debian (`.deb`)

From within your build container (`build-env-debian`), navigate to the project root and run:

```bash
dpkg-buildpackage -us -uc
```
This will create the `.deb` file in the directory above your project root.

### Red Hat (`.rpm`)

RPM building is a bit more involved and typically requires a source tarball.

1.  **Create a source tarball** from your project root:
    ```bash
    # (Assuming your project version is 0.1.0)
    tar -czvf pam-purpose-0.1.0.tar.gz --exclude-vcs --transform 's,^,pam-purpose-0.1.0/,' .
    ```

2.  **Inside the build container** (`build-env-rhel`), set up the RPM build environment and build:
    ```bash
    # Copy the tarball into the container
    # Then, inside the container:
    rpmbuild -ta /path/to/pam-purpose-0.1.0.tar.gz
    ```

