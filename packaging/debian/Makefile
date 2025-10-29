# Debian package building

.PHONY: package-deb all install

package-deb:
	@echo "Buiding package"
	@dpkg-buildpackage -us -uc -b -Ppam-purpose

all: 
	@$(MAKE) -C src/c $@
	@$(MAKE) -C src/doc $@

install:
	@$(MAKE) -C src/c $@
	@$(MAKE) -C src/doc $@

