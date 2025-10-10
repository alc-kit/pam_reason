Name:           pam-purpose-tool
Version:        0.1.0
Release:        1%{?dist}
Summary:        Diagnostic tool for the pam_purpose module

License:        GPLv3
URL:            https://github.com/alc-kit/pam_purpose
Source0:        test/check_pam_purpose

BuildArch:      noarch
Requires:       pam-purpose = %{version}-%{release}

%description
This package provides a script to debug and analyze the configuration
of the pam_purpose.so module for specific users.

%install
mkdir -p %{buildroot}/usr/sbin
install -m 755 %{SOURCE0} %{buildroot}/usr/sbin/check_pam_purpose.py

%files
/usr/sbin/check_pam_purpose
