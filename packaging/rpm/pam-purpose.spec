# spec file for pam-purpose RPM package

%define _name pam_purpose
%define version 0.1.0
%define release 1

Name:      %{_name}
Version:   %{version}
Release:   %{release}%{?dist}
Summary:   PAM module to require and audit a login purpose
License:   MIT
URL:       https://github.com/alc-kit/pam_purpose
Source0:   %{name}-%{version}.tar.gz

BuildRequires: gcc
BuildRequires: make
BuildRequires: pam-devel
BuildRequires: pandoc
BuildRequires: gzip

%description
This PAM module prompts interactive users for a written purpose for their
login session, which is then audited via syslog.
It is designed to enhance security and accountability by ensuring that
logins to sensitive systems are justified.

%prep
%setup -q -n %{name}-%{version}

%build
# Build both the C and Rust modules
make all

%install
# Install the built files into the RPM build root
make DESTDIR=%{buildroot} install

%files
# List the files that will be owned by this package
# This assumes RHEL-style paths. The Makefile's install logic should handle this.
/lib64/security/pam_purpose.so
#/lib64/security/pam_purpose_rs.so
/usr/share/man/man8/pam_purpose.8.gz

%changelog
* Fri Oct 10 2025 Allan Christoffersen <alc@kvalitetsit.dk> - 0.1.0-1
- Initial package release

