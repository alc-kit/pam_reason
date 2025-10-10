% pam_purpose(8) | Linux-PAM Manual

# NAME

**pam_purpose** - PAM module to require and audit a login purpose

# SYNOPSIS

**auth** \[*control-flag*\] **pam_purpose.so** \[\*\*users=\*\**user1*,*user2*,...\] \[\*\*groups=\*\**group1*,*group2*,...\]

# DESCRIPTION

The **pam_purpose.so** module is designed to prompt interactive users for a written purpose for their login session. The provided purpose is audited via syslog for accountability.

This module is intended to be used in the `auth` stack. For interactive sessions, the user is presented with a text prompt. An empty or aborted response will cause the module to return an authentication failure.

For non-interactive sessions, such as those initiated by automation tools (e.g., Ansible) or file transfer services (e.g., SCP/SFTP), the module will automatically succeed and log the access as "AUTOMATED_ACCESS", specifying whether the match was based on the user or group list.

# OPTIONS

\*\*users=\*\**user1*,*user2*,... :
    This option restricts the module's execution to a comma-separated list of usernames.

\*\*groups=\*\**group1*,*group2*,... :
    This option restricts the module's execution to users who are members of one of the comma-separated groups.

If either `users` or `groups` is specified, the module will only activate for matching users. If both are omitted, the module will not activate for any user.

# MODULE TYPES PROVIDED

Only the `auth` module type is provided.

# RETURN VALUES

**PAM_SUCCESS** :
    The user successfully provided a purpose, the session was non-interactive, or the user was not targeted by the configuration.

**PAM_AUTH_ERR** :
    The user failed to provide a purpose, or an internal error occurred that should prevent login.

# EXAMPLES

The following configuration for `/etc/pam.d/sshd` requires users in the `wheel` group to provide a login purpose after successful primary authentication.

```
# /etc/pam.d/sshd

# ... primary authentication modules ...
@include common-auth

# Require a purpose for specific admin users AFTER primary auth.
# NOTE: Use 'required', never 'sufficient'.
auth    required    pam_purpose.so groups=wheel

```

# SECURITY CONSIDERATIONS

Misconfiguration of this module can introduce a severe security vulnerability.

1. The control-flag **MUST** be set to `required` or `requisite`. Using `sufficient` will create a serious security vulnerability, allowing targeted users to bypass primary authentication.

2. This module **MUST** be placed in the `auth` stack *after* the primary authentication module(s) (e.g., `pam_unix.so`).

# SEE ALSO

**pam.conf**(5), **pam**(8), **syslog**(3)


