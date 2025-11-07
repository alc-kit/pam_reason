# pam_purpose PAM module
## A KvalitetsIT extensions for PAM

pam_purpose is a PAM module for asking users for the purpose of their login to hosts 
used in KIT K8s installations. The purpose is to simply enquire why a user logs on to a
host and notice this in the audit log. If the audit log is correctly configured this
information will be used to correlate actions with a given task to be handled.

## License

This software is released as LGPL 2.0, no rights reserved. Use it at your own discretion,
but do not expect anything but a few helping pats on your back if you mess up stuff.

## The source code

The source code is split up in two parts - each a replacement for the other, because we 
we have not yet decided if the C or Rust version will survive. This is left for testing.

The source code root directory is split up in two directories C and Rust.
Build scripts reside under each directory.
