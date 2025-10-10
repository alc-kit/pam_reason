### Sådan bruges værktøjet

1.  **Gem filen:** Gem koden som `check_pam_purpose.py` et passende sted på din server (f.eks. i `/usr/local/sbin/`).
2.  **Gør den eksekverbar:**
    ```bash
    sudo chmod +x /usr/local/sbin/check_pam_purpose.py
    ```
3.  **Kør den med `sudo`:** Scriptet skal bruge root-rettigheder for at kunne læse `/etc/pam.d/sshd` og slå gruppeinformation op.
    ```bash
    sudo check_pam_purpose.py <brugernavn>
    ```

#### Eksempel på output (hvis brugeren matcher)

```
$ sudo ./check_pam_purpose.py alice
--- PAM Purpose Debugger ---
Analyzing configuration for user: alice

User 'alice' is a member of the following groups:
  alice, wheel, sudo

Found active configuration line in /etc/pam.d/sshd:
  auth    required    pam_purpose.so users=bob,charlie groups=wheel

Parsed configuration:
  - Users to prompt: bob,charlie
  - Groups to prompt: wheel

--- Analysis ---
[MATCH] User 'alice' is a member of a required group: wheel

====================
DECISION: User 'alice' WILL BE PROMPTED for a purpose.
====================

