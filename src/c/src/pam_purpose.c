// pam_purpose.c - Hardened version with DUAL (syslog + auditd) logging

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <grp.h>      // Needed for group lookups
#include <pwd.h>      // Needed for user information
#include <libaudit.h> // Added for auditd
#include <errno.h>    // Added for auditd error checking

// --- CONSTANTS ---
#define PURPOSE_PROMPT "Enter purpose for login (Brief reason): "
#define USERS_PREFIX "users="
#define GROUPS_PREFIX "groups="
#define MAX_PURPOSE_LENGTH 500 // Max length for user-provided purpose
#define MAX_REASON_LENGTH 128  // Buffer for logging the match reason

// --- HELPER FUNCTIONS ---

// Checks if the user is a member of any of the specified groups.
// Returns 1 for yes, 0 for no.
int is_user_in_listed_groups(pam_handle_t *pamh, const char *user, const char *groups_list_str) {
    if (!user || !groups_list_str) return 0;

    // Get user's group information
    struct passwd *pw = getpwnam(user);
    if (!pw) {
        pam_syslog(pamh, LOG_ERR, "Could not find user '%s' for group lookup.", user);
        return 0;
    }

    int ngroups = 0;
    getgrouplist(user, pw->pw_gid, NULL, &ngroups); // Get the number of groups
    gid_t *groups = malloc(sizeof(gid_t) * ngroups);
    if (!groups) {
        pam_syslog(pamh, LOG_CRIT, "CRIT: Failed to allocate memory for group list.");
        return 0;
    }
    getgrouplist(user, pw->pw_gid, groups, &ngroups);

    // Copy the group list for safe use with strtok()
    char *list_copy = strdup(groups_list_str);
    if (!list_copy) {
        pam_syslog(pamh, LOG_CRIT, "CRIT: Failed to allocate memory for group list copy.");
        free(groups);
        return 0;
    }

    char *token = strtok(list_copy, ",");
    int found = 0;
    while (token != NULL) {
        struct group *gr = getgrnam(token);
        if (gr) {
            for (int i = 0; i < ngroups; i++) {
                if (gr->gr_gid == groups[i]) {
                    found = 1;
                    break;
                }
            }
        }
        if (found) break;
        token = strtok(NULL, ",");
    }

    free(list_copy);
    free(groups);
    return found;
}

// Checks if the user is on the specified user list.
// Returns 1 for yes, 0 for no.
int is_user_in_listed_users(const char *user, const char *users_list_str) {
    if (!user || !users_list_str) return 0;

    char *list_copy = strdup(users_list_str);
    if (!list_copy) return 0; // Error handling in calling function

    char *token = strtok(list_copy, ",");
    int found = 0;
    while (token != NULL) {
        if (strcmp(user, token) == 0) {
            found = 1;
            break;
        }
        token = strtok(NULL, ",");
    }
    free(list_copy);
    return found;
}

// --- NEW HELPER FUNCTION: DUAL LOGGING (AUDITD + SYSLOG) ---
static void log_pam_event(pam_handle_t *pamh, const char *user, const char *action, 
                          const char *purpose, const char *match_reason, int success, int pam_retval)
{
    int au_fd = -1;
    char msg_buf[1024];
    const char *tty_name = NULL;
    const char *rhost = NULL;

    // 1. Get additional context from PAM
    pam_get_item(pamh, PAM_TTY, (const void **)&tty_name);
    pam_get_item(pamh, PAM_RHOST, (const void **)&rhost);

    // 2. Build the structured message payload
    snprintf(msg_buf, sizeof(msg_buf),
             "op=pam_purpose action=%s user=%s purpose=\"%s\" match_reason=\"%s\" pam_retval=%d",
             action,
             user ? user : "unknown",
             purpose ? purpose : "none",
             match_reason ? match_reason : "none",
             pam_retval);

    // --- 3. Log to auditd (The primary audit log) ---
    au_fd = audit_open();
    if (au_fd < 0) {
        // If we can't open auditd, log this error *to syslog*
        pam_syslog(pamh, LOG_CRIT, "CRIT: Failed to open auditd connection (errno=%d). PAM_PURPOSE FAILED.", errno);
    } else {
        if (audit_log_user_message(au_fd, AUDIT_USER_AUTH, msg_buf,
                                   rhost, NULL, tty_name, success) <= 0) {
            // If writing to auditd fails, log this error *to syslog*
            pam_syslog(pamh, LOG_ERR, "Failed to write to auditd. Message was: %s", msg_buf);
        }
        audit_close(au_fd);
    }

    // --- 4. Log to syslog (The operational/debug log) ---
    // We log to syslog regardless, so administrators can see it in journalctl -f
    int log_level = (success == 1) ? LOG_INFO : LOG_ERR;
    pam_syslog(pamh, log_level, "%s", msg_buf);
}


// --- MAIN FUNCTION: AUTHENTICATION ---
PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
                    int argc, const char **argv)
{
    // Explicitly mark 'flags' as unused to prevent compiler errors with -Werror
    (void)flags;

    const char *user = NULL;
    const char *users_list_str = NULL;
    const char *groups_list_str = NULL;
    int user_match = 0;
    int group_match = 0;
    // Use the new, larger constant for match_reason buffer
    char match_reason[MAX_REASON_LENGTH] = "not specified";
    // Default to denying access (Fail-Safe)
    int pam_ret_val = PAM_AUTH_ERR; 
    int retval; // To store return values from PAM calls

    // 1. Get user
    if ((retval = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS || !user) {
        pam_syslog(pamh, LOG_ERR, "CRIT: Could not retrieve PAM_USER. Denying.");
        return PAM_AUTH_ERR;
    }

    // 2. Parse arguments for user and group lists
    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], USERS_PREFIX, strlen(USERS_PREFIX)) == 0) {
            users_list_str = argv[i] + strlen(USERS_PREFIX);
        } else if (strncmp(argv[i], GROUPS_PREFIX, strlen(GROUPS_PREFIX)) == 0) {
            groups_list_str = argv[i] + strlen(GROUPS_PREFIX);
        }
    }

    // If no lists are provided, the module does nothing for any user
    if (!users_list_str && !groups_list_str) {
        return PAM_SUCCESS;
    }

    // 3. Check if the user matches one of the lists
    if (users_list_str && is_user_in_listed_users(user, users_list_str)) {
        user_match = 1;
    }
    if (groups_list_str && is_user_in_listed_groups(pamh, user, groups_list_str)) {
        group_match = 1;
    }

    // If the user matches neither list, skip
    if (!user_match && !group_match) {
        return PAM_SUCCESS;
    }

    // Build reason string for logging
    if (user_match && group_match) {
        // snprintf is safe and will respect the MAX_REASON_LENGTH
        snprintf(match_reason, sizeof(match_reason), "user and group lists");
    } else if (user_match) {
        snprintf(match_reason, sizeof(match_reason), "users list");
    } else if (group_match) {
        snprintf(match_reason, sizeof(match_reason), "groups list");
    }

    // 4. Detect Non-Interactive Session
    const char *tty_name = NULL;
    pam_get_item(pamh, PAM_TTY, (const void **)&tty_name);
    
    if (!tty_name || strlen(tty_name) == 0) {
        log_pam_event(pamh, user, "LOGIN_SUCCESS", "AUTOMATED_ACCESS", match_reason, 1, PAM_SUCCESS);
        return PAM_SUCCESS;
    }

    // 5. Interactive Prompt
    char *purpose_response = NULL;
    retval = pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &purpose_response, PURPOSE_PROMPT);

    if (retval == PAM_SUCCESS && purpose_response) {
        size_t purpose_len = strlen(purpose_response);

        if (purpose_len == 0) {
            // Failure: Empty response
            log_pam_event(pamh, user, "LOGIN_DENIED", "Empty purpose", match_reason, 0, retval);
            pam_ret_val = PAM_AUTH_ERR;
        } else if (purpose_len > MAX_PURPOSE_LENGTH) {
            // Failure: Response is too long
            log_pam_event(pamh, user, "LOGIN_DENIED", "Purpose too long", match_reason, 0, retval);
            pam_ret_val = PAM_AUTH_ERR;
        } else {
            // Success: Log and set return value to success
            log_pam_event(pamh, user, "LOGIN_SUCCESS", purpose_response, match_reason, 1, PAM_SUCCESS);
            pam_ret_val = PAM_SUCCESS;
        }
    } else {
        // Failure: pam_prompt() failed (e.g., user pressed Ctrl+C)
        // retval now contains the error code from pam_prompt
        log_pam_event(pamh, user, "LOGIN_DENIED", "Prompt failed/aborted", match_reason, 0, retval);
        pam_ret_val = PAM_AUTH_ERR;
    }

    // Clean up the memory allocated by pam_prompt
    if (purpose_response) {
        free(purpose_response);
    }

    return pam_ret_val;
}

// --- PAM STUBS ---
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}


