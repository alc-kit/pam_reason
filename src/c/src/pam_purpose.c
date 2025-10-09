// pam_purpose.c - Hærdet udgave med bruger- og gruppelister
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <grp.h>      // Nødvendig for gruppeopslag
#include <pwd.h>      // Nødvendig for at få brugerinformation

// --- KONSTANTER ---
#define PURPOSE_PROMPT "Enter purpose for login (Brief reason): "
#define USERS_PREFIX "users="
#define GROUPS_PREFIX "groups="

// --- HJÆLPEFUNKTIONER ---

// Tjekker om brugeren er medlem af en af de specificerede grupper.
// Returnerer 1 for ja, 0 for nej.
int is_user_in_listed_groups(pam_handle_t *pamh, const char *user, const char *groups_list_str) {
    if (!user || !groups_list_str) return 0;

    // Få brugerens gruppeinformation
    struct passwd *pw = getpwnam(user);
    if (!pw) {
        pam_syslog(pamh, LOG_ERR, "Could not find user '%s' for group lookup.", user);
        return 0;
    }

    int ngroups = 0;
    getgrouplist(user, pw->pw_gid, NULL, &ngroups); // Få antallet af grupper
    gid_t *groups = malloc(sizeof(gid_t) * ngroups);
    if (!groups) {
        pam_syslog(pamh, LOG_CRIT, "CRIT: Failed to allocate memory for group list.");
        return 0;
    }
    getgrouplist(user, pw->pw_gid, groups, &ngroups);

    // Kopier gruppelisten for sikker brug af strtok()
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

// Tjekker om brugeren er på den specificerede brugerliste.
// Returnerer 1 for ja, 0 for nej.
int is_user_in_listed_users(const char *user, const char *users_list_str) {
    if (!user || !users_list_str) return 0;

    char *list_copy = strdup(users_list_str);
    if (!list_copy) return 0; // Fejlhåndtering i kaldende funktion

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


// --- HOVED FUNKTION: GODKENDELSE ---
PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
                    int argc, const char **argv)
{
    const char *user = NULL;
    const char *users_list_str = NULL;
    const char *groups_list_str = NULL;
    int user_match = 0;
    int group_match = 0;
    char match_reason[64] = "not specified";

    // Standard til at nægte adgang (Fail-Safe)
    int pam_ret_val = PAM_AUTH_ERR;

    // 1. Hent bruger
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !user) {
        pam_syslog(pamh, LOG_ERR, "CRIT: Could not retrieve PAM_USER. Denying.");
        return PAM_AUTH_ERR;
    }

    // 2. Parse argumenter for bruger- og gruppelister
    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], USERS_PREFIX, strlen(USERS_PREFIX)) == 0) {
            users_list_str = argv[i] + strlen(USERS_PREFIX);
        } else if (strncmp(argv[i], GROUPS_PREFIX, strlen(GROUPS_PREFIX)) == 0) {
            groups_list_str = argv[i] + strlen(GROUPS_PREFIX);
        }
    }

    // Hvis ingen lister er angivet, gælder modulet ikke for nogen
    if (!users_list_str && !groups_list_str) {
        return PAM_SUCCESS;
    }

    // 3. Tjek om brugeren matcher en af listerne
    if (users_list_str && is_user_in_listed_users(user, users_list_str)) {
        user_match = 1;
    }
    if (groups_list_str && is_user_in_listed_groups(pamh, user, groups_list_str)) {
        group_match = 1;
    }

    // Hvis brugeren ikke matcher nogen af listerne, spring over
    if (!user_match && !group_match) {
        return PAM_SUCCESS;
    }

    // Opbyg årsag til logning
    if (user_match && group_match) {
        snprintf(match_reason, sizeof(match_reason), "user and group lists");
    } else if (user_match) {
        snprintf(match_reason, sizeof(match_reason), "users list");
    } else if (group_match) {
        snprintf(match_reason, sizeof(match_reason), "groups list");
    }

    // 4. Detekter Non-Interaktiv Session
    const char *tty_name = NULL;
    pam_get_item(pamh, PAM_TTY, (const void **)&tty_name);
    
    if (!tty_name || strlen(tty_name) == 0) {
        pam_syslog(pamh, LOG_INFO, "USER=%s ACTION=LOGIN_SUCCESS Purpose='AUTOMATED_ACCESS (matched %s)'", user, match_reason);
        return PAM_SUCCESS;
    }

    // 5. Interaktiv Prompt
    char *purpose_response = NULL;
    int retval = pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &purpose_response, PURPOSE_PROMPT);

    if (retval == PAM_SUCCESS && purpose_response && strlen(purpose_response) > 0) {
        pam_syslog(pamh, LOG_INFO, "USER=%s ACTION=LOGIN_SUCCESS Purpose='%s' (matched %s)", user, purpose_response, match_reason);
        pam_ret_val = PAM_SUCCESS;
    } else {
        pam_syslog(pamh, LOG_ERR, "USER=%s ACTION=LOGIN_DENIED REASON='Prompt failed or empty purpose' (matched %s)", user, match_reason);
    }

    if (purpose_response) {
        free(purpose_response);
    }

    return pam_ret_val;
}

// --- PAM STUBS ---
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
