// pam_require_purpose.c
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <stdio.h> // Til strtok

#define PURPOSE_PROMPT "Enter purpose for login (Brief reason): "
#define MAX_PURPOSE_LEN 256
#define WHITELIST_PREFIX "only_for_users="

// --- Deklarationer af Service Modul stubs (Nødvendige for linkning) ---
PAM_EXTERN int pam_sm_setcred(pam_handle_t *, int, int, const char **);
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *, int, int, const char **);
PAM_EXTERN int pam_sm_open_session(pam_handle_t *, int, int, const char **);
PAM_EXTERN int pam_sm_close_session(pam_handle_t *, int, int, const char **);

// --- WHITERLIST OG ARGUMENT PARSING ---

// Returnerer 1 hvis brugeren skal prompts, 0 hvis modulet skal springes over
// pam_require_purpose.c

// Funktion til at læse og tjekke, om brugeren er whitelisted
int check_whitelist(pam_handle_t *pamh, const char *user, int argc, const char **argv)
{
    // 1. ITERÉR GENNEM ARGUMENTER
    for (int i = 0; i < argc; i++) {
        // Tjek, om argumentet starter med "only_for_users="
        if (strncmp(argv[i], "only_for_users=", 15) == 0) {
            
            // 2. UDPAK BRUGERNAVNE
            // Spring "only_for_users=" over (15 tegn)
            const char *user_list_str = argv[i] + 15;
            
            // 3. OPBYG EN MIDLERTIDIG KOPI (strtok ændrer strengen)
            char list_copy[MAX_PURPOSE_LEN];
            strncpy(list_copy, user_list_str, MAX_PURPOSE_LEN - 1);
            list_copy[MAX_PURPOSE_LEN - 1] = '\0';

            // 4. SØG EFTER BRUGEREN I LISTEN
            char *token = strtok(list_copy, ","); // Splitter strengen ved komma
            while (token != NULL) {
                if (strcmp(user, token) == 0) {
                    // BRUGER FUNDET PÅ WHITELIST
                    pam_syslog(pamh, LOG_INFO, "User %s is whitelisted for purpose prompt.", user);
                    return 1; // Returner 1 for "skal eksekveres"
                }
                token = strtok(NULL, ",");
            }
            
            // Hvis listen blev fundet, men brugeren ikke var der
            return 0; // Returner 0 for "skal springes over"
        }
    }
    
    // Hvis parameteren "only_for_users=" ikke blev fundet, eksekveres modulet for ALLE
    pam_syslog(pamh, LOG_INFO, "No whitelist found. Module applied to all users.");
    return 1;
}

// --- HOVED FUNKTION: GODKENDELSE ---
PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
                    int argc, const char **argv)
{
    const char *user;
    const char *tty_name = NULL;
    const char *service_name = NULL;
    char *purpose_response = NULL;
    int retval;

    // 1. Hent PAM variabler (bruger)
    if ((retval = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) return retval;

    // 2. Tjek Whitelist: Afgør om modulet skal eksekveres for denne bruger
    if (check_whitelist(pamh, user, argc, argv) == 0) {
        return PAM_SUCCESS; // Spring over, hvis ikke på listen
    }

    // 3. Detekter Non-Interaktiv Session (PAM_TTY og PAM_SERVICE)
    pam_get_item(pamh, PAM_TTY, (const void **)&tty_name);
    pam_get_item(pamh, PAM_SERVICE, (const void **)&service_name);

    if (!tty_name || strcmp(tty_name, "") == 0 || (service_name && (strcmp(service_name, "sftp") == 0 || strcmp(service_name, "scp") == 0))) 
    {
        pam_syslog(pamh, LOG_INFO, "User=%s ACTION=LOGIN_SUCCESS Purpose='AUTOMATED_ACCESS' SERVICE=%s", user, service_name ? service_name : "UNKNOWN");
        return PAM_SUCCESS; // Tillad automatiseret adgang uden prompt
    }

    // 4. Interaktiv Prompt
    pam_syslog(pamh, LOG_INFO, "User %s initiated interactive login. Prompting for purpose.", user);
    
    retval = pam_prompt(pamh, PAM_PROMPT_ECHO_ON,
                        &purpose_response, PURPOSE_PROMPT);

    // 5. Håndter Resultat
    if (retval != PAM_SUCCESS || !purpose_response || strlen(purpose_response) == 0) {
        // Log og afvis hvis input mangler/fejler
        if (purpose_response) free(purpose_response);
        pam_syslog(pamh, LOG_ERR, "LOGIN_DENIED: User=%s Missing or failed purpose.", user);
        return PAM_AUTH_ERR;
    }
    
    // Succes: Journaliser og frigør hukommelse
    pam_syslog(pamh, LOG_INFO, "LOGIN_PURPOSE_AUDIT: User=%s ACTION=LOGIN_SUCCESS Purpose='%s'", user, purpose_response);
    free(purpose_response);

    return PAM_SUCCESS;
}

// --- PAM STUBS (Uændrede) ---

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) { return PAM_SUCCESS; }
