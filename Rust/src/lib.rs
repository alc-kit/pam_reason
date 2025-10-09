// src/lib.rs
// Importér de nødvendige elementer. Vi importerer funktionerne direkte fra nonstick
use nonstick::{
    // Importerer de nødvendige elementer, der er globale i nonstick
    PamModule, ModuleClient, ErrorCode, Result as PamResult,
    Item as PamItem, Type as PamType, AuthnFlags as PamFlags,
    // Importerer de specifikke funktioner som standalone kald
    get_user, get_item, Conversation as conversation,
    pam_export,
};
use std::{ffi::CStr, str};
use log::{info, warn, error};
use syslog::{Facility, init, LogFormat};

// --- KONSTANTER ---
const PURPOSE_PROMPT: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"Enter purpose for login (Brief reason): \0") };
const WHITELIST_PREFIX: &str = "only_for_users=";

// --- LOGGING INITIALISERING ---
// Funktionen, der initialiserer loggeren kun én gang
fn init_logging() {
    let _ = init(Facility::LOG_AUTH, log::LevelFilter::Info, Some("PAM_RUST_PURPOSE"))
        .map_err(|e| {
            // Hvis syslog init fejler, fallback til stderr/stdout
            eprintln!("CRITICAL: Failed to initialize SysLog. Error: {}", e);
        });
}

// --- PAM FUNKTIONER ---

struct RequirePurpose;
pam_export!(RequirePurpose);

impl<> PamModule<> for RequirePurpose {
    
}

#[no_mangle]
pub extern "C" fn pam_sm_authenticate(
    pamh: &mut Pam,
    _flags: PamFlag,
    _args: Vec<String>, // Brug string her for at matche moderne nonstick
) -> PamResult {
    // Kald init_logging, hvis det ikke allerede er sket (kan gøres i en lazy_static blok for sikrere singleton)
    init_logging(); 

    // Bemærk: Nonstick giver direkte adgang til metoder på pamh
    let user = match pamh.get_item::<String>(PamItem::User) {
        Ok(Some(u)) => u,
        _ => return PamError::AuthErr.into(),
    };

    // 1. Tjek Whitelist (Args er nu Vec<String> for at lette parsing)
    // Implementér logikken for at tjekke bruger mod _args her

    // 2. Detekter Non-Interaktiv Session
    let tty_name = pamh.get_item::<String>(PamItem::Tty).unwrap_or_default();

    if tty_name.is_empty() {
        info!("User={} ACTION=LOGIN_SUCCESS Purpose='AUTOMATED_ACCESS' TTY=NULL", user);
        return PamResult::Success;
    }

    // 3. Interaktiv Prompt (Brug Conversation-objektet)
    // Vi bruger pamh.conversation til at bede om input
    match pamh.conversation(|conv| {
        // Bemærk: Nonstick håndterer C-strenge og frigørelse for dig
        let response = conv.send_message(
            PamType::PromptEchoOn, 
            PURPOSE_PROMPT
        )?;
        Ok(response)
    }) {
        Ok(Some(response)) => {
            let purpose = response;
            if purpose.is_empty() {
                warn!("LOGIN_DENIED: User={} Missing purpose.", user);
                return PamResult::AuthErr;
            }
            info!("LOGIN_PURPOSE_AUDIT: User={} ACTION=LOGIN_SUCCESS Purpose='{}'", user, purpose);
            PamResult::Success
        }
        _ => {
            warn!("LOGIN_DENIED: User={} Prompt failed or aborted.", user);
            PamResult::AuthErr
        }
    }
}

// --- PAM STUBS ---
// nonstick kræver, at du definerer alle de nødvendige C-funktioner

#[no_mangle]
pub extern "C" fn pam_sm_setcred(pamh: &mut Pam, flags: PamFlag, args: Vec<String>) -> PamResult {
    PamResult::Success
}
// Du skal definere de resterende stubs: pam_sm_acct_mgmt, pam_sm_open_session, pam_sm_close_session.
// Sørg for at bruge den korrekte signatur: (pamh: &mut Pam, flags: PamFlag, args: Vec<String>) -> PamResult
#[no_mangle]
pub extern "C" fn pam_sm_acct_mgmt(pamh: &mut Pam, flags: PamFlags, args: Vec<String>) -> PamResult {
    PamResult::Success
}

#[no_mangle]
pub extern "C" fn pam_sm_open_session(pamh: &mut Pam, flags: PamFlags, args: Vec<String>) -> PamResult {
    PamResult::Success
}

#[no_mangle]
pub extern "C" fn pam_sm_close_session(pamh: &mut Pam, flags: PamFlags, args: Vec<String>) -> PamResult {
    PamResult::Success
}

