// rs/build.rs
use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // Tell Cargo to re-run this script only if the man page markdown changes
    println!("cargo:rerun-if-changed=../doc/pam_purpose.8.md");

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("pam_purpose.8");
    
    // Convert the shared man page from the ../doc/ directory
    if let Err(e) = pandoc::new()
        .add_input("../doc/pam_purpose.8.md")
        .set_output(pandoc::OutputKind::File(dest_path))
        .set_output_format(pandoc::OutputFormat::Man)
        .execute()
    {
        // If pandoc fails, just print a warning but don't fail the build
        eprintln!("Warning: Failed to convert man page with pandoc: {}", e);
    }
}

