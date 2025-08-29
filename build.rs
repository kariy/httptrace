use std::env;
use std::path::PathBuf;

fn main() {
    // Build the C library for socket interposition
    cc::Build::new()
        .file("src/hook.c")
        .compile("libhook.a");
    
    // Tell cargo to look for the library
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=hook");
}
