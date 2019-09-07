extern crate cmake;

use std::io::Result;

fn main() -> Result<()> {
    let clib = cmake::build("clib");

    println!("cargo:rustc-link-search=native={}", clib.display());
    println!("cargo:rustc-link-lib=static=jabberdclib");

    Ok(())
}
