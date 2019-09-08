extern crate cmake;

use std::io::Result;

fn main() -> Result<()> {
    let clib = cmake::build("clib");

    println!("cargo:rustc-link-search=native={}", clib.display());
    println!("cargo:rustc-link-lib=static=jabberdclib");
    println!("cargo:rustc-link-lib=stdc++");
    println!("cargo:rustc-link-lib=idn");
    println!("cargo:rustc-link-lib=glibmm-2.4");
    println!("cargo:rustc-link-lib=gobject-2.0");
    println!("cargo:rustc-link-lib=glib-2.0");
    println!("cargo:rustc-link-lib=sigc-2.0");
    Ok(())
}
