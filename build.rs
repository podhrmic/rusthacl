extern crate gcc;

use std::process::Command;

fn main() {
    Command::new("git")
        .arg("clone")
        .arg("https://github.com/mitls/hacl-c.git")
        .output()
        .expect("failed to execute process");

    Command::new("make")
        .arg("-C")
        .arg("hacl-c")
        .arg("libhacl.a")
        .output()
        .expect("failed to execute process");

	println!("cargo:rustc-link-search=native=hacl-c");
    println!("cargo:rustc-link-lib=hacl");
		
}
