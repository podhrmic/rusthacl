use std::process::Command;
use std::env;


fn main() {

  let out = Command::new("git")
        .arg("clone")
        .arg("https://github.com/mitls/hacl-c.git")
        .output()
        .expect("failed to execute process");
  println!("Rusthacl git: {:?}", out);

  let out = Command::new("make")
        .env("CC", "gcc")
        .arg("-C")
        .arg("hacl-c")
        .arg("libhacl.a")
        .output()
        .expect("failed to execute process");
  println!("Rusthacl make: {:?}", out);

  let out_dir = env::var("OUT_DIR").unwrap();
  let out = Command::new("mv")
        .arg("hacl-c/libhacl.a")
        .arg(out_dir + "/.")
        .output()
        .expect("failed to execute process");
  println!("Rusthacl mv: {:?}", out);

  let out_dir = env::var("OUT_DIR").unwrap();		
  println!("cargo:rustc-link-search={}",out_dir);
  println!("cargo:rustc-link-lib=hacl");		
}
