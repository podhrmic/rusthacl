use std::process::Command;
use std::env;


fn main() {

  let out = Command::new("git")
        .arg("clone")
        .arg("https://github.com/mitls/hacl-c.git")
        .output()
        .expect("failed to execute process");
  println!("rusthacl git out: {:?}",out);

  let out = Command::new("make")
        .arg("-C")
        .arg("hacl-c")
        .arg("libhacl.a")
        .output()
        .expect("failed to execute process");
  println!("rusthacl make out: {:?}",out);

  



  let out_dir = env::var("OUT_DIR").unwrap();

  let out = Command::new("mv")
        .arg("hacl-c/libhacl.a")
        .arg(out_dir + "/.")
        .output()
        .expect("failed to execute process");
  println!("rusthacl mv out: {:?}",out);

  let out_dir = env::var("OUT_DIR").unwrap();
  println!("rusthacl OUT_DIR = {}", out_dir);		
	println!("cargo:rustc-link-search={}",out_dir);
  println!("cargo:rustc-link-lib=hacl");		
}
