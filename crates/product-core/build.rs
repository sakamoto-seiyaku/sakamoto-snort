use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let fixture_source = manifest_dir
        .join("..")
        .join("..")
        .join("src")
        .join("product")
        .join("native")
        .join("sakamoto_product_host_fixture_abi.c");
    println!("cargo:rerun-if-changed={}", fixture_source.display());
    println!(
        "cargo:rerun-if-changed={}",
        fixture_source.parent().unwrap().display()
    );

    let vapi_include = env::var_os("SAKAMOTO_PRODUCT_VAPI_INCLUDE_DIR");
    let generated_include = env::var_os("SAKAMOTO_PRODUCT_VAPI_GENERATED_DIR");
    let require_vapi = env::var_os("SAKAMOTO_PRODUCT_VAPI_REQUIRED")
        .map(|value| value == "1")
        .unwrap_or(false);
    let use_vapi = vapi_include.is_some() && generated_include.is_some();
    if vapi_include.is_some() != generated_include.is_some() {
        panic!("SAKAMOTO_PRODUCT_VAPI_INCLUDE_DIR and SAKAMOTO_PRODUCT_VAPI_GENERATED_DIR must be supplied together");
    }
    if require_vapi && !use_vapi {
        panic!("the production Host artifact requires generated VAPI headers; set both SAKAMOTO_PRODUCT_VAPI_* directories");
    }
    let source = if use_vapi {
        manifest_dir
            .join("..")
            .join("..")
            .join("src")
            .join("product")
            .join("native")
            .join("sakamoto_product_vapi.c")
    } else {
        fixture_source
    };
    println!("cargo:rerun-if-changed={}", source.display());
    println!("cargo:rerun-if-env-changed=SAKAMOTO_PRODUCT_VAPI_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=SAKAMOTO_PRODUCT_VAPI_GENERATED_DIR");
    println!("cargo:rerun-if-env-changed=SAKAMOTO_PRODUCT_VAPI_LIBRARY_DIR");
    println!("cargo:rerun-if-env-changed=SAKAMOTO_PRODUCT_VAPI_REQUIRED");

    let include_dir = manifest_dir
        .join("..")
        .join("..")
        .join("src")
        .join("product")
        .join("include");
    let library_name = if use_vapi {
        "sakamoto_product_vapi_abi"
    } else {
        "sakamoto_product_host_fixture_abi"
    };
    let object = out_dir.join(format!("{library_name}.o"));
    let library = out_dir.join(format!("lib{library_name}.a"));
    let mut compiler = Command::new("cc");
    compiler
        .args([
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fno-strict-aliasing",
        ])
        .arg("-I")
        .arg(&include_dir);
    if use_vapi {
        compiler.arg("-I").arg(vapi_include.as_ref().unwrap());
        compiler.arg("-I").arg(generated_include.as_ref().unwrap());
    } else {
        compiler.arg("-DSAKAMOTO_PRODUCT_HOST_FIXTURE=1");
    }
    let status = compiler
        .arg("-c")
        .arg(&source)
        .arg("-o")
        .arg(&object)
        .status()
        .expect("failed to invoke the C compiler for the product ABI");
    assert!(status.success(), "product ABI C compilation failed");

    let status = Command::new("ar")
        .args(["crus"])
        .arg(&library)
        .arg(&object)
        .status()
        .expect("failed to invoke ar for the product ABI");
    assert!(status.success(), "product ABI archive failed");

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static={library_name}");
    if use_vapi {
        if let Some(vapi_library) = env::var_os("SAKAMOTO_PRODUCT_VAPI_LIBRARY_DIR") {
            println!(
                "cargo:rustc-link-search=native={}",
                PathBuf::from(vapi_library).display()
            );
        }
        println!("cargo:rustc-link-lib=dylib=vapiclient");
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=dl");
        println!("cargo:rustc-link-lib=rt");
        println!("cargo:rustc-link-lib=m");
    }
}
