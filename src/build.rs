//! Embed the decryptor icon in Windows PE resources without checking a
//! generated binary .ico file into the source tree.
//! The same PNG is also used by eframe for the visible window icon.

use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=assets/decryptor-icon.png");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    // Windows ICO directory with a single PNG-compressed 64x64 image.
    let png = include_bytes!("../assets/decryptor-icon.png");
    assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"), "bundled icon is not a PNG");
    let size = u32::try_from(png.len()).expect("icon too large");
    let mut ico = Vec::with_capacity(png.len() + 22);
    ico.extend_from_slice(&[0, 0, 1, 0, 1, 0]); // reserved, icon type, one image
    ico.extend_from_slice(&[64, 64, 0, 0]); // width, height, palette, reserved
    ico.extend_from_slice(&1u16.to_le_bytes()); // color planes
    ico.extend_from_slice(&32u16.to_le_bytes()); // bits per pixel
    ico.extend_from_slice(&size.to_le_bytes());
    ico.extend_from_slice(&22u32.to_le_bytes()); // PNG offset after ICO header
    ico.extend_from_slice(png);

    let ico_path = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR not set"))
        .join("decryptor.ico");
    fs::write(&ico_path, ico).expect("cannot write temporary Windows icon");
    winresource::WindowsResource::new()
        .set_icon(ico_path.to_str().expect("non-UTF8 build output path"))
        .compile()
        .expect("cannot compile Windows executable icon resource");
}
