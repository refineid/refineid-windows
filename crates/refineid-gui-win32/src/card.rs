// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! Card foundation: reader enumeration and ATR snapshots over PC/SC.
//! Public data only; no PIN enters this module.
use pcsc::{Attribute, Context, Protocols, Scope, ShareMode};

/// Reader names currently visible to PC/SC. Cheap; no card contact.
pub fn list_readers() -> Result<Vec<String>, String> {
    let context = Context::establish(Scope::User).map_err(|error| format!("{error:?}"))?;
    let names = context
        .list_readers_owned()
        .map_err(|error| format!("{error:?}"))?;
    Ok(names
        .iter()
        .map(|name| name.to_string_lossy().into_owned())
        .collect())
}

/// Space-separated ATR hex for one reader, or a short reason.
pub fn reader_atr_hex(reader: &str) -> Result<String, String> {
    let context = Context::establish(Scope::User).map_err(|error| format!("{error:?}"))?;
    let name = std::ffi::CString::new(reader).map_err(|_| String::from("Bad reader name."))?;
    let card = context
        .connect(&name, ShareMode::Shared, Protocols::ANY)
        .map_err(|error| format!("{error:?}"))?;
    let mut buffer = [0u8; 64];
    let atr = card
        .get_attribute(Attribute::AtrString, &mut buffer)
        .map_err(|error| format!("{error:?}"))?;
    Ok(hex_spaced(atr))
}

fn hex_spaced(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 3);
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            out.push(' ');
        }
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}
