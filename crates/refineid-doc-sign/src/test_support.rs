// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! Test-only helpers for the ported sign stack.
use refineid_lib_core::x509::{Certificate, OwnedCert};

/// Parse a fixture certificate for tests.
///
/// `Certificate::from_der` is crate-private in lib-core, and the
/// owned wrapper cannot lend a borrowed view past its own
/// lifetime, so the parsed wrapper is intentionally leaked: a few
/// kilobytes per test, freed at process exit. Test code only.
pub fn parse_certificate_for_test(der: &[u8]) -> Certificate<'static> {
    let owned = Box::new(OwnedCert::from_der(der).expect("fixture certificate parses"));
    Box::leak(owned).view()
}
