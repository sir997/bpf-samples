// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)"
//
// THIS FILE IS AUTOGENERATED BY CARGO-LIBBPF-GEN!

#[path = "minimal.skel.rs"]
mod minimal_skel;

#[path = "minimal_legacy.skel.rs"]
mod minimal_legacy_skel;

#[path = "bootstrap.skel.rs"]
mod bootstrap_skel;

pub use minimal_skel::*;

pub use minimal_legacy_skel::*;

pub use bootstrap_skel::*;
