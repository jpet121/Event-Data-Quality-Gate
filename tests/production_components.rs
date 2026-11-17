//! Exercise defensive contracts on the real production components.
#![allow(dead_code)]

extern crate self as sesv;
macro_rules! production_source {
    ($file:literal) => {
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/", $file));
    };
}
macro_rules! wire_source {
    ($file:literal) => {};
}
include!("../qualification/component_probes.rs");
