//! Pure ratatui view renderers for `confidant-tui`.
//!
//! Every view exposes `pub fn render(state, frame, area)` and performs no I/O.

pub mod alert;
pub mod capture;
pub mod check;
pub mod confirm;
pub mod conflict;
pub mod context;
pub mod diff;
pub mod doctor;
pub mod help;
pub mod info;
pub mod palette;
pub mod people;
pub mod proposals;
pub mod search;
