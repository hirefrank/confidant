//! Pure ratatui view renderers for `confidant-tui`.
//!
//! Every view exposes `pub fn render(state, frame, area)` and performs no I/O.

pub mod alert;
pub mod check;
pub mod confirm;
pub mod context;
pub mod diff;
pub mod doctor;
pub mod find;
pub mod proposals;
