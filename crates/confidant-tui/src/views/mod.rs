//! Pure ratatui view renderers for `confidant-tui`.
//!
//! Every view exposes `pub fn render(state, frame, area)` and performs no I/O.

pub mod alert;
pub mod check;
pub mod context;
pub mod doctor;
pub mod find;
