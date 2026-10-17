//! Runtime pack registry (#432).
//!
//! Replaces the compile-time [`crate::packs::ALL_PACKS`] lookups with a
//! runtime `PackRegistry` value passed to call sites. For now the registry
//! holds exactly the two compiled packs (no behaviour change); a later
//! issue adds loaded packs from `confidant.lock` (#438).
//!
//! A compiled pack always wins on the same `name@version` (PD14); per-pack
//! failures fail closed (PD12). The [`crate::packs::Pack`] trait is not
//! changed by this module.

use crate::packs::{orphan_owners, resolve_enabled, OrphanOwners, Pack};

/// The packs available to a vault, resolved at runtime.
#[derive(Clone)]
pub struct PackRegistry {
    packs: Vec<&'static dyn Pack>,
}

impl std::fmt::Debug for PackRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PackRegistry")
            .field(
                "packs",
                &self.packs.iter().map(|p| p.name()).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl PackRegistry {
    /// Register one pack at load time (#438). External packs are leaked
    /// per vault load and appended here; the compiled packs always come
    /// first, so a compiled pack wins on the same `name@version` (PD14)
    /// by construction of the loader.
    pub fn register(&mut self, pack: &'static dyn Pack) {
        self.packs.push(pack);
    }

    /// The compiled packs, in `ALL_PACKS` order.
    pub fn compiled() -> Self {
        Self {
            packs: crate::packs::ALL_PACKS.to_vec(),
        }
    }

    /// All packs in the registry, in registry order.
    pub fn all(&self) -> &[&'static dyn Pack] {
        &self.packs
    }

    /// The enabled packs for a vault's `packs = [...]` list, each at most
    /// once (a duplicated listing folds once), plus the listed names no
    /// pack in this registry implements. Order follows the config list.
    pub fn resolve_enabled(&self, names: &[String]) -> (Vec<&'static dyn Pack>, Vec<String>) {
        resolve_enabled(names, &self.packs)
    }

    /// Claims owned by packs in this registry that are *not* in `enabled`,
    /// keyed by claim name to the owning pack's name. `check` turns these
    /// into `W_PACK_ORPHAN` warnings instead of unknown-verb /
    /// unknown-metric errors.
    pub fn orphan_owners(&self, enabled: &[&dyn Pack]) -> OrphanOwners {
        orphan_owners(&self.packs, enabled)
    }
}
