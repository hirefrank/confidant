//! Runtime pack registry (#432).
//!
//! Replaces the compile-time [`crate::packs::ALL_PACKS`] lookups with a
//! runtime `PackRegistry` value passed to call sites. The registry holds
//! the compiled packs plus the implicit built-ins (#551); a later issue adds
//! loaded packs from `confidant.lock` (#438).
//!
//! A compiled pack always wins on the same `name@version` (PD14); per-pack
//! failures fail closed (PD12). The [`crate::packs::Pack`] trait is not
//! changed by this module.

use crate::packs::embedded;
use crate::packs::{orphan_owners, resolve_enabled, OrphanOwners, Pack};

/// The packs available to a vault, resolved at runtime.
///
/// `packs` holds every available pack: the compiled packs, the implicit
/// built-ins (#551) and any loaded external packs. `implicit` marks the
/// built-ins that are enabled in every vault, independent of the vault's
/// `packs = [...]` list.
#[derive(Clone)]
pub struct PackRegistry {
    packs: Vec<&'static dyn Pack>,
    implicit: Vec<&'static dyn Pack>,
}

impl std::fmt::Debug for PackRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PackRegistry")
            .field(
                "packs",
                &self.packs.iter().map(|p| p.name()).collect::<Vec<_>>(),
            )
            .field(
                "implicit",
                &self.implicit.iter().map(|p| p.name()).collect::<Vec<_>>(),
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

    /// The packs always available to a vault: the compiled packs plus the
    /// implicit built-ins (#551). The built-ins are enabled in every vault
    /// even when `packs = []`.
    pub fn compiled() -> Self {
        let implicit: Vec<&'static dyn Pack> = embedded::embedded_packs()
            .iter()
            .map(|p| p.pack())
            .collect();
        let mut packs = crate::packs::ALL_PACKS.to_vec();
        packs.extend(implicit.iter().copied());
        Self { packs, implicit }
    }

    /// All packs in the registry, in registry order.
    pub fn all(&self) -> &[&'static dyn Pack] {
        &self.packs
    }

    /// The implicit built-ins, enabled in every vault (#551).
    pub fn implicit(&self) -> &[&'static dyn Pack] {
        &self.implicit
    }

    /// The agent-facing skill text the registry's pack `name` carries, if
    /// any (#445). Compiled packs return `None` (their text is embedded in
    /// the CLI); an external pack returns its vendored skill file.
    pub fn skill_text(&self, name: &str) -> Option<&'static str> {
        self.packs
            .iter()
            .find(|p| p.name() == name)
            .and_then(|p| p.skill_text())
    }

    /// The enabled packs for a vault's `packs = [...]` list, each at most
    /// once (a duplicated listing folds once), plus the listed names no
    /// pack in this registry implements. Order follows the config list;
    /// the implicit built-ins are appended.
    pub fn resolve_enabled(&self, names: &[String]) -> (Vec<&'static dyn Pack>, Vec<String>) {
        resolve_enabled(names, &self.packs, &self.implicit)
    }

    /// Claims owned by packs in this registry that are *not* in `enabled`,
    /// keyed by claim name to the owning pack's name. `check` turns these
    /// into `W_PACK_ORPHAN` warnings instead of unknown-verb /
    /// unknown-metric errors.
    pub fn orphan_owners(&self, enabled: &[&dyn Pack]) -> OrphanOwners {
        orphan_owners(&self.packs, enabled)
    }
}
