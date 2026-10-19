//! Runtime pack registry (#432).
//!
//! Replaces the compile-time [`crate::packs::ALL_PACKS`] lookups with a
//! runtime `PackRegistry` value passed to call sites. The registry holds
//! any compiled packs, the implicit built-ins (#551) and the external packs
//! loaded from `confidant.lock` (#438). There are no compiled optional
//! packs today (#449).
//!
//! A compiled pack always wins on the same `name@version` (PD14); per-pack
//! failures fail closed (PD12). The [`crate::packs::Pack`] trait is not
//! changed by this module.

use crate::packs::embedded;
use crate::packs::manifest::PackOrigin;
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

    /// Whether the registry's pack `name` came from the vault (external)
    /// rather than being compiled into the binary (#535). `false` for a
    /// name no pack implements. The decision is by [`Pack::origin`], never
    /// by base name, so an external pack whose base name matches a
    /// compiled pack (`coaching@0.9` next to `coaching@0.1`) is still
    /// external.
    pub fn is_external(&self, name: &str) -> bool {
        self.packs
            .iter()
            .find(|p| p.name() == name)
            .is_some_and(|p| p.origin() == PackOrigin::External)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::{Finding, MergeMap};
    use crate::vault::{SourcedEntry, Vault};
    use chrono::NaiveDate;

    struct CollidingExternal;
    struct EmptyState;

    impl crate::packs::PackState for EmptyState {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    impl Pack for CollidingExternal {
        fn name(&self) -> &'static str {
            "coaching@0.9"
        }
        fn verbs(&self) -> &'static [&'static str] {
            &[]
        }
        fn record_types(&self) -> &'static [&'static str] {
            &[]
        }
        fn fields(&self) -> &'static [&'static str] {
            &[]
        }
        fn balance_metrics(&self) -> &'static [&'static str] {
            &[]
        }
        fn finding_codes(&self) -> &'static [&'static str] {
            &[]
        }
        fn origin(&self) -> PackOrigin {
            PackOrigin::External
        }
        fn fold(
            &self,
            _vault: &Vault,
            _merges: &MergeMap,
            _as_of: NaiveDate,
            _findings: &mut Vec<Finding>,
        ) -> Box<dyn crate::packs::PackState> {
            Box::new(EmptyState)
        }
        fn findings(
            &self,
            _vault: &Vault,
            _state: &dyn crate::packs::PackState,
            _as_of: NaiveDate,
            _findings: &mut Vec<Finding>,
        ) {
        }
        fn check_balance(
            &self,
            _vault: &Vault,
            _state: &dyn crate::packs::PackState,
            _sourced: &SourcedEntry,
            _findings: &mut Vec<Finding>,
        ) {
        }
    }

    /// #535: an external pack whose base name matches a compiled pack is
    /// still external. The external-pack label keys on [`Pack::origin`], not
    /// on the name, so this origin decision must not be fooled by a name
    /// collision. A synthetic registry stands in for the (unreachable) real
    /// install: both colliding base names are reserved and the external
    /// loader refuses them (`E_PACK_INVALID`, #504 R8).
    #[test]
    fn is_external_decides_by_origin_not_base_name() {
        let mut registry = PackRegistry::compiled();
        let external: &'static dyn Pack = Box::leak(Box::new(CollidingExternal));
        registry.register(external);

        // The external pack keeps the compiled pack's base name.
        assert_eq!(
            "coaching@0.9".split('@').next(),
            "coaching@0.1".split('@').next()
        );
        assert!(registry.is_external("coaching@0.9"));
        // The compiled pack and the compiled-in built-in are not external,
        // even though the built-in carries skill text of its own.
        assert!(!registry.is_external("coaching@0.1"));
        assert!(!registry.is_external("personal@0.2"));
        // A name no pack implements is not external.
        assert!(!registry.is_external("nope@9.9"));
    }
}
