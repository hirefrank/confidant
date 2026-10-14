//! Merge-canonicalization machinery shared by every compiled pack fold (#303).
//!
//! Coaching and personal independently grew the same skeleton: a merge map,
//! a per-date cache of merge groups, and the `canonical_on` / `ensure_members`
//! / `group_people` helpers around it. This module factors that skeleton so a
//! third pack reuses it instead of copying it, and reconciles the two packs'
//! subtly divergent `ensure_members` seeding (coaching seeded only from its
//! own people; personal also seeded every merge-map endpoint).

use std::cell::{Ref, RefCell};
use std::collections::{HashMap, HashSet};

use chrono::NaiveDate;

use crate::check::{canonical_on, MergeMap};
use crate::id::{Prefix, RecordId};

/// `as_of` → canonical person id → the member ids folded into it.
pub(crate) type MembersByRoot = HashMap<NaiveDate, HashMap<RecordId, Vec<RecordId>>>;

/// Merge map + per-date merge-group cache. [`MergeGroups`] is `Clone` so a
/// pack's fold can `Clone` it out of the parent's state; it shares the
/// `RefCell` cache. `Default` is the empty (no-merge) state.
#[derive(Clone, Debug, Default)]
pub(crate) struct MergeGroups {
    parent: MergeMap,
    members_by_root: RefCell<MembersByRoot>,
}

impl MergeGroups {
    pub(crate) fn new(parent: MergeMap) -> Self {
        Self {
            parent,
            members_by_root: RefCell::new(HashMap::new()),
        }
    }

    /// Merge-canonical id as of `on`.
    pub(crate) fn canonical_on(&self, id: &RecordId, on: NaiveDate) -> RecordId {
        canonical_on(id, &self.parent, on)
    }

    /// Cache the merge-group map for `on`, seeded from `seed` (the pack's own
    /// person ids) plus every merge-map endpoint, so a canonical person with
    /// no direct events still groups correctly. Idempotent per date.
    pub(crate) fn ensure_members<I>(&self, seed: I, on: NaiveDate)
    where
        I: IntoIterator<Item = RecordId>,
    {
        if self.members_by_root.borrow().contains_key(&on) {
            return;
        }
        let mut all: HashSet<RecordId> = seed.into_iter().collect();
        for (from, (to, _)) in &self.parent {
            all.insert(from.clone());
            all.insert(to.clone());
        }
        let mut map: HashMap<RecordId, Vec<RecordId>> = HashMap::new();
        for id in all {
            if id.prefix() != Prefix::Person {
                continue;
            }
            let root = canonical_on(&id, &self.parent, on);
            map.entry(root).or_default().push(id);
        }
        for members in map.values_mut() {
            members.sort();
            members.dedup();
        }
        self.members_by_root.borrow_mut().insert(on, map);
    }

    /// The cached group map (call [`Self::ensure_members`] first).
    pub(crate) fn groups(&self) -> Ref<'_, MembersByRoot> {
        self.members_by_root.borrow()
    }
}
