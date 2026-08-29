use std::{
    collections::{BTreeSet, VecDeque},
    sync::Arc,
};

#[derive(Debug)]
pub(crate) struct BoundedFingerprints<T> {
    members: BTreeSet<Arc<T>>,
    insertion_order: VecDeque<Arc<T>>,
}

impl<T> Default for BoundedFingerprints<T> {
    fn default() -> Self {
        Self {
            members: BTreeSet::new(),
            insertion_order: VecDeque::new(),
        }
    }
}

impl<T> BoundedFingerprints<T>
where
    T: Ord,
{
    pub(crate) fn insert_if_new(&mut self, fingerprint: T, capacity: usize) -> bool {
        let fingerprint = Arc::new(fingerprint);
        if self.members.contains(fingerprint.as_ref()) {
            return false;
        }

        let capacity = capacity.max(1);
        while self.members.len() >= capacity {
            let Some(oldest) = self.insertion_order.pop_front() else {
                break;
            };
            self.members.remove(oldest.as_ref());
        }

        self.members.insert(Arc::clone(&fingerprint));
        self.insertion_order.push_back(fingerprint);
        true
    }
}
