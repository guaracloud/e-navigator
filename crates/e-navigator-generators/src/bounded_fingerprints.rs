use std::collections::{BTreeSet, VecDeque};

#[derive(Debug)]
pub(crate) struct BoundedFingerprints<T> {
    members: BTreeSet<T>,
    insertion_order: VecDeque<T>,
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
    T: Clone + Ord,
{
    pub(crate) fn insert_if_new(&mut self, fingerprint: T, capacity: usize) -> bool {
        if self.members.contains(&fingerprint) {
            return false;
        }

        let capacity = capacity.max(1);
        while self.members.len() >= capacity {
            let Some(oldest) = self.insertion_order.pop_front() else {
                break;
            };
            self.members.remove(&oldest);
        }

        self.members.insert(fingerprint.clone());
        self.insertion_order.push_back(fingerprint);
        true
    }
}
