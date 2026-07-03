use e_navigator_signals::ContainerContext;
use std::collections::{BTreeMap, VecDeque, btree_map::Entry};

#[derive(Debug)]
pub(super) struct BoundedContainerCache<K> {
    entries: BTreeMap<K, ContainerContext>,
    order: VecDeque<K>,
}

impl<K> Default for BoundedContainerCache<K> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            order: VecDeque::new(),
        }
    }
}

impl<K> BoundedContainerCache<K>
where
    K: Clone + Ord,
{
    pub(super) fn get(&self, key: &K) -> Option<ContainerContext> {
        self.entries.get(key).cloned()
    }

    pub(super) fn insert(&mut self, key: K, value: ContainerContext, max_entries: usize) {
        if let Entry::Occupied(mut entry) = self.entries.entry(key.clone()) {
            entry.insert(value);
            return;
        }

        let max_entries = max_entries.max(1);
        while self.entries.len() >= max_entries {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
                continue;
            }
            if let Some(first) = self.entries.keys().next().cloned() {
                self.entries.remove(&first);
            }
            break;
        }

        self.order.push_back(key.clone());
        self.entries.insert(key, value);
    }

    pub(super) fn remove(&mut self, key: &K) {
        self.entries.remove(key);
    }

    pub(super) fn replace_entries(&mut self, entries: BTreeMap<K, ContainerContext>) {
        self.order = entries.keys().cloned().collect();
        self.entries = entries;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_container_cache_evicts_oldest_inserted_entry() {
        let mut cache = BoundedContainerCache::default();

        cache.insert(20_u32, container("twenty"), 2);
        cache.insert(10_u32, container("ten"), 2);
        cache.insert(5_u32, container("five"), 2);

        assert!(cache.get(&20).is_none());
        assert!(cache.get(&10).is_some());
        assert!(cache.get(&5).is_some());
    }

    #[test]
    fn bounded_container_cache_updates_existing_without_reordering() {
        let mut cache = BoundedContainerCache::default();

        cache.insert(20_u32, container("first"), 2);
        cache.insert(10_u32, container("ten"), 2);
        cache.insert(20_u32, container("updated"), 2);
        cache.insert(5_u32, container("five"), 2);

        assert!(cache.get(&20).is_none());
        assert!(cache.get(&10).is_some());
        assert!(cache.get(&5).is_some());
    }

    fn container(id: &str) -> ContainerContext {
        ContainerContext {
            container_id: id.to_string(),
            runtime: Some("containerd".to_string()),
        }
    }
}
