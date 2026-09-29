//! One in-flight operation per key: the first caller does the work, everyone arriving while
//! it runs waits for its result.
//!
//! Used to deduplicate upstream queries. RFC 5452 section 5: an attacker's chance of forging
//! an answer "rises linearly with the number of outstanding queries" for the same name and
//! type. With only one request in flight, an attacker has exactly one response to guess.

use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::sync::Mutex;

use tokio::sync::broadcast;

/// Work currently in progress: key → the channel to notify when it finishes.
#[derive(Debug)]
pub struct Coalescer<K, V> {
    running: Mutex<HashMap<K, broadcast::Sender<V>>>,
}

impl<K, V> Default for Coalescer<K, V> {
    fn default() -> Self {
        Self {
            running: Mutex::new(HashMap::new()),
        }
    }
}

impl<K, V> Coalescer<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    /// If someone is already working on `key`, waits for their result; otherwise runs `work`
    /// and notifies everyone waiting when it finishes.
    ///
    /// What breaks if you change it: when the leader is cancelled mid-flight, waiters see the
    /// channel close — at that point they must do the work themselves rather than keep
    /// waiting, or one cancelled query would stall every later query for the same name.
    pub async fn run<F, Fut>(&self, key: &K, work: F) -> V
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = V>,
    {
        let waiting = {
            let Ok(mut running) = self.running.lock() else {
                // A poisoned lock means no deduplication; do the work. One extra upstream
                // query beats a stalled one.
                return work().await;
            };
            match running.get(key) {
                Some(sender) => Some(sender.subscribe()),
                None => {
                    let (sender, _) = broadcast::channel(1);
                    running.insert(key.clone(), sender);
                    None
                }
            }
        };

        if let Some(mut receiver) = waiting {
            return match receiver.recv().await {
                Ok(value) => value,
                Err(_) => work().await,
            };
        }

        // Removal and notification happen under the same lock: anyone arriving afterwards
        // cannot see the old channel, and anyone already subscribed is guaranteed the result.
        // The guard makes sure removal happens on cancellation too.
        let guard = Leader {
            coalescer: self,
            key,
        };
        let value = work().await;
        guard.finish(&value);
        value
    }
}

struct Leader<'a, K: Eq + Hash, V> {
    coalescer: &'a Coalescer<K, V>,
    key: &'a K,
}

impl<K: Eq + Hash, V: Clone> Leader<'_, K, V> {
    fn finish(self, value: &V) {
        if let Ok(mut running) = self.coalescer.running.lock()
            && let Some(sender) = running.remove(self.key)
        {
            let _ = sender.send(value.clone());
        }
        std::mem::forget(self);
    }
}

impl<K: Eq + Hash, V> Drop for Leader<'_, K, V> {
    /// Dropped without reaching `finish` means the leader was cancelled. Remove the channel;
    /// waiters see it close and do the work themselves.
    fn drop(&mut self) {
        if let Ok(mut running) = self.coalescer.running.lock() {
            running.remove(self.key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    /// Should change: five simultaneous calls for one key do the work once, and all five get
    /// the same result.
    #[tokio::test]
    async fn one_key_does_the_work_once() {
        let c = Arc::new(Coalescer::<String, u32>::default());
        let done = Arc::new(AtomicU32::new(0));
        let tasks: Vec<_> = (0..5)
            .map(|_| {
                let (c, done) = (Arc::clone(&c), Arc::clone(&done));
                tokio::spawn(async move {
                    c.run(&"example.com A".to_string(), || async {
                        done.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        42
                    })
                    .await
                })
            })
            .collect();
        for t in tasks {
            assert_eq!(t.await.unwrap(), 42);
        }
        assert_eq!(done.load(Ordering::SeqCst), 1);
        assert!(
            c.running.lock().unwrap().is_empty(),
            "finished entries must be removed, or the map grows without bound"
        );
    }

    /// Should not change: different keys run independently, and a key that has finished runs
    /// again next time (this is not a cache).
    #[tokio::test]
    async fn different_keys_run_separately_and_nothing_is_retained() {
        let c = Coalescer::<&str, u32>::default();
        let done = AtomicU32::new(0);
        let work = || async {
            done.fetch_add(1, Ordering::SeqCst);
            1
        };
        c.run(&"a", work).await;
        c.run(&"b", work).await;
        c.run(&"a", work).await;
        assert_eq!(done.load(Ordering::SeqCst), 3);
    }

    /// Should change: when the leader is cancelled, the waiter does not stall — it does the
    /// work itself.
    #[tokio::test]
    async fn a_cancelled_leader_leaves_the_waiter_to_do_the_work() {
        let c = Arc::new(Coalescer::<&str, u32>::default());
        let leader = {
            let c = Arc::clone(&c);
            tokio::spawn(async move {
                c.run(&"k", || async {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    1
                })
                .await
            })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        let follower = {
            let c = Arc::clone(&c);
            tokio::spawn(async move { c.run(&"k", || async { 2 }).await })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        leader.abort();
        let got = tokio::time::timeout(Duration::from_secs(2), follower)
            .await
            .expect("the waiter must not stall")
            .unwrap();
        assert_eq!(got, 2);
        assert!(c.running.lock().unwrap().is_empty());
    }
}
