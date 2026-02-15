use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FifoQueue<T>(VecDeque<T>);

impl<T> FifoQueue<T> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self(VecDeque::with_capacity(capacity))
    }

    pub fn push(&mut self, item: T) {
        self.0.push_back(item);
    }

    pub fn pop_next(&mut self) -> Option<T> {
        self.0.pop_front()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
