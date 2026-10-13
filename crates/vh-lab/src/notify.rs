use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotifyRec {
    pub at_ms: u64,
    pub title: String,
    pub body: String,
}
