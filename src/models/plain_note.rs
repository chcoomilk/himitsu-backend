use crate::{schema::plain_notes, ServerError};

use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};
use uuid::Uuid;

#[derive(Debug, Queryable, Serialize, Deserialize, Insertable)]
#[table_name = "plain_notes"]
pub struct PlainNote {
    pub id: String,
    pub title: String,
    pub content: String,
    pub is_encrypted: bool,
    pub created_at: SystemTime,
    pub expired_at: SystemTime,
}

#[derive(Debug, Deserialize)]
pub struct ReqPlainNote {
    pub title: String,
    pub content: String,
    pub lifetime_in_secs: Option<u64>,
    pub is_encrypted: bool,
}

impl ReqPlainNote {
    pub fn to_insertable(self) -> Result<PlainNote, ServerError> {
        let id = Uuid::new_v4().to_string();

        let time_now = SystemTime::now();
        let mut duration = Duration::from_secs(self.lifetime_in_secs.unwrap_or(2700));
        if duration.is_zero() || duration.gt(&Duration::from_secs(63115200)) { // max is 2 years
            duration = Duration::from_secs(2700);
        }
        let expiry_time = time_now + duration;

        Ok(PlainNote {
            id,
            title: self.title.clone(),
            content: self.content.clone(),
            is_encrypted: self.is_encrypted,
            created_at: time_now,
            expired_at: expiry_time,
        })
    }
}
