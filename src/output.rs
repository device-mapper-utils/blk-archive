use chrono::prelude::*;
use std::sync::Arc;
use thinp::report::*;

// A structure to encapsulate related output options and output formattting.
pub struct Output {
    pub start_time: DateTime<Utc>,
    pub report: Arc<Report>,
    pub json: bool,
}
