use serde_json::json;
use serde_json::to_string_pretty;

use anyhow::{Context, Result};
use chrono::prelude::*;
use clap::ArgMatches;
use std::path::Path;
use std::sync::Arc;

use crate::output::Output;
use crate::stream_archive::StreamArchive;

//-----------------------------------------

fn fmt_time(t: &chrono::DateTime<FixedOffset>) -> String {
    t.format("%b %d %y %H:%M").to_string()
}

pub fn run(matches: &ArgMatches, output: Arc<Output>) -> Result<()> {
    let archive_dir = Path::new(matches.get_one::<String>("ARCHIVE").unwrap()).canonicalize()?;

    // Open stream archive
    let stream_archive = StreamArchive::open_read(&archive_dir)?;
    let num_streams = stream_archive.stream_count();

    if output.json {
        let mut j_output = Vec::new();
        for stream_id in 0..num_streams {
            let cfg = stream_archive
                .read_config(stream_id as u32)
                .with_context(|| format!("Failed to read metadata for stream {}", stream_id))?;

            let time = chrono::DateTime::parse_from_rfc3339(&cfg.pack_time)
                .context("Failed to parse pack_time")?;

            j_output.push(json!({
                "stream_id": stream_id,
                "size": cfg.size,
                "time": time.to_rfc3339(),
                "source": cfg.name,
                "source_path": cfg.source_path
            }));
        }

        println!("{}", to_string_pretty(&j_output).unwrap());
    } else {
        // Calculate size width
        let mut width = 0;
        for stream_id in 0..num_streams {
            let cfg = stream_archive.read_config(stream_id as u32)?;
            let txt = format!("{}", cfg.size);
            width = width.max(txt.len());
        }

        // Output in order (already chronological)
        for stream_id in 0..num_streams {
            let cfg = stream_archive
                .read_config(stream_id as u32)
                .with_context(|| format!("Failed to read metadata for stream {}", stream_id))?;

            let time = chrono::DateTime::parse_from_rfc3339(&cfg.pack_time)
                .context("Failed to parse pack_time")?;

            output.report.to_stdout(&format!(
                "{:016x} {:width$} {} {}",
                stream_id,
                cfg.size,
                fmt_time(&time),
                cfg.name.unwrap_or_else(|| "unnamed".to_string())
            ));
        }
    }
    Ok(())
}

//-----------------------------------------
