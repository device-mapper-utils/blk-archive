use anyhow::Result;
use clap::ArgMatches;
use std::path::Path;
use std::sync::Arc;

use crate::output::Output;
use crate::slab::SlabFile;
use crate::stream::*;

//-----------------------------------------

pub fn run(matches: &ArgMatches, output: Arc<Output>) -> Result<()> {
    let archive_dir = Path::new(matches.get_one::<String>("ARCHIVE").unwrap()).canonicalize()?;
    let stream = matches.get_one::<String>("STREAM").unwrap();

    let mut d = Dumper::<SlabFile>::new(&archive_dir, stream)?;
    d.dump(output)
}

//-----------------------------------------
