use anyhow::Result;
use std::process::exit;
use std::sync::Arc;
use thinp::report::*;

use blk_stash::archive::flight_check;
use blk_stash::create;
use blk_stash::dump_stream;
use blk_stash::list;
use blk_stash::output::Output;
use blk_stash::pack;
use blk_stash::unpack;

//-----------------------

fn mk_report(json: bool) -> Arc<Report> {
    if json {
        Arc::new(mk_quiet_report())
    } else if atty::is(atty::Stream::Stdout) {
        Arc::new(mk_progress_bar_report())
    } else {
        Arc::new(mk_simple_report())
    }
}

fn mk_output(json: bool) -> Arc<Output> {
    let report = mk_report(json);
    report.set_level(LogLevel::Info);

    Arc::new(Output { report, json })
}

fn with_output<F>(matches: &clap::ArgMatches, f: F) -> Result<()>
where
    F: FnOnce(Arc<Output>) -> Result<()>,
{
    let json = matches.get_flag("JSON");
    let output = mk_output(json);
    f(output)
}

fn main_() -> Result<()> {
    let cli = cli::build_cli();
    let matches = cli.get_matches();

    // Check for and apply recovery checkpoint before processing any command
    // This handles interrupted operations by truncating files to last known-good state
    // and cleaning up indexs, cuckoo filters etc.
    if let Some((subcommand_name, sub_matches)) = matches.subcommand() {
        if let Some(archive_path) = sub_matches.get_one::<String>("ARCHIVE") {
            // Do a preflight check before proceeding to ensure the archive is in a hopefully
            // good state (skip for create command as archive doesn't exist yet)
            if subcommand_name != "create" && std::env::var("BLK_STASH_DEVEL_SKIP_DATA").is_err() {
                flight_check(archive_path)?;
            }
        }
    }

    match matches.subcommand() {
        Some(("create", sub_matches)) => {
            let output = mk_output(false);
            create::run(sub_matches, output.report.clone())?;
        }
        Some(("pack", sub)) => {
            with_output(sub, |out| pack::run(sub, out))?;
        }
        Some(("unpack", sub)) => {
            with_output(sub, |out| unpack::run_unpack(sub, out))?;
        }
        Some(("verify", sub)) => {
            with_output(sub, |out| unpack::run_verify(sub, out))?;
        }
        Some(("list", sub)) => {
            with_output(sub, |out| list::run(sub, out))?;
        }
        Some(("dump-stream", sub)) => {
            with_output(sub, |out| dump_stream::run(sub, out))?;
        }
        _ => unreachable!("Exhausted list of subcommands and subcommand_required prevents 'None'"),
    }

    Ok(())
}

fn main() {
    let code = match main_() {
        Ok(()) => 0,
        Err(e) => {
            // FIXME: write to report
            eprintln!("{e:?}");
            // We don't print out the error since -q may be set
            1
        }
    };

    exit(code)
}

//-----------------------
