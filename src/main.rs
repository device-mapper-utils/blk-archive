use anyhow::{anyhow, Result};
use clap::ArgMatches;
use std::process::exit;
use std::sync::Arc;

use blk_archive::create;
use blk_archive::dump_stream;
use blk_archive::list;
use blk_archive::output::Output;
use blk_archive::pack;
use blk_archive::recovery::{confirm_data_loss_warning, flight_check};
use blk_archive::unpack;

use blk_archive::utils::mk_output;

//-----------------------

fn with_output<F>(matches: &clap::ArgMatches, f: F) -> Result<()>
where
    F: FnOnce(Arc<Output>) -> Result<()>,
{
    let json = matches.get_flag("JSON");
    let output = mk_output(json);
    f(output)
}

fn repairing(subcommand_name: &str, sub_matches: &ArgMatches) -> bool {
    subcommand_name == "verify" && sub_matches.get_flag("REPAIR")
}

fn handle_repair_mode(archive_path: &str, is_repairing: bool, force: bool) -> Result<()> {
    match (flight_check(archive_path), is_repairing) {
        (Ok(_), true) | (Err(_), true) => {
            // Either way, repairing requires confirmation (unless --force is used)
            if !force && !confirm_data_loss_warning() {
                return Err(anyhow!("User selected to NOT confirm data loss, exiting!"));
            }
            Ok(())
        }
        (Err(e), false) => {
            eprintln!("Archive is in an inconsistent state, try verify --all --repair");
            Err(e)
        }
        (Ok(_), false) => Ok(()),
    }
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
            if subcommand_name != "create" && std::env::var("BLK_ARCHIVE_DEVEL_SKIP_DATA").is_err()
            {
                let is_repairing = repairing(subcommand_name, sub_matches);
                let force = if subcommand_name == "verify" {
                    sub_matches.get_flag("FORCE")
                } else {
                    false
                };
                handle_repair_mode(archive_path, is_repairing, force)?;
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
