use clap::{command, Arg, ArgAction, ArgGroup, Command, ValueHint};

use std::env;

pub fn build_cli() -> clap::Command {
    let archive_arg = Arg::new("ARCHIVE")
        .help("Specify archive directory")
        .long("archive")
        .short('a')
        .value_name("ARCHIVE")
        .num_args(1)
        .env("BLK_STASH_DIR")
        .required(true)
        .help_heading("Required Options");

    let stream_arg = Arg::new("STREAM")
        .help("Specify an archived stream to unpack")
        .required(true)
        .long("stream")
        .short('s')
        .value_name("STREAM")
        .num_args(1)
        .help_heading("Required Options");

    let json: Arg = Arg::new("JSON")
        .help("Output JSON")
        .required(false)
        .long("json")
        .short('j')
        .value_name("JSON")
        .action(ArgAction::SetTrue)
        .global(false)
        .help_heading("Optional Options");

    let data_cache_size: Arg = Arg::new("DATA_CACHE_SIZE_MEG")
        .help("Specify how much memory is used for caching data")
        .required(false)
        .long("data-cache-size-meg")
        .value_name("DATA_CACHE_SIZE_MEG")
        .num_args(1)
        .help_heading("Optional Options");

    command!("blk-stash")
        .version(env!("CARGO_PKG_VERSION"))
        .propagate_version(true)
        .bin_name("blk-stash")
        .disable_help_flag(true)
        .disable_version_flag(true)
        .subcommand_required(true)
        .arg_required_else_help(true)
        .about("A tool for archiving block devices and files. \
                Data is de-duplicated, optionally compressed and stored in a \
                directory in the filesystem.")
        .arg(
            Arg::new("help")
                .long("help")
                .short('h')
                .action(ArgAction::Help)
                .help("Print help information")
                .help_heading("Global Options")
                .global(true),
        )
        .arg(
            Arg::new("version")
                .long("version")
                .short('V')
                .action(ArgAction::Version)
                .help("Print version information")
                .help_heading("Global Options")
                .global(true),
        )
        .subcommand(
            Command::new("create")
                .about("creates a new archive")
                // We don't want to take a default from the env var, so can't use
                // archive_arg
                .arg(
                    Arg::new("ARCHIVE")
                        .help("Specify archive directory")
                        .required(true)
                        .long("archive")
                        .short('a')
                        .value_name("ARCHIVE")
                        .num_args(1)
                        .help_heading("Required Options"),
                )
                .arg(
                    Arg::new("BLOCK_SIZE")
                        .help("Specify the average block size used when deduplicating data")
                        .required(false)
                        .long("block-size")
                        .value_name("BLOCK_SIZE")
                        .num_args(1)
                        .help_heading("Optional Options"),
                )
                .arg(
                    Arg::new("HASH_CACHE_SIZE_MEG")
                        .help("Specify how much memory is used for caching hash entries")
                        .required(false)
                        .long("hash-cache-size-meg")
                        .value_name("HASH_CACHE_SIZE_MEG")
                        .num_args(1)
                        .help_heading("Optional Options"),
                )
                .arg(data_cache_size.clone())
                .arg(
                    Arg::new("DATA_COMPRESSION")
                        .long("data-compression")
                        .value_name("y|n")
                        .help("Enable or disable slab data compression")
                        .value_parser(["y", "n"]) // Restrict values
                        .default_value("y")
                        .action(ArgAction::Set)
                        .help_heading("Optional Options"),
                ),
        )
        .subcommand(
            Command::new("pack")
                .about("packs a stream into the archive")
                .arg(
                    Arg::new("INPUT")
                        .help("Specify one or more devices or files to archive (only one INPUT allowed with --delta-stream/--delta-device)")
                        .required(true)
                        .value_name("INPUT")
                        .num_args(1..)
                        .help_heading("Required Options"),
                )
                .arg(archive_arg.clone())
                .arg(
                    Arg::new("DELTA_STREAM")
                        .help(
                            "Specify the stream that contains an older version of this thin device (requires --delta-device, only single INPUT allowed)",
                        )
                        .required(false)
                        .long("delta-stream")
                        .value_name("DELTA_STREAM")
                        .num_args(1)
                        .requires("DELTA_DEVICE")
                        .help_heading("Optional Options"),
                )
                .arg(
                    Arg::new("DELTA_DEVICE")
                        .help(
                            "Specify the device that contains an older version of this thin device (requires --delta-stream, only single INPUT allowed)",
                        )
                        .required(false)
                        .long("delta-device")
                        .value_name("DELTA_DEVICE")
                        .num_args(1)
                        .requires("DELTA_STREAM")
                        .help_heading("Optional Options"),
                )
                .arg(data_cache_size.clone())
                .arg(json.clone())
                .arg(
                    Arg::new("SYNC_POINT_SECS")
                        .help("Number of seconds before creating a sync point in the archive. Smaller \
                              values allow you to restart a pack with less data needing to be added to \
                              archive at the cost of slower pack times")
                        .required(false)
                        .long("sync-point-secs")
                        .value_name("SYNC_POINT_SECS")
                        .num_args(1)
                        .default_value("15")
                        .value_parser(clap::value_parser!(u64).range(1..)),
                ),
        )
        .subcommand(
            Command::new("unpack")
                .about("unpacks a stream from the archive")
                .arg(
                    Arg::new("OUTPUT")
                        .help("Specify a device or file as the destination")
                        .required(true)
                        .value_name("OUTPUT")
                        .index(1)
                        .help_heading("Required Options"),
                )
                .arg(
                    Arg::new("CREATE")
                        .help("Create a new file rather than unpack to an existing file.")
                        .long("create")
                        .action(clap::ArgAction::SetTrue)
                        .help_heading("Optional Options"),
                )
                .arg(data_cache_size.clone())
                .arg(archive_arg.clone())
                .arg(stream_arg.clone())
                .arg(json.clone()),
        )
        .subcommand(
                Command::new("verify")
        .about("verifies stream in the archive against the original file/dev or an internal blake3 hash")
        .arg(
            Arg::new("INPUT")
                .help("Device or file containing the correct version of the data")
                .value_name("INPUT")
                .value_hint(ValueHint::FilePath)
                .num_args(1), // not required; enforced via group below
        )
        .arg(
            Arg::new("internal")
                .long("internal")
                .help("Verify using the archive's internally stored blake3 hash (no INPUT needed)")
                .action(ArgAction::SetTrue),
        )
        .group(
            ArgGroup::new("verify-source")
                .args(["INPUT", "internal"])
                .required(true), // must choose exactly one
        )
        .arg(data_cache_size.clone())
        .arg(archive_arg.clone())
        .arg(stream_arg.clone())
        .arg(json.clone()),
)
        .subcommand(
            Command::new("dump-stream")
                .about("dumps stream instructions (development tool)")
                .arg(archive_arg.clone())
                .arg(stream_arg.clone())
                .arg(json.clone()),
        )
        .subcommand(
            Command::new("list")
                .about("lists the streams in the archive")
                .arg(archive_arg.clone())
                .arg(json.clone()),
        )
}
