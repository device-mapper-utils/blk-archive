use anyhow::Context;
use chrono::Local;
use clap::Command;
use glob::glob;
use regex::Regex;
use std::{
    env, fs,
    path::{Path, PathBuf},
};

fn man_base_dir() -> PathBuf {
    // Allow this to be overridden with a specific directory
    if let Some(p) = env::var_os("MAN_OUT_DIR") {
        let mut path = PathBuf::from(p);
        path.push("generated-man");
        return path;
    }

    let out_dir = env::var_os("OUT_DIR").expect("OUT_DIR not set (build.rs must run under Cargo)");

    // Kind of hackish, but options are limited
    let mut target_dir = PathBuf::from(out_dir)
        .ancestors()
        .nth(4) // Walk back up to "target"
        .map(Path::to_path_buf)
        .expect("Unexpected OUT_DIR layout; expected target/*/build/<crate>-<hash>/out");

    target_dir.push("generated-man");
    target_dir
}

fn set_versions_recursively(mut cmd: Command, ver: &'static str) -> Command {
    // Version missing on subcommand man pages, fix-up
    if cmd.get_version().is_none() && cmd.get_long_version().is_none() {
        cmd = cmd.version(ver);
    }
    // collect names first to avoid borrow issues
    let subs: Vec<String> = cmd
        .get_subcommands()
        .map(|s| s.get_name().to_string())
        .collect();
    for name in subs {
        cmd = cmd.mut_subcommand(&name, |sub| {
            if sub.get_version().is_none() && sub.get_long_version().is_none() {
                sub.version(ver)
            } else {
                sub
            }
        });
    }
    cmd
}

fn gen_man() {
    use clap_mangen::Man;
    use std::fs::File;
    use std::path::Path;

    let binary = "blk-stash";
    let ver = env!("CARGO_PKG_VERSION");

    let root_cmd = cli::build_cli();

    let mut root_cmd = set_versions_recursively(root_cmd, ver);
    let out_dir = man_base_dir();

    fs::create_dir_all(&out_dir).unwrap();

    let base = Path::new(&out_dir);

    // Generate main page
    let main_path = base.join("blk-stash.1");
    let mut file = File::create(&main_path).unwrap();

    let mut root_man = Man::new(root_cmd.clone());

    let date = Local::now().format("%Y-%m-%d").to_string();
    root_man = root_man.date(date.clone());
    root_man.render(&mut file).unwrap();

    // Generate subcommand man pages
    for sub in root_cmd.get_subcommands_mut() {
        let sub_name = sub.get_name().replace('_', "-");
        let full_bin = format!("{binary} {sub_name}");
        let full_man = format!("{binary}-{sub_name}.1");

        let file_path = base.join(full_man.clone());
        let mut file = File::create(file_path).unwrap();

        let full_man_upper = full_bin.to_uppercase();

        let mut man = Man::new(sub.clone().bin_name(full_bin).display_name(&full_man_upper));
        man = man.date(date.clone());

        man.render(&mut file).unwrap();
    }
}

fn rename_options_sections() {
    // Work around for: https://github.com/clap-rs/clap/issues/5844
    // although https://github.com/clap-rs/clap/pull/5854 seems indicate it addresses this?
    //
    // Doing this for know, before spending more time looking for a better solution, or correction.
    let dir = man_base_dir();
    let pattern = dir.join("*.1");
    let pattern = pattern
        .to_str()
        .context("non-UTF8 path not supported for glob")
        .unwrap();

    // Anchor to whole lines inside the file (multi-line mode).
    // Matches:
    //   .SH OPTIONS
    //   .SH   "OPTIONS"
    //   .SH\tOPTIONS
    let re = Regex::new(r#"(?m)^\.[ \t]*SH[ \t]+"?OPTIONS"?[ \t]*$"#).unwrap();

    let mut changed = 0;
    for entry in glob(pattern).context("bad glob pattern").unwrap() {
        let path = entry.unwrap();
        let text = fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))
            .unwrap();

        if !re.is_match(&text) {
            continue;
        }

        let new_text = re.replace_all(&text, r#".SH "GLOBAL OPTIONS""#);
        if new_text != text {
            fs::write(&path, new_text.as_bytes())
                .with_context(|| format!("writing {}", path.display()))
                .unwrap();
            changed += 1;
        }
    }

    println!(
        "cargo:warning=Rewrote OPTIONS section in {changed} man page(s), is there a better way?"
    );
}

fn main() {
    gen_man();
    rename_options_sections();
}
