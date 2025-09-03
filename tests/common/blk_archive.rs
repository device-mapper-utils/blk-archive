use anyhow::Result;
use duct::unix::HandleExt;
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

use crate::args;
use crate::common::process::*;
use crate::common::targets::*;

//-----------------------------------------

pub struct BlkArchive {
    archive: PathBuf,
    server: Option<duct::Handle>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct PackStats {
    pub written: u64,
    pub mapped_size: u64,
    pub fill_size: u64,
    pub stream_written: u64,
    pub size: u64,
}
#[derive(Deserialize, Serialize, Debug)]
pub struct PackResponse {
    pub stream_id: String,
    pub stats: PackStats,
}

impl BlkArchive {
    pub fn new(archive: &Path) -> Result<Self> {
        Self::new_with(archive, 4096, true)
    }

    pub fn new_with(archive: &Path, block_size: usize, data_compression: bool) -> Result<Self> {
        let bs_str = block_size.to_string();
        let compression = if data_compression { "y" } else { "n" };

        run_ok(create_cmd(args![
            "-a",
            archive,
            "--block-size",
            &bs_str,
            "--data-compression",
            &compression
        ]))?;

        Ok(Self {
            archive: archive.to_path_buf(),
            server: None,
        })
    }

    pub fn service_start(&mut self) -> Result<()> {
        let c = server_cmd(args!["-a", &self.archive]);
        self.server = Some(run_spawn(c)?);
        Ok(())
    }

    pub fn service_end(&mut self) -> Result<ExitStatus> {
        if let Some(h) = self.server.take() {
            h.send_signal(2)?;
            let status = h.wait()?.status;
            return Ok(status);
        }
        Ok(ExitStatus::default())
    }

    pub fn from_path(archive: &Path) -> Result<Self> {
        Ok(Self {
            archive: archive.to_path_buf(),
            server: None,
        })
    }

    pub fn data_size(&self) -> std::io::Result<u64> {
        fn file_size(path: &PathBuf) -> std::io::Result<u64> {
            fs::metadata(path).map(|meta| meta.len())
        }

        let base_path = self.archive.clone();
        let data_size = file_size(&base_path.join("data/data"))?;
        Ok(data_size)
    }

    pub fn pack_cmd(&self, input: &Path) -> Command {
        pack_cmd(args!["-a", &self.archive, &input, "-j"])
    }

    pub fn send_cmd(&self, input: &Path) -> Command {
        send_cmd(args!["--server", "localhost:9876", &input, "-j"])
    }

    pub fn receive_cmd(&self, stream_id: &str, output: &Path) -> Command {
        recv_cmd(args![
            "--server",
            "localhost:9876",
            "-s",
            stream_id,
            output,
            "--create",
            "-j"
        ])
    }

    pub fn pack(&self, input: &Path) -> Result<PackResponse> {
        let stdout = run_ok(self.pack_cmd(input))?;
        let response: PackResponse = serde_json::from_str(&stdout)?;
        Ok(response)
    }

    pub fn send(&self, input: &Path) -> Result<PackResponse> {
        let stdout = run_ok(self.send_cmd(input))?;
        let response: PackResponse = serde_json::from_str(&stdout)?;
        Ok(response)
    }

    pub fn receive(&self, stream_id: &str, input: &Path) -> Result<()> {
        let _stdout = run_ok(self.receive_cmd(stream_id, input))?;
        Ok(())
    }

    pub fn unpack_cmd(&self, stream: &str, output: &Path, create: bool) -> Command {
        let mut args = args!["-a", &self.archive, "-s", stream, &output].to_vec();
        if create {
            args.push(std::ffi::OsStr::new("--create"));
        }
        unpack_cmd(args)
    }

    pub fn unpack(&self, stream: &str, output: &Path, create: bool) -> Result<()> {
        run_ok(self.unpack_cmd(stream, output, create))?;
        Ok(())
    }

    pub fn verify_cmd(&self, input: &Path, stream: &str) -> Command {
        verify_cmd(args!["-a", &self.archive, "-s", stream, input])
    }

    pub fn verify(&self, input: &Path, stream: &str) -> Result<()> {
        run_ok(self.verify_cmd(input, stream))?;
        Ok(())
    }
}

impl Drop for BlkArchive {
    fn drop(&mut self) {
        self.service_end().unwrap();
    }
}

pub fn same_bytes(file1: &Path, file2: &Path) -> Result<bool, std::io::Error> {
    let f1 = File::open(file1)?;
    let f2 = File::open(file2)?;

    // Check if file sizes are different
    if f1.metadata()?.len() != f2.metadata()?.len() {
        return Ok(false);
    }

    // Use buf readers since they are much faster
    let bf1 = BufReader::new(f1);
    let bf2 = BufReader::new(f2);

    // Do a byte to byte comparison of the two files
    for (b1, b2) in bf1.bytes().zip(bf2.bytes()) {
        if b1.unwrap() != b2.unwrap() {
            return Ok(false);
        }
    }

    return Ok(true);
}

//-----------------------------------------
