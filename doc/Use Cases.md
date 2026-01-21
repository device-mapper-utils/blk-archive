# blk-stash Use Cases

## Create a new archive

**Scenario:**
You want to initialize a new archive directory where blk-stash will store deduplicated and compressed data.

**Goal:**
Set up a root directory for an archive with an appropriate block size.

**Solution with blk-stash:**
Use the `create` subcommand with the `-a` switch. The directory should not exist beforehand; it will be created by blk-stash. Optionally, specify a block size (rounded to nearest power of two). Smaller block sizes improve deduplication but increase metadata overhead.

**Example commands:**
```bash
blk-stash create -a my-archive
blk-stash create -a my-archive --block-size 8092
```

An archive is composed of a directory with multiple sub directories and files.

```bash
tree my-archive/
my-archive/
├── data
│   ├── data
│   ├── data.offsets
│   ├── hashes
│   └── hashes.offsets
├── dm-archive.yaml
├── indexes
│   ├── seen
│   └── seen.offsets
└── streams
```

## Add a large file to an archive

**Scenario:**
You want to store a large file efficiently, reducing storage via deduplication and compression.

**Goal:**
Deduplicate and compress file data and pack it into an archive.

**Solution with blk-stash:**
Use the `pack` subcommand. Statistics will be shown to understand compression and deduplication effectiveness along with some other data (subject to change before release 1.0).

**Example command:**

```bash
blk-stash pack -a my-archive /tmp/test_file.bin
Packing /tmp/test_file.bin ... [                                        ] Remaining 0s
elapsed          : 1.033
stream id        : ba83f083d6628555
file size        : 1G
mapped size      : 1G
total read       : 1G
fills size       : 482.74M
duplicate data   : 446.88M
data written     : 94.38M
stream written   : 541
ratio            : 10.85
speed            : 991.29M/s
```

## Add a non-live block device to an archive

**Scenario:**
You want to archive the contents of a block device that is currently unused (not mounted).

**Goal:**
Safely archive a block device by reading its content directly.

**Solution with blk-stash:**
Use `pack` just as you would do with a file.

**Example command:**
```bash
blk-stash pack -a my-archive /dev/ublkb1
Packing /dev/ublkb1 ... [                                        ] Remaining 0s
elapsed          : 795.734
stream id        : 2b3985ef2ec276eb
file size        : 931.32G
mapped size      : 931.32G
total read       : 931.32G
fills size       : 891.73G
duplicate data   : 34.56G
data written     : 5.03G
stream written   : 2.94K
ratio            : 185.07
speed            : 1.17G/s
```

## Use LVM snapshot to archive a live block device

**Scenario:**
You need to archive a block device that is currently in use.

**Goal:**
Capture a consistent snapshot of the live device and archive it without unmounting.

**Solution with blk-stash:**
Use LVM to create a snapshot and archive the snapshot device.  The snapshot needs to be inactive
before adding it to the archive.

**Example commands:**
```bash
lvcreate -s --name snap1 --size 512M my-vg/my-thick-volume
blk-stash pack -a my-archive /dev/my-vg/snap1
Packing /dev/dm-8 ... [                                        ] Remaining 0s
elapsed          : 1.099
stream id        : 689a120cd415c0f7
file size        : 1G
mapped size      : 1G
total read       : 1G
fills size       : 1021.78M
duplicate data   : 0
data written     : 2.22M
stream written   : 78
ratio            : 461.36
speed            : 931.76M/s
```

## Add an inactive thin device to an archive

**Scenario:**
You are archiving a thinly provisioned device, e.g., from a thin LVM pool that is inactive.

**Goal:**
Efficiently archive only provisioned regions of a thin device.

**Solution with blk-stash:**
blk-stash detects thin devices and reads only mapped areas, saving time and space.

**Example commands:**
```bash
blk-stash pack -a my-archive /dev/my-vg/my-thin-volume
elapsed          : 0.067
stream id        : 3b9beb432a83a142
file size        : 1G
mapped size      : 64.69M
total read       : 64.69M
fills size       : 64.31M
duplicate data   : 0
data written     : 390.77K
stream written   : 111
ratio            : 169.46
speed            : 965.49M/s
```

## Use a thin snapshot to archive a live thin device

**Scenario:**
You want to archive a thin device that is actively used.

**Goal:**
Create a snapshot of the device and archive its state with minimal new data written.

**Solution with blk-stash:**
Use `lvcreate` to snapshot the device. Then archive the snapshot using `pack`.

**Example commands:**
```bash
lvcreate -s --name base-line my-vg/my-thin-volume
  Logical volume "base-line" created.

lvchange -ay -Ky my-vg/base-line

blk-stash pack -a my-archive /dev/my-vg/base-line
elapsed          : 0.079
stream id        : b53d6b40b692f645
file size        : 1G
mapped size      : 64.69M
total read       : 64.69M
fills size       : 62.28M
duplicate data   : 390.77K
data written     : 2.03M
stream written   : 123
ratio            : 31.89
speed            : 818.83M/s

lvremove -y /dev/my-vg/base-line
  Logical volume "base-line" successfully removed.
```

## Add a thin snapshot of a device already in the archive

**Scenario:**
You have archived a previous version of a device and now want to archive a newer snapshot efficiently.

**Goal:**
Use delta encoding to avoid storing duplicated data from a previously archived snapshot.

**Solution with blk-stash:**
Use `pack` and provide the previous stream ID and device path to enable delta mode.

**Example commands:**
```bash
blk-stash pack -a my-archive /dev/my-vg/delta-ss-second  --delta-stream 3d1444b0baa4a1e1 --delta-device /dev/my-vg/delta-ss-initial
elapsed          : 0.101
stream id        : 7cd3daf2d6062d40
file size        : 1G
mapped size      : 64.69M
total read       : 98.06M
fills size       : 97.71M
duplicate data   : 160K
data written     : 202.60K
stream written   : 151
ratio            : 326.71
speed            : 970.92M/s
```

## List streams in an archive

**Scenario:**
You want to see which files or devices have been archived.

**Goal:**
List all the streams stored in the archive along with metadata.

**Solution with blk-stash:**
Use the `list` subcommand.

**Example command:**
```bash
blk-stash list -a my-archive
689a120cd415c0f7 1073741824 Jul 29 25 14:18 snap1
3b9beb432a83a142 1073741824 Jul 29 25 14:22 my-thin-volume
b53d6b40b692f645 1073741824 Jul 29 25 14:45 base-line
3d1444b0baa4a1e1 1073741824 Jul 29 25 14:50 delta-ss-initial
7cd3daf2d6062d40 1073741824 Jul 29 25 14:56 delta-ss-second
```

## Restore to a file

**Scenario:**
You want to recover a previously archived file to a new destination.

**Goal:**
Restore data from a stream using its unique ID.

**Solution with blk-stash:**
Use the `unpack` command with the `--create` option.

**Example command:**
```bash
blk-stash unpack -a my-archive --stream af5449cc3a2f95ab --create /tmp/my-file
speed            : 449.84M/s
```

## Restore to a block device

**Scenario:**
You want to restore a stream to an existing block device.

**Goal:**
Recreate a previously archived block device.

**Solution with blk-stash:**
Use `unpack` without `--create`. Destination must already exist and match original size.

**Example command:**
```bash
blk-stash unpack -a my-archive --stream 7cd3daf2d6062d40 /dev/my-vg/restore-volume
speed            : 1.72G/s
```

## Restore to a thinly provisioned block device

**Scenario:**
You want to restore data to a thin device, reusing storage via copy-on-write when possible.

**Goal:**
Maximize data sharing during restore to a thin device.

**Solution with blk-stash:**
blk-stash checks for duplicate regions and avoids unnecessary writes to preserve sharing.

**Example command:**
```bash
blk-stash unpack -a my-archive --stream 7cd3daf2d6062d40 /dev/my-vg/restore-thin-volume
speed            : 12.35G/s
```

## Integrate blk-stash with other tools

**Scenario:**
You want to integrate blk-stash into other tools or work flows

**Goal:**
Enable automated, non-interactive usage.

**Solution with blk-stash:**
blk-stash supports JSON output to facilitate integration with other tools.
Use the `-j` option to enable JSON-formatted output.

**Example command:**
```bash
blk-stash -j pack -a my-archive /usr/bin/ls
```

**Example JSON output:**
```json
{
  "stats": {
    "data_written": 145312,
    "fill_size": 0,
    "mapped_size": 145312
  },
  "stream_id": "2c7c9e40ebd7b26e"
}

```

## Deleting a stream from an archive

**Scenario:**
You want to remove specific streams from an archive to save space.

**Goal:**
Delete unused streams from the archive.

**Solution with blk-stash:**
Not supported. Workaround is to create a new archive and repack selected streams using original
files or block devices.

**Example command:**
_Not available. Feature not supported._

## Migrating streams to a new archive

**Scenario:**
You want to move selected streams from one archive to another for cleanup or rotation.

**Goal:**
Support rotation, pruning, and long-term storage by moving streams.

**Solution with blk-stash:**
Planned feature. Not yet implemented.

**Example command:**
_Not available. Feature not implemented._
