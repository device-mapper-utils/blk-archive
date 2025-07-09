#!/usr/bin/bash

echo "Kernel version"
uname -a

echo "Distro info"
lsb_release -a

START_DIR=$(pwd)

echo "PWD $START_DIR"

# Name of modules we need for ublk_drv (if we later want to use it!)
K_PKG_NAME="linux-modules-extra-$(uname -r)"

# Install all the dependencies
export DEBIAN_FRONTEND="noninteractive"
apt-get update -y || exit 1

apt-get install git gcc clang-tools libdevmapper-dev pkg-config mount python3 python3-toml python3-pudb python3-numpy "$K_PKG_NAME"  -y || exit 1

if [ ! -e "$HOME/.cargo/env" ]; then
    # install rust via rustup as packages are too old on ubuntu
    curl https://sh.rustup.rs -sSf | sh -s -- -y || exit 1
fi

# Get rust tools in path
source "$HOME/.cargo/env" || exit 1

echo "Building release version of blk-archive"
cargo build --release || exit 1

PATH=$PATH:$(pwd)/target/release
export path

if [ ! -d dmtest-python ]; then
    git clone https://github.com/jthornber/dmtest-python.git || exit 1
fi


# Create the block devices and loop back devices if needed
if [ ! -e /block1.img ]; then
    echo "Creating sparse block images"
    truncate -s 1T /block1.img || exit 1
    truncate -s 1T /block2.img || exit 1
    truncate -s 1T /block3.img || exit 1

    echo "Setting up loop back devices ..."
    loop1=$(losetup -f --show /block1.img)
    loop2=$(losetup -f --show /block2.img)
    loop3=$(losetup -f --show /block3.img)

    cd "$START_DIR" || exit 1
    # setup the configuration file for dmtest-python
    cd dmtest-python || exit 1

    echo "metadata_dev = '$loop1'" > config.toml
    echo "data_dev = '$loop2'" >> config.toml
    echo "disable_by_id_check = true" >> config.toml
fi


# Run the cargo based tests
cd "$START_DIR" || exit 1

echo "Running the cargo tests ..."
cargo test -- --test-threads=1 || exit 1

# Unable to run rolling linux test as we don't have enough disk space in the CI VMs.
# Run the dmtest-python tests for blk-archive
echo "Running the dmtest combinations..."
cd dmtest-python || exit 1

export DMTEST_RESULT_SET=unit-test
./dmtest health || exit 1
./dmtest run blk-archive/unit/combinations
rc=$?
if [ $rc -ne 0 ]; then
    ./dmtest log /blk-archive/unit/combinations
    exit 1
fi
exit 0
