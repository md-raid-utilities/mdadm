#!/usr/bin/bash

sudo make clean
sudo make -j$(nproc)
sudo make install
sudo mdadm -Ss
sudo ./test setup
sudo ./test --skip-broken --no-error --disable-integrity --disable-multipath --disable-linear --keep-going
sudo ./test cleanup