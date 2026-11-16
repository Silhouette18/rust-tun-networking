#!/bin/bash

cargo build || exit 1

sudo ./target/debug/rust-net-stack
