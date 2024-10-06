#!/usr/bin/env bash

set -e

# Check if we can execute msmtp at all
../src/msmtp --version > /dev/null
../src/msmtp --help    > /dev/null
