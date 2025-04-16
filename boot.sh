#!/bin/bash

set -euo pipefail

echo "=> This script is for fresh Ubuntu Server 24.04 installations only!"
echo -e "\nBegin installation (or abort with ctrl+c)..."

sudo apt-get update >/dev/null
sudo apt-get install -y git >/dev/null

echo "Installation starting..."
source ~/.local/share/ubunfast/install.sh
