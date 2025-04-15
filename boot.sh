#!/bin/bash

set -euo pipefail

banner=' ███████████   █████████    █████████  ███████████ ███████████    █████████   ███████████
░░███░░░░░░█  ███░░░░░███  ███░░░░░███░█░░░███░░░█░░███░░░░░███  ███░░░░░███ ░█░░░███░░░█
 ░███   █ ░  ░███    ░███ ░███    ░░░ ░   ░███  ░  ░███    ░███ ░███    ░███ ░   ░███  ░ 
 ░███████    ░███████████ ░░█████████     ░███     ░██████████  ░███████████     ░███    
 ░███░░░█    ░███░░░░░███  ░░░░░░░░███    ░███     ░███░░░░░███ ░███░░░░░███     ░███    
 ░███  ░     ░███    ░███  ███    ░███    ░███     ░███    ░███ ░███    ░███     ░███    
 █████       █████   █████░░█████████     █████    ███████████  █████   █████    █████   
░░░░░       ░░░░░   ░░░░░  ░░░░░░░░░     ░░░░░    ░░░░░░░░░░░  ░░░░░   ░░░░░    ░░░░░    
                                                                              
'

echo -e "$banner"
echo "=> This script is for fresh Ubuntu Server 24.04 installations only!"
echo -e "\nBegin installation (or abort with ctrl+c)..."

sudo apt-get update >/dev/null
sudo apt-get install -y git >/dev/null

echo "Cloning Ubinkaze..."
rm -rf ~/.local/share/ubunfast
git clone https://github.com/romanzini/UbunFast.git ~/.local/share/ubunfast >/dev/null

UBUNFAST_REF=${UBUNFAST_REF:-"stable"}

if [[ $UBUNFAST_REF != "main" ]]; then
  cd ~/.local/share/ubunfast
  git fetch origin "$UBUNFAST_REF" && git checkout "$UBUNFAST_REF"
  cd - >/dev/null
fi

echo "Installation starting..."
source ~/.local/share/ubunfast/install.sh