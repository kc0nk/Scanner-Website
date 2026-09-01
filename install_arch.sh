#!/usr/bin/env bash
set -euo pipefail
sudo pacman -S --needed python python-pip chromium
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m playwright install chromium
printf '\nInstalled. Run: ./run.sh\n'
