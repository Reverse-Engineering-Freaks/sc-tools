#!/bin/bash

if [ ! -S /run/pcscd/pcscd.comm ]; then
  # Cannot use host pcscd
  sudo pcscd -f --error &
fi

poetry install
