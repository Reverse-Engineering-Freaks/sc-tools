#!/bin/bash

if [ ! -S /run/pcscd/pcscd.comm ]; then
  # Cannot use host pcscd
  sudo pcscd -f --error &
fi

export POETRY_VIRTUALENVS_IN_PROJECT=1
poetry install
