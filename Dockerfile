# syntax=docker/dockerfile:1

FROM python:3.13-bookworm

ARG UID=1000
ARG GID=1000

RUN --mount=type=cache,target=/var/lib/apt/,sharing=locked \
    --mount=type=cache,target=/var/cache/apt/,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    # For build
    curl swig libpcsclite-dev \
    # For running
    libpcsclite1 pcscd

RUN groupadd -g $GID python \
    && useradd -m -s /bin/bash -u $UID -g $GID python

USER python

# Install Poetry
RUN curl -sSL https://install.python-poetry.org | python -
ENV PATH=/home/python/.local/bin:$PATH

WORKDIR /app

COPY pyproject.toml poetry.lock README.md /app/
COPY sc_tools/ sc_tools/
COPY sc_explorer_cli/ sc_explorer_cli/

RUN poetry install

ENTRYPOINT [ "poetry", "run", "sc-explorer" ]
