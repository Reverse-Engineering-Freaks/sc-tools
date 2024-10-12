FROM python:3.12

ARG UID=1000
ARG GID=1000

# Add Cloudflare repository
RUN --mount=type=cache,target=/var/lib/apt/,sharing=locked \
    --mount=type=cache,target=/var/cache/apt/,sharing=locked \
    mkdir -p --mode=0755 /usr/share/keyrings \
    && curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null \
    && echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared jammy main' | tee /etc/apt/sources.list.d/cloudflared.list

RUN --mount=type=cache,target=/var/lib/apt/,sharing=locked \
    --mount=type=cache,target=/var/cache/apt/,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    # For development
    sudo cloudflared opensc \
    # For build
    swig libpcsclite-dev \
    # For running
    libpcsclite1 pcscd

RUN groupadd -g $GID python \
    && useradd -m -s /bin/bash -u $UID -g $GID python \
    && echo 'python ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers \
    && sudo adduser python plugdev

USER python

# Install Poetry
RUN curl -sSL https://install.python-poetry.org | python3 -

# Create working directory
WORKDIR /home/python/workspace/
