FROM mcr.microsoft.com/devcontainers/typescript-node:4-24-trixie

RUN apt update && export DEBIAN_FRONTEND=noninteractive \
    && apt install -y --no-install-recommends cmake python3 xz-utils bzip2 python-is-python3 make

COPY install-emscripten.sh .
