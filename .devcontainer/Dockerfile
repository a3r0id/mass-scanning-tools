FROM mcr.microsoft.com/devcontainers/python:3.13-bookworm

ENV DEBIAN_FRONTEND=noninteractive

# Base image ships a stale Yarn apt source that breaks apt-get update
RUN rm -f /etc/apt/sources.list.d/yarn.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends zmap whois \
    && rm -rf /var/lib/apt/lists/*

# Allow vscode user to run zmap without full root when capabilities allow
RUN setcap cap_net_raw+ep /usr/sbin/zmap || true
