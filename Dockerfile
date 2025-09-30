# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

ARG DEBIAN_TAG=trixie-slim

FROM debian:${DEBIAN_TAG} AS debsbom

ARG SOURCE_DATE_EPOCH

ARG DEBIAN_TAG=trixie-slim

ARG TARGETPLATFORM
ARG DEBIAN_FRONTEND=noninteractive
ENV LANG=en_US.utf8
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean && \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-packages.conf && \
    if echo "${DEBIAN_TAG}" | grep -q "[0-9]"; then \
        sed -i -e '/^URIs:/d' -e 's|^# http://snapshot\.|URIs: http://snapshot.|' \
            /etc/apt/sources.list.d/debian.sources; \
        echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/use-snapshot.conf; \
        echo 'Acquire::Retries "10";' >> /etc/apt/apt.conf.d/use-snapshot.conf; \
        echo 'Acquire::Retries::Delay::Maximum "600";' >> /etc/apt/apt.conf.d/use-snapshot.conf; \
    fi && \
    apt-get update && \
    apt-get install -y locales && \
    localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8 && \
    apt-get install --no-install-recommends -y \
        python3-apt python3-cyclonedx-lib python3-debian python3-packageurl \
        python3-beartype python3-click python3-license-expression python3-ply \
        python3-rdflib python3-semantic-version python3-uritools python3-xmltodict \
        python3-yaml python3-zstandard python3-requests && \
    rm -rf /var/log/* /tmp/* /var/tmp/* /var/cache/ldconfig/aux-cache

# install debsbom in a reproducible way
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    --mount=type=bind,target=/debsbom,rw \
    apt-get update && \
    apt-get install --no-install-recommends -y \
        python3-pip python3-setuptools && \
    pip3 --proxy=$https_proxy install \
        --no-deps \
        --no-build-isolation \
        --break-system-packages \
        --root-user-action=ignore \
        spdx-tools==0.8.3 \
        /debsbom && \
    rm -rf $(pip3 cache dir) && \
    apt-get autopurge -y python3-pip python3-setuptools && \
    rm -rf /root/.cache /var/log/* /tmp/* /var/tmp/* /var/cache/ldconfig/aux-cache && \
    debsbom --version

WORKDIR /var/lib/debsbom
