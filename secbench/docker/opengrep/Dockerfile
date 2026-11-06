# Opengrep has no official OCI image: it ships cosign-signed, self-contained (Nuitka) release binaries.
# This builds a minimal, non-root image from the verified binary. Built and pinned by scripts/pin-images.sh.
#
# ARGs are supplied by pin-images.sh from images.src / this file's defaults.
# OPENGREP_SHA256 must match the value published on https://github.com/opengrep/opengrep/releases for the version.

ARG BASE_IMAGE=debian:bookworm-slim
FROM ${BASE_IMAGE} AS fetch
ARG OPENGREP_VERSION=v1.30.0
ARG OPENGREP_ASSET=opengrep_manylinux_x86
ARG OPENGREP_SHA256=35779bdd72e92129c8df2a77f0c55e8c08356801ea92591ef32108d6b28d564c
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL -o /opengrep "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/${OPENGREP_ASSET}" \
 && echo "${OPENGREP_SHA256}  /opengrep" | sha256sum -c - \
 && chmod 0755 /opengrep

FROM ${BASE_IMAGE}
ARG OPENGREP_VERSION
LABEL org.opencontainers.image.title="secbench/opengrep" \
      org.opencontainers.image.version="${OPENGREP_VERSION}" \
      org.opencontainers.image.source="https://github.com/opengrep/opengrep"
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --no-create-home opengrep
COPY --from=fetch /opengrep /usr/local/bin/opengrep
USER 10001
ENTRYPOINT ["/usr/local/bin/opengrep"]
