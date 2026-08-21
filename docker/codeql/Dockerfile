# ==========================================
# Stage 1: Downloader & Verifier
# ==========================================
FROM ubuntu:24.04 AS downloader

ARG CODEQL_VERSION

RUN printf 'Acquire::Retries "5";\nAcquire::http::Timeout "30";\nAcquire::https::Timeout "30";\n' > /etc/apt/apt.conf.d/80retries && \
    apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    test -n "$CODEQL_VERSION"; \
    asset="codeql-bundle-linux64.tar.gz"; \
    release_url="https://github.com/github/codeql-action/releases/download/codeql-bundle-v${CODEQL_VERSION}"; \
    mkdir -p /tmp/codeql-download; \
    cd /tmp/codeql-download; \
    curl --fail --location --retry 10 --retry-all-errors --retry-delay 5 -C - --output "$asset" "$release_url/$asset"; \
    curl --fail --location --retry 10 --retry-all-errors --retry-delay 5 -C - --output "$asset.checksum.txt" "$release_url/$asset.checksum.txt"; \
    sha256sum -c "$asset.checksum.txt"; \
    tar -xzf "$asset" -C /opt; \
    rm -rf /tmp/codeql-download

# ==========================================
# Stage 2: CodeQL Analysis Runtime
# ==========================================
FROM ubuntu:24.04

RUN printf 'Acquire::Retries "5";\nAcquire::http::Timeout "30";\nAcquire::https::Timeout "30";\n' > /etc/apt/apt.conf.d/80retries && \
    apt-get update \
    && apt-get install --yes --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

COPY --from=downloader /opt/codeql /opt/codeql

RUN ln -s /opt/codeql/codeql /usr/local/bin/codeql \
    && chmod -R a+rX /opt/codeql
