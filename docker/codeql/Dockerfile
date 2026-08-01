FROM ubuntu:24.04

ARG CODEQL_VERSION

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    test -n "$CODEQL_VERSION"; \
    asset="codeql-bundle-linux64.tar.gz"; \
    release_url="https://github.com/github/codeql-action/releases/download/codeql-bundle-v${CODEQL_VERSION}"; \
    mkdir -p /tmp/codeql-download; \
    cd /tmp/codeql-download; \
    curl --fail --location --retry 3 --output "$asset" "$release_url/$asset"; \
    curl --fail --location --retry 3 --output "$asset.checksum.txt" "$release_url/$asset.checksum.txt"; \
    sha256sum -c "$asset.checksum.txt"; \
    tar -xzf "$asset" -C /opt; \
    ln -s /opt/codeql/codeql /usr/local/bin/codeql; \
    rm -rf /tmp/codeql-download

RUN apt-get update \
    && apt-get install --yes --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

RUN chmod -R a+rX /opt/codeql
