FROM python:3.13-slim-bookworm

ARG SQLMAP_VERSION
ARG SQLMAP_SHA256

RUN set -eux; \
    test -n "$SQLMAP_VERSION"; \
    test -n "$SQLMAP_SHA256"; \
    printf 'sqlmap==%s --hash=sha256:%s\n' "$SQLMAP_VERSION" "$SQLMAP_SHA256" > /tmp/requirements.txt; \
    pip install --no-cache-dir --no-deps --no-binary sqlmap --require-hashes -r /tmp/requirements.txt; \
    rm -f /tmp/requirements.txt

ENTRYPOINT ["sqlmap"]
