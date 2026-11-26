# syntax=docker/dockerfile:1
#
# Drop-in replacement for nginx:1.25-bookworm, built from OUR .deb packages
# (build/Dockerfile -> out/, run by `make test`). Mirrors the official Dockerfile
# (nginxinc/docker-nginx@9abe4ae, mainline/debian) step by step; the only
# intended difference is where the packages come from:
#   official: apt repo nginx.org          ours: out/*.deb built from source
#
# Base pinned by digest (debian:bookworm-slim, Debian 12.15, 2026-11-24).
ARG BASE=debian:bookworm-slim@sha256:e67eeead736ff7bbe258ef088bff683635c561b1fcfefad0806c1df4ab49ce0e
FROM ${BASE}

# Same metadata as the original, so anything reading these keeps working.
LABEL maintainer="NGINX Docker Maintainers <docker-maint@nginx.com>"
ENV NGINX_VERSION=1.25.5
ENV NJS_VERSION=0.8.4
ENV NJS_RELEASE=3~bookworm
ENV PKG_RELEASE=1~bookworm

# The .debs are bind-mounted for this step only, so they never become a layer.
RUN --mount=type=bind,source=out,target=/tmp/debs \
    set -x \
    && groupadd --system --gid 101 nginx \
    && useradd --system --gid nginx --no-create-home --home /nonexistent --comment "nginx user" --shell /bin/false --uid 101 nginx \
    && arch="$(dpkg --print-architecture)" \
    && apt-get update \
    # the original installs "gnupg1 ca-certificates" to verify nginx.org's key and
    # only removes gnupg1 afterwards, so ca-certificates is part of the image
    && apt-get install --no-install-recommends --no-install-suggests -y ca-certificates \
    # zlib1g 1.4 (CVE-2026-27171) replaces Debian's 1.2.13; nginx with both
    # backports (CVE-2025-23419, CVE-2026-42945) + the same four module packages;
    # same extras as the original.
    && apt-get install --no-install-recommends --no-install-suggests -y \
        /tmp/debs/zlib1g_*_"$arch".deb \
        /tmp/debs/nginx_*_"$arch".deb \
        /tmp/debs/nginx-module-xslt_*_"$arch".deb \
        /tmp/debs/nginx-module-geoip_*_"$arch".deb \
        /tmp/debs/nginx-module-image-filter_*_"$arch".deb \
        /tmp/debs/nginx-module-njs_*_"$arch".deb \
        gettext-base \
        curl \
    && apt-get remove --purge --auto-remove -y && rm -rf /var/lib/apt/lists/* \
    # forward request and error logs to docker log collector
    && ln -sf /dev/stdout /var/log/nginx/access.log \
    && ln -sf /dev/stderr /var/log/nginx/error.log \
    && mkdir /docker-entrypoint.d

COPY docker-entrypoint/docker-entrypoint.sh /
COPY docker-entrypoint/10-listen-on-ipv6-by-default.sh /docker-entrypoint.d
COPY docker-entrypoint/15-local-resolvers.envsh /docker-entrypoint.d
COPY docker-entrypoint/20-envsubst-on-templates.sh /docker-entrypoint.d
COPY docker-entrypoint/30-tune-worker-processes.sh /docker-entrypoint.d

ENTRYPOINT ["/docker-entrypoint.sh"]

EXPOSE 80

STOPSIGNAL SIGQUIT

CMD ["nginx", "-g", "daemon off;"]
