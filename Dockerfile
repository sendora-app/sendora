# Base images are pinned by digest (the tag stays for readability); Dependabot
# proposes updates. Build and runtime use Debian 13 "trixie": Debian 12
# "bookworm" left regular security support on 2026-07-11 (LTS only since).

# The web build output is platform independent: always build it on the build
# platform, also when cross-building locally (releases build natively per platform).
FROM --platform=$BUILDPLATFORM node:26-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5 AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# Build the exact engine required by Sendora, not Debian's system SQLite.
# golang:1.27-trixie is go1.27.4, which fixes GO-2026-6859 (net/http
# MaxBytesReader header race; go1.26 line was fixed in 1.26.11).
FROM golang:1.27-trixie@sha256:430985542100b871e108ccc00e8dcc5eef08ca14ee5825e98ebf563d8ffec4ee AS sqlcipher
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates curl libssl-dev pkg-config tcl \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir /tmp/sqlcipher-download /tmp/sqlcipher-source /tmp/sqlcipher-build \
    && curl -fL --retry 3 https://github.com/sqlcipher/sqlcipher/archive/refs/tags/v4.20.0.tar.gz \
       -o /tmp/sqlcipher-download/source.tar.gz \
    && printf '%s  %s\n' '38705f51b61ac0636a5fd064f9a77fafabc7227b2aa2513f1b14c8bb1102affc' \
       /tmp/sqlcipher-download/source.tar.gz | sha256sum -c - \
    && tar -xzf /tmp/sqlcipher-download/source.tar.gz --strip-components=1 -C /tmp/sqlcipher-source
WORKDIR /tmp/sqlcipher-build
# Upstream's current makefile names its library sqlite3. Give this isolated
# engine its own library/header/pkg-config names to prevent mixed-engine links.
ENV SQLCIPHER_CFLAGS="-O2 -DSQLITE_HAS_CODEC -DSQLITE_TEMP_STORE=2 -DSQLITE_THREADSAFE=1 -DSQLITE_EXTRA_INIT=sqlcipher_extra_init -DSQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown"
RUN /tmp/sqlcipher-source/configure --disable-tcl --with-tempstore=yes \
      CFLAGS="$SQLCIPHER_CFLAGS" LDFLAGS="-lcrypto" \
    && make -j"$(nproc)" sqlite3.c shell.c \
    && cc $SQLCIPHER_CFLAGS -fPIC -shared -Wl,-soname,libsqlcipher.so.0 \
       -o libsqlcipher.so.0 sqlite3.c -lcrypto -lm -ldl -lpthread \
    && install -d /usr/local/lib/pkgconfig /usr/local/include/sqlcipher \
    && install -m 0755 libsqlcipher.so.0 /usr/local/lib/ \
    && ln -s libsqlcipher.so.0 /usr/local/lib/libsqlcipher.so \
    && install -m 0644 sqlite3.h sqlite3ext.h /usr/local/include/sqlcipher/ \
    && printf '%s\n' 'prefix=/usr/local' 'libdir=${prefix}/lib' 'includedir=${prefix}/include/sqlcipher' \
       'Name: SQLCipher' 'Description: SQLCipher encrypted database engine' 'Version: 4.20.0' \
       'Libs: -L${libdir} -lsqlcipher' 'Libs.private: -lcrypto -lm -ldl -lpthread' \
       'Cflags: -I${includedir}' > /usr/local/lib/pkgconfig/sqlcipher.pc \
    && ldconfig \
    && cc $SQLCIPHER_CFLAGS -I. -o /usr/local/bin/sqlcipher shell.c \
       -L/usr/local/lib -lsqlcipher -lcrypto -lm -ldl -lpthread \
    && install -D -m 0644 /tmp/sqlcipher-source/LICENSE.md /usr/share/licenses/sqlcipher/LICENSE.md

FROM sqlcipher AS build
WORKDIR /src
ARG VERSION=0.3.0-dev
COPY go.mod go.sum ./
# go.mod replaces mattn/go-sqlite3 with this SQLCipher linkage fork.
COPY third_party/ ./third_party/
RUN go mod download
COPY . .
COPY --from=web /web/dist ./web/dist
# One binary: the offline database tool is "sendora db ..." and, through the
# sendora-db link installed below, "sendora-db ...".
# The footer's "Source code" link (AGPL-3.0 section 13) points at the release
# tag v${VERSION}; forks set SOURCE_URL (or SENDORA_SOURCE_URL at run time) to
# their own repository ({version} and {revision} are filled in).
ARG REVISION=unknown
ARG SOURCE_URL=
RUN CGO_ENABLED=1 go build -trimpath -ldflags "-s -w -X main.version=${VERSION} -X main.revision=${REVISION} -X main.sourceURL=${SOURCE_URL}" -o /sendora .
# The engine is exactly 4.20.0 and the program links it, not a system SQLite.
# (The runtime image has no sqlcipher shell; Sendora checks the version again
# at every start and logs it.)
RUN sqlcipher :memory: 'PRAGMA cipher_version;' | grep '^4\.20\.0 ' \
    && ldd /sendora | grep -q 'libsqlcipher\.so\.0 => /usr/local/lib/libsqlcipher\.so\.0' \
    && ! ldd /sendora | grep -q 'libsqlite3'

FROM debian:trixie-slim@sha256:8aa5a7bf5a1955bddbe7d74fcdd0b91ab30e74362a8b73af672b0481b35b44a0
ARG VERSION=0.3.0-dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="Sendora" \
      org.opencontainers.image.description="Self-hosted file sharing with an encrypted SQLCipher database" \
      org.opencontainers.image.source="https://github.com/sendora-app/sendora" \
      org.opencontainers.image.url="https://github.com/sendora-app/sendora" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
# libssl3t64 is trixie's name for the OpenSSL 3 runtime library (libcrypto).
# No setuid/setgid programs: nothing in the container can gain privileges.
# sendora-db is a link to /sendora (the same program started under another
# name), so "docker exec <container> sendora-db ..." keeps working.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata libssl3t64 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 app && useradd --uid 10001 --gid 10001 --no-create-home app \
    && mkdir /data && chown app:app /data \
    && ln -s /sendora /usr/local/bin/sendora-db && ln -s /sendora /sendora-db \
    && find / -xdev -type f -perm /6000 -exec chmod a-s {} + \
    && test -z "$(find / -xdev -type f -perm /6000)"
COPY --from=sqlcipher /usr/local/lib/libsqlcipher.so* /usr/local/lib/
COPY --from=sqlcipher /usr/share/licenses/sqlcipher/LICENSE.md /usr/share/licenses/sqlcipher/LICENSE.md
RUN ldconfig
USER 10001:10001
ENV DATA_DIR=/data PORT=8080 HOST=0.0.0.0 SENDORA_DB_INITIALIZE=false
VOLUME /data
EXPOSE 8080
# "sendora healthcheck" asks http://127.0.0.1:$PORT/api/health (2 s timeout).
# The start period covers a first start or an integrity check of a large database.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 CMD ["/sendora", "healthcheck"]
COPY LICENSE NOTICE LICENSE-ADDITIONAL-TERMS.md TRADEMARKS.md /usr/share/licenses/sendora/
COPY --from=build /sendora /sendora
ENTRYPOINT ["/sendora"]
