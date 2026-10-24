FROM debian:bookworm-slim AS build

RUN apt-get update \
    && apt-get install --no-install-recommends --yes \
        build-essential pkg-config python3 \
        libssl-dev libsqlite3-dev libcurl4-openssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Makefile ./
COPY src/ ./src/
COPY scripts/embed_assets.py ./scripts/embed_assets.py
COPY scripts/embed_mail_templates.py ./scripts/embed_mail_templates.py
COPY web/ ./web/
RUN make -j2

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --no-install-recommends --yes \
        ca-certificates curl libssl3 libsqlite3-0 libcurl4 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 certificati \
    && useradd --uid 10001 --gid 10001 --no-create-home \
        --home-dir /data --shell /usr/sbin/nologin certificati \
    && install -d -o 10001 -g 10001 -m 0700 /data

COPY --from=build /src/certificati /usr/local/bin/certificati
USER 10001:10001
WORKDIR /data
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/certificati"]
CMD ["--db", "/data/certificati.db", "serve", "--bind", "0.0.0.0", "--port", "8080"]
