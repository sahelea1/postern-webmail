# syntax=docker/dockerfile:1
#
# Three stages: build the web client, compile it into one static binary,
# ship only that binary. The final image has no shell, no package manager
# and no libraries: /postern and an empty /data.

ARG NODE_VERSION=22
ARG RUST_VERSION=1.97

FROM node:${NODE_VERSION}-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY web/build.mjs web/tsconfig.json ./
COPY web/static ./static
COPY web/src ./src
RUN node build.mjs

FROM rust:${RUST_VERSION}-alpine AS build
RUN apk add --no-cache build-base
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY web/admin ./web/admin
COPY --from=web /src/web/dist ./web/dist
RUN cargo build --release --locked \
 && mkdir -p /out/data \
 && cp target/release/postern /out/postern

FROM scratch
COPY --from=build /out/postern /postern
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
ENV POSTERN_DATA_DIR=/data \
    POSTERN_LISTEN=0.0.0.0:8080 \
    POSTERN_ADMIN_LISTEN=0.0.0.0:8081
EXPOSE 8080 8081
VOLUME /data
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD ["/postern", "healthcheck"]
ENTRYPOINT ["/postern"]
CMD ["run"]
