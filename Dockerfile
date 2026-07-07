FROM golang:1.26 AS builder

WORKDIR /src
COPY go.mod go.sum /src/
RUN go mod download

COPY main.go /src/
COPY ./scripts/build.sh /
COPY pkg /src/pkg

RUN go mod download    

RUN /build.sh

FROM alpine AS alpine
RUN apk update && apk add git ca-certificates tzdata

FROM scratch

ENV TZ=Pacific/Auckland

ENV RSP_LISTEN=":9999" \
    RSP_SENTINEL=":26379" \
    RSP_MASTER="mymaster" \
    RSP_RESOLVE_RETRIES="3" \
    RSP_SENTINEL_TLS="false" \
    RSP_SENTINEL_TLS_CA_FILE="" \
    RSP_SENTINEL_TLS_CERT_FILE="" \
    RSP_SENTINEL_TLS_KEY_FILE="" \
    RSP_SENTINEL_TLS_SERVER_NAME="" \
    RSP_SENTINEL_TLS_SKIP_VERIFY="false" \
    RSP_MASTER_TLS="false" \
    RSP_MASTER_TLS_CA_FILE="" \
    RSP_MASTER_TLS_CERT_FILE="" \
    RSP_MASTER_TLS_KEY_FILE="" \
    RSP_MASTER_TLS_SERVER_NAME="" \
    RSP_MASTER_TLS_SKIP_VERIFY="false" \
    RSP_LISTEN_TLS="false" \
    RSP_LISTEN_TLS_CERT_FILE="" \
    RSP_LISTEN_TLS_KEY_FILE="" \
    RSP_LISTEN_TLS_CLIENT_CA_FILE=""

USER 65535

COPY --from=alpine /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=alpine /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=alpine /tmp /tmp
COPY --from=builder /src/redis-sentinel-proxy /redis-sentinel-proxy

ENTRYPOINT [ "/redis-sentinel-proxy" ]
