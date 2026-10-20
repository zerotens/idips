FROM golang:1.26-alpine AS build
ARG VERSION=dev
WORKDIR /src
RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X idips/internal/app.Version=${VERSION}" -o /out/idips ./cmd/idips

FROM golang:1.26-alpine AS wireproxy
RUN GOBIN=/out go install github.com/pufferffish/wireproxy/cmd/wireproxy@v1.0.10

FROM alpine:3.24 AS iptoasn
ARG IPTOASN_DB_URL=https://iptoasn.com/data/ip2asn-combined.tsv.gz
ARG IPTOASN_CACHE_BUST=dev
RUN apk add --no-cache ca-certificates curl \
    && mkdir -p /out \
    && echo "${IPTOASN_CACHE_BUST}" \
    && curl -fsSL --retry 3 --retry-delay 5 \
         "${IPTOASN_DB_URL}" \
         -o /out/ip2asn-combined.tsv.gz \
    && gzip -t /out/ip2asn-combined.tsv.gz

FROM alpine:3.24
RUN apk add --no-cache ca-certificates tzdata \
    && mkdir -p /data /usr/share/idips
COPY --from=build /out/idips /usr/local/bin/idips
COPY --from=wireproxy /out/wireproxy /usr/local/bin/wireproxy
COPY --from=iptoasn /out/ip2asn-combined.tsv.gz /usr/share/idips/ip2asn-combined.tsv.gz
ENV IDIPS_IPTOASN_DB=/usr/share/idips/ip2asn-combined.tsv.gz
VOLUME ["/data"]
EXPOSE 8080 1080 8081 53/udp 53/tcp 853 1082 8053
ENTRYPOINT ["/usr/local/bin/idips"]
CMD ["-data", "/data"]
# TPROXY and binding :53 require NET_ADMIN / NET_BIND_SERVICE. For a
# non-root deployment use high ports and map them, or add the capabilities.
