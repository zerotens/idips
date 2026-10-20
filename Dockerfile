FROM golang:1.25-alpine AS build
ARG VERSION=dev
WORKDIR /src
RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X idips/internal/app.Version=${VERSION}" -o /out/idips ./cmd/idips

FROM golang:1.25-alpine AS wireproxy
RUN GOBIN=/out go install github.com/pufferffish/wireproxy/cmd/wireproxy@v1.0.10

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata \
    && mkdir -p /data
COPY --from=build /out/idips /usr/local/bin/idips
COPY --from=wireproxy /out/wireproxy /usr/local/bin/wireproxy
VOLUME ["/data"]
EXPOSE 8080 1080 8081 53/udp 53/tcp 853 1082 8053
ENTRYPOINT ["/usr/local/bin/idips"]
CMD ["-data", "/data"]
# TPROXY and binding :53 require NET_ADMIN / NET_BIND_SERVICE. For a
# non-root deployment use high ports and map them, or add the capabilities.
