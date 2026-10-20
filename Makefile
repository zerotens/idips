.PHONY: build test vet run docker geo

build:
	go build -o idips ./cmd/idips

test:
	go test ./...

vet:
	go vet ./...

run: build
	./idips -data ./data

docker:
	docker compose up -d --build

geo:
	curl -fsSL --retry 3 https://iptoasn.com/data/ip2asn-combined.tsv.gz -o ip2asn-combined.tsv.gz
	gzip -t ip2asn-combined.tsv.gz
