.PHONY: build test vet run docker

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
