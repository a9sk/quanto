.PHONY: build test test-docker lint clean

build:
	go build -o bin/quanto ./cmd/quanto

test:
	go test ./...

test-docker:
	./scripts/test-in-docker.sh

lint:
	go vet ./...
	gofmt -l .

clean:
	rm -rf bin/
