.PHONY: build test vet clean

build:
	go build -o bin/singgalang .

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -rf bin
