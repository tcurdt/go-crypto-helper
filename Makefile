include .project

MAKEFLAGS += --silent

.PHONY:
all: test

.PHONY: test
test:
	go test -v ./...

.PHONY: release
release: all
	git tag -a $(VERSION) -m "releasing $(VERSION)"
	git push --tags origin master
