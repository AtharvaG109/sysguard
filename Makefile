.PHONY: fmt check test ci

fmt:
	cargo fmt

check:
	cargo check

test:
	cargo test

ci: fmt check test
