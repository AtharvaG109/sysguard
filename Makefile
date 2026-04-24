.PHONY: fmt check test doctor ci

fmt:
	cargo fmt

check:
	cargo check

test:
	cargo test

doctor:
	./scripts/doctor.sh

ci: fmt check test
