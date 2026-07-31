.PHONY: check-env test

check-env:
# Checks if VIRTUAL_ENV is empty or undefined
ifeq ($(VIRTUAL_ENV),)
	$(error Virtual environment is NOT active. Please activate it first)
else
	@echo "Virtual environment detected at: $(VIRTUAL_ENV)"
endif


all:
	cargo build


.PHONY: test

test:
	cargo test

.PHONY: develop

develop: check-env
	maturin develop -m parser/Cargo.toml

.PHONY: clean

clean:
	cargo clean
