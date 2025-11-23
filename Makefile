.PHONY: .venv build publish clean

venv: .venv
.venv:
	uv venv --allow-existing

build:
	uv build

publish: build
	uv publish
	uv run --with pg-scram-sha256 --no-project -- python -c "import pg_scram_sha256"

clean:
	rm -rf .ruff_cache .venv dist *.egg-info uv.lock
	find . -type d ! -name . -name __pycache__ -exec rm -r {} +
