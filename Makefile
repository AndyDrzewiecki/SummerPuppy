.PHONY: lint typecheck test test-integration install

install:
	pip install -e ".[dev]"

lint:
	ruff check src/ tests/
	ruff format --check src/ tests/

format:
	ruff check --fix src/ tests/
	ruff format src/ tests/

typecheck:
	mypy src/summer_puppy/

test:
	pytest tests/unit/ -v

test-integration:
	pytest tests/integration/ -v

test-all: lint typecheck test test-integration
