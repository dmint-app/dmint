.PHONY: help install test lint format typecheck check clean build

help:
	@echo "Dmint Unified Monorepo Targets:"
	@echo "  make install    - Install dmint in editable mode with dev extras"
	@echo "  make test       - Run all test suites across core, cli, mcp, dashboard, and skills"
	@echo "  make lint       - Run ruff linter across the entire repository"
	@echo "  make format     - Run ruff code formatter"
	@echo "  make typecheck  - Run mypy type checker across src/"
	@echo "  make check      - Run all lint, typecheck, and test checks"
	@echo "  make build      - Build wheel and sdist distribution packages"
	@echo "  make clean      - Clean build and test artifacts"

install:
	pip install -e ".[dev]"

test:
	pytest -v

lint:
	ruff check .

format:
	ruff format .

typecheck:
	mypy src/

check: lint typecheck test

build:
	python3 -m build

clean:
	rm -rf build/ dist/ src/*.egg-info/ *.egg-info/ .pytest_cache/ .mypy_cache/ .ruff_cache/ .coverage coverage.xml htmlcov/
