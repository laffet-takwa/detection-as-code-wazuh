# SentinelForge Makefile
# Convenience targets for common development tasks

.PHONY: help install test lint typecheck validate convert report clean

# Default target
help:
	@echo "SentinelForge - Detection-as-Code Engineering Platform for Wazuh"
	@echo ""
	@echo "Available targets:"
	@echo "  install      Install dependencies (core + dev)"
	@echo "  install-core Install core dependencies only"
	@echo "  test         Run full test suite (validate + convert + fixtures)"
	@echo "  validate     Validate all Sigma rules"
	@echo "  convert      Convert rules to Wazuh XML"
	@echo "  fixtures     Run synthetic fixture tests"
	@echo "  wazuh-test   Run Wazuh integration tests (requires wazuh-logtest)"
	@echo "  report       Generate JSON and Markdown reports"
	@echo "  coverage     Compute and display coverage metrics"
	@echo "  lint         Run Ruff linting and formatting"
	@echo "  typecheck    Run mypy type checking"
	@echo "  clean        Remove generated artifacts"
	@echo "  pre-commit   Run pre-commit hooks on all files"
	@echo ""

# Installation
install:
	pip install -r requirements.txt -r requirements-dev.txt
	pre-commit install

install-core:
	pip install -r requirements.txt

# Validation & Conversion
validate:
	python scripts/validate_rules.py

convert:
	python scripts/convert_rules.py

# Testing
fixtures:
	python scripts/run_tests.py

wazuh-test:
	SENTINELFORGE_WAZUH_LOGTEST=/var/ossec/bin/wazuh-logtest python scripts/run_tests.py --wazuh

# Full test suite
test: validate convert fixtures report

# Reporting
report:
	python scripts/generate_report.py

coverage:
	sentinelforge coverage

# Code Quality
lint:
	ruff check src/ tests/ scripts/
	ruff format --check src/ tests/ scripts/

lint-fix:
	ruff check --fix src/ tests/ scripts/
	ruff format src/ tests/ scripts/

typecheck:
	mypy src/sentinelforge

pre-commit:
	pre-commit run --all-files

# Cleanup
clean:
	rm -rf wazuh/rules/*.xml
	rm -rf reports/*
	rm -rf .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

# Development
run-validate:
	sentinelforge validate

run-convert:
	sentinelforge convert --backend wazuh

run-test:
	sentinelforge test --fixtures tests/fixtures

run-report:
	sentinelforge report

run-coverage:
	sentinelforge coverage

# CI simulation
ci: lint typecheck validate convert fixtures report
	@echo "CI pipeline completed successfully"

# Docker (if needed)
docker-build:
	docker build -t sentinelforge:latest .

docker-test:
	docker run --rm sentinelforge:latest make test