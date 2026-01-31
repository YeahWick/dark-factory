.PHONY: install test coverage mutate counterexamples mutation-report validate all clean

## Install dependencies
install:
	pip install -r requirements.txt

## Run the test suite
test:
	python -m pytest tests/ -v

## Run tests with branch-level coverage
coverage:
	python -m pytest tests/ --cov=calculator --cov-branch --cov-report=term-missing

## Run mutation testing (mutmut)
mutate:
	mutmut run --paths-to-mutate=calculator.py --tests-dir=tests/
	mutmut results

## Run the counterexample search (external validation)
counterexamples:
	python -m validation.counterexample_search

## Analyse surviving mutants
mutation-report:
	python -m validation.mutation_analysis

## Full validation pipeline: tests + coverage + counterexample search
validate: test coverage counterexamples
	@echo ""
	@echo "=== Full validation pipeline complete ==="

## Everything: validate then mutation-test
all: validate mutate mutation-report

## Remove caches
clean:
	rm -rf __pycache__ .pytest_cache .hypothesis .mutmut-cache
	find . -name '*.pyc' -delete
	find . -name '__pycache__' -type d -exec rm -rf {} +
