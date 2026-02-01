.PHONY: install test coverage mutate mutate-explicit counterexamples mutation-report validate all clean run

## Install dependencies
install:
	pip install -r requirements.txt

## Run the test suite
test:
	python -m pytest tests/ -v

## Run tests with branch-level coverage
coverage:
	python -m pytest tests/ --cov --cov-branch --cov-report=term-missing --cov-config=pyproject.toml

## Run mutation testing (AST-based, from mutations.yaml)
mutate:
	python -m validation.run_mutations

## Run mutation testing with explicit (programmatic) mutations
mutate-explicit:
	python -m validation.run_mutations --explicit

## Run the counterexample search (external validation)
counterexamples:
	python -m validation.counterexample_search

## Analyse surviving mutants (legacy mutmut wrapper)
mutation-report:
	python -m validation.mutation_analysis

## Full validation pipeline: tests + coverage + counterexample search
validate: test coverage counterexamples
	@echo ""
	@echo "=== Full validation pipeline complete ==="

## Everything: validate then mutation-test
all: validate mutate
	@echo ""
	@echo "=== Full pipeline (validate + mutation testing) complete ==="

## Run the API server
run:
	uvicorn app:app --reload --host 0.0.0.0 --port 8000

## Remove caches
clean:
	rm -rf __pycache__ .pytest_cache .hypothesis .mutmut-cache .coverage htmlcov
	find . -name '*.pyc' -delete
	find . -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
