.PHONY: install test coverage validate clean run

install:
	pip install -r requirements.txt

test:
	python -m pytest tests/ -v

coverage:
	python -m pytest tests/ --cov --cov-report=term-missing --cov-config=pyproject.toml

validate: test coverage

run:
	uvicorn app:app --reload --host 0.0.0.0 --port 8000

clean:
	rm -rf __pycache__ .pytest_cache .coverage htmlcov
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
