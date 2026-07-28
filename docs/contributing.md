# Contributing

## Development setup

```bash
git clone https://github.com/hitoshyamamoto/soapbar
cd soapbar
uv sync --group dev --group lint --group type

# Run tests
uv run pytest tests/ -v

# Lint
uv run ruff check src/ tests/

# Type check
uv run mypy src/
```

Run the example server (requires FastAPI + uvicorn):

```bash
pip install fastapi uvicorn
uvicorn examples.calculator_fastapi:app --reload --port 8000
```

Then fetch the WSDL: `curl http://localhost:8000/soap?wsdl`

## Contributing guide

See the full contributing guide at
[CONTRIBUTING.md](https://github.com/hitoshyamamoto/soapbar/blob/main/CONTRIBUTING.md)
on GitHub.
