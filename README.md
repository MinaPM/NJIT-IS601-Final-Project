# NJIT IS601 Final Project

FastAPI application for calculations, authentication, and profile management with a PostgreSQL backend.

## Run The Application

### With Docker Compose

1. Start the full stack:

	```bash
	docker compose up --build
	```

2. Open the app in your browser at `http://localhost:8000`.

3. Optional services:
	- pgAdmin: `http://localhost:5050`

### Locally With Python

1. Create and activate a virtual environment.

2. Install dependencies:

	```bash
	pip install -r requirements.txt
	```

3. Set the required environment variables, especially `DATABASE_URL`.

4. Initialize the database and start the API:

	```bash
	python -m app.database_init
	uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
	```

## Run Tests Locally

Run the full test suite with:

```bash
pytest
```

You can also run the suites separately:

```bash
pytest tests/unit/
pytest tests/integration/
pytest tests/e2e/
```

If you run the end-to-end tests directly, make sure Playwright browsers are installed first:

```bash
playwright install
```

## Docker Hub Repository

The published Docker image is available on Docker Hub at:

[https://hub.docker.com/r/minam1/is601_final_project](https://hub.docker.com/r/minam1/is601_final_project)

## Dependency Management

This project uses a two-file workflow:

- `requirements.in` stores the top-level dependencies you choose directly.
- `requirements.txt` is the pinned lockfile generated from `requirements.in`.

The dependency toolchain is:

```bash
pip install pipreqs pip-tools pip-audit
pipreqs . --print
pip-audit -r requirements.txt
pip-compile requirements.in
pip-sync requirements.txt
```

Typical usage:

1. Use `pipreqs . --print` to inspect the direct imports needed by the project.
2. Update `requirements.in` with the dependencies you want to manage directly.
3. Run `pip-compile requirements.in` to generate a fully pinned `requirements.txt`.
4. Run `pip-audit -r requirements.txt` to check for known vulnerabilities.
5. Run `pip-sync requirements.txt` to make your environment match the lockfile exactly.
