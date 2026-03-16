# SummerPuppy

Autonomous security operations and remediation platform.

## Build Commands

```bash
make install        # Install package with dev dependencies
make lint           # Run ruff check and format check
make format         # Auto-fix lint issues and format code
make typecheck      # Run strict mypy type checking
make test           # Run unit tests
make test-all       # Run lint + typecheck + unit + integration tests
make check          # Run lint + typecheck + unit tests (no integration)
make coverage       # Run tests with coverage report
```

## Architecture

Module dependency flow (left may not import from right):

```
trust → events → audit → channel → pipeline
```

- **trust** — Trust scoring, phase transitions, auto-approval policies
- **events** — Security event ingestion and normalization
- **audit** — Audit trail and compliance logging
- **channel** — Communication channel integrations
- **pipeline** — Orchestration pipeline for security operations
- **logging** — Structured logging configuration

### Dependency Rules

- `trust` must not import from `pipeline`
- `pipeline` may import from all other modules

## Module Conventions

- Every module has `__init__.py` with `__all__` listing public exports
- Data models live in `models.py`
- Business logic lives in separate files (e.g., `scoring.py`)

## Testing Conventions

- TDD: write tests first, then implementation
- Unit tests mirror `src/` structure under `tests/unit/`
- Integration tests live under `tests/integration/` and use testcontainers
- Factory functions for test data live in `tests/conftest.py`

## Code Style

- Strict mypy (all flags enabled)
- Ruff linter and formatter
- 99-character line length
- `from __future__ import annotations` in every `.py` file
- Pydantic v2 `BaseModel` for all data models
- `StrEnum` for all enumerations
- Type annotations on all function signatures

## Commit Convention

Conventional commits:

- `feat:` — New feature
- `fix:` — Bug fix
- `refactor:` — Code restructuring without behavior change
- `test:` — Adding or updating tests
- `docs:` — Documentation changes
