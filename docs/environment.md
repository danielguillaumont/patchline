# Development environment

Recommended Windows PowerShell 5.1, Python 3.12, uv, Git, Node.js 22, VS Code and Power BI Desktop. Keep actual local version output in the PR description; do not commit machine-specific paths or tokens.

Initial verification:

```powershell
uv --version
uv python find 3.12
uv sync --python 3.12
uv run pytest
uv run ruff check .
```

`uv.lock` is generated during the initial verified install and must be committed before pushing CI, which invokes `uv sync --locked`.
