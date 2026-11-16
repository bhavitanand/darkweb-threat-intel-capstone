# Contributing

Thank you for helping. A change is ready when it has a test, passes CI, and says what it changed.

## Setup

```bash
pip install -r requirements-dev.txt
python -m pytest -q                                     # backend
cd frontend && npm ci && npm run lint && npm test && npm run build   # frontend
```

Set `TEST_DATABASE_URL` to a throwaway Postgres to also run the storage and API tests against Postgres (CI does this).

## Rules for changes

1. Fork, branch, keep one concern per pull request, and fill in the pull request template.
2. **New detection rules** go in `darklens/rules/rules.yaml` with an id, a plain-English `why`, a test that fires, **and** a test for a look-alike that must stay Low (see `tests/test_database_sale.py`). Prefer bounded gaps (`.{0,60}`) over open-ended ones.
3. **Accuracy claims** must say what data they were measured on. Synthetic numbers are labelled synthetic.
4. **Frontend:** plain words for non-technical readers, no emojis, keyboard and screen-reader friendly, works at phone width.
5. User-visible changes get a line in [CHANGELOG.md](CHANGELOG.md).
6. Read [SECURITY.md](SECURITY.md) before touching the crawler. No real leaked data, credentials, personal data or keys in commits.

## Ways to help that are not code

- Press **"Is this right?"** on alerts in the website.
- Add real, public, hand-labelled examples to `data/real_labelled/` (see its README). This is the single most valuable contribution.
- Report wrong scores with the alert's link.

See [docs/roadmap.md](docs/roadmap.md) for what is wanted next.
