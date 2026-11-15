# Contributing

1. Fork, branch, keep one module per pull request. 2. `pip install -r requirements.txt && python -m pytest -q` must pass.
3. New detection rules go in `darklens/rules/rules.yaml` with an id, a plain-English `why`, and a test case.
4. Read [SECURITY.md](SECURITY.md) before touching the crawler. No real leaked data, credentials or keys in commits.
