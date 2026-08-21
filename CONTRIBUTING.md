# Contributing

Thanks for your interest in OPEN-SOURCE!

## Quick Start

1. **Fork** the repo — your fork will appear automatically in the [Live Showcase](showcase/index.html)
2. Clone your fork: `git clone https://github.com/YOUR-USER/OPEN-SOURCE`
3. Create a branch: `git checkout -b feat/my-feature`
4. Make changes and test

## Testing the defensive scanner

```bash
cd cloner-detector
python3 run.py selfcheck
python3 -m unittest discover -s tests -v
python3 run.py scan .. --exclude cloner-detector
```

## Testing the showcase

```bash
cd showcase
python3 -m http.server 8080
# open http://localhost:8080
```

Or just open `showcase/index.html` directly — it uses only the GitHub REST API, no backend.

## Pull Requests

- Keep PRs focused and describe what changed
- Ensure `selfcheck` passes
- Stars and forks are live from GitHub API — no manual updates needed

## Code of Conduct

- Be respectful
- No credential-stuffing / account-takeover assistance
- Defensive research and education only for the cloner-detector component
