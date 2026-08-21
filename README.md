<p align="center">
  <img src="https://img.shields.io/github/stars/AHMADOAFRIDI/OPEN-SOURCE?style=for-the-badge&logo=github&color=6366f1" alt="GitHub stars" />
  <img src="https://img.shields.io/github/forks/AHMADOAFRIDI/OPEN-SOURCE?style=for-the-badge&logo=github&color=22d3ee" alt="GitHub forks" />
  <img src="https://img.shields.io/github/watchers/AHMADOAFRIDI/OPEN-SOURCE?style=for-the-badge&logo=github&color=34d399" alt="GitHub watchers" />
  <img src="https://img.shields.io/github/license/AHMADOAFRIDI/OPEN-SOURCE?style=for-the-badge&color=f472b6" alt="License" />
</p>

<h1 align="center">🕸️ OPEN-SOURCE</h1>

<p align="center"><b>OPEN FILE CLONING</b></p>

<p align="center">
  <a href="showcase/index.html"><b>✨ Live Repo Showcase</b></a>
  &nbsp;·&nbsp; stars, forks, watchers &amp; every user fork — live from the GitHub API
</p>

---

## 🚀 Live Repo Showcase

See the repository in style — **who forked it, when, star counts, contributors and live stats**:

```bash
cd showcase
python3 -m http.server 8080
# open http://localhost:8080
```

Or open [`showcase/index.html`](showcase/index.html) directly in any browser.

The page pulls straight from the [GitHub REST API](https://docs.github.com/en/rest) —
no backend, no keys, and it works on GitHub Pages too (just enable Pages on the `main` branch).

## 🛡️ Defensive addition

> This repository also contains [ClonerHunter](cloner-detector/README.md), a defensive scanner that
> detects this class of *"Facebook cloner"* tooling. It fingerprints the leaked tokens, legacy
> endpoints, spoofed headers and behavioural patterns that such scripts rely on — see the
> [cloner-detector](cloner-detector/) directory.
>
> ```bash
> cd cloner-detector
> python3 run.py scan .. --exclude cloner-detector
> ```
>
> Running that command against this repo flags `AHMAD0.py` as
> `DEFINITIVE — Termux Facebook cloner (AHMAD0 / Hannan-404 style)`.

> **⚠️ Legal note:** credential-stuffing / account-takeover tooling is illegal in most jurisdictions
> and violates Meta's Terms of Service and GitHub's acceptable-use policy. The detector exists for
> defenders, researchers and educators.

---

## 📁 Contents

| Path | Purpose |
|------|---------|
| [`AHMAD0.py`](AHMAD0.py) | Original file under analysis |
| [`cloner-detector/`](cloner-detector/) | Defensive scanner (ClonerHunter) |
| [`showcase/`](showcase/) | Stylish live repo showcase (stats + forks) |

## ⭐ Community

- **Star** this repo to follow updates
- **Fork** it and open a PR — your fork shows up in the [showcase](showcase/index.html) automatically
- Watch the [forks page](https://github.com/AHMADOAFRIDI/OPEN-SOURCE/forks) to see who's contributing
