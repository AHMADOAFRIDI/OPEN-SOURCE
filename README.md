# OPEN-SOURCE

OPEN FILE CLONING

> **Defensive addition:** this repository now also contains
> [ClonerHunter](cloner-detector/README.md), a defensive scanner that
> detects this class of "Facebook cloner" tooling. It fingerprints the
> leaked tokens, legacy endpoints, spoofed headers and behavioural
> patterns that such scripts rely on — see the
> [cloner-detector](cloner-detector/) directory.
>
> ```bash
> cd cloner-detector
> python3 run.py scan .. --exclude cloner-detector
> ```
>
> Running that command against this repo flags `AHMAD0.py` as
> `DEFINITIVE — Termux Facebook cloner (AHMAD0 / Hannan-404 style)`.
>
> Note: credential-stuffing / account-takeover tooling is illegal in most
> jurisdictions and violates Meta's Terms of Service and GitHub's
> acceptable-use policy. The detector exists for defenders, researchers
> and educators.
