# ExposureCheck

**Is your live site leaking secrets?** ExposureCheck is a free, 100% client-side scanner that checks what your *deployed* site actually serves to the public internet and flags the things that leak credentials — published source maps, a readable `.env`, an exposed `.git` directory, and API keys / private keys baked into the HTML and JS your site hands out.

**Live:** https://dukotah.github.io/exposurecheck/

A **Copper Bay Labs** product.

---

## The ship-safety suite

ExposureCheck is the third tool in the Copper Bay Labs ship-safety suite for vibe-coded and indie apps. Each answers a different "did I just ship something bad?" question:

| Tool | Question | Link |
| --- | --- | --- |
| **ShipSafe** | Will you get *sued*? (ADA / accessibility + privacy gaps) | https://dukotah.github.io/shipsafe/ |
| **LeakCheck** | Did you leak a secret in your *code*? (paste code / `.env` / config) | https://dukotah.github.io/leakcheck/ |
| **ExposureCheck** | Is your *live site* leaking? (scan what your deployment serves) | https://dukotah.github.io/exposurecheck/ |

ExposureCheck shares LeakCheck's Copper Bay Labs design system, severity model, masking, and `textContent`-safe rendering.

## How it works

- **URL mode** — give it a URL and it fetches the page plus a short list of well-known sensitive paths through a public CORS proxy (so your browser can read cross-origin responses). All detection then runs locally on the returned text. Only publicly-served paths are ever requested. *The target URL is visible to the public proxy — this is disclosed in-app.*
- **Paste mode** — view source / open your bundle, paste the text, and scan with **zero** network activity. Fully offline.

Every detected secret is **masked** (first/last few characters only) before it ever reaches the screen, so a screenshot or screen-share never releaks it.

## What it checks

Exposed `.env`, exposed `.git` directory, secret keys & private-key (PEM) blocks in served files, published source maps, backup/dotfile leaks, server-side keys shipped to the front-end, information-leaking headers, and risky exposed paths — each flagged Critical / High / Medium / Low by typical blast radius. See **[about.html](./about.html)** for the full methodology, the checks table, and the ethics rules.

## Ethics — authorized use only

ExposureCheck is a **defensive self-check, not a pentest tool.** Only scan sites you own or have explicit permission to test. It performs ordinary unauthenticated `GET` requests for conventional public paths — it never logs in, brute-forces, fuzzes, or sends exploit payloads. Scanning infrastructure you don't own may be unlawful regardless; when in doubt, use **paste mode** on output you've viewed yourself.

## Privacy

Nothing is stored — no account, no database, no analytics on your input, no logging. Results live only in the current tab and vanish on reload. In URL mode the target passes through a third-party public CORS proxy (disclosed); paste mode is fully local.

## Run it locally

It's a static site — no build step, no backend. Clone the folder and either open `index.html` directly, or serve it:

```bash
# Python
python -m http.server 8080

# or Node
npx serve .
```

Then visit `http://localhost:8080`. Paste mode works completely offline.

## Disclaimer

ExposureCheck is a fast heuristic surface scanner — **not a security guarantee, certification, or audit.** A clean result does not mean your site is secure, and a flagged result does not always mean a real exposure. Use it as a quick first pass, not the final word.

---

A [Copper Bay Labs](https://copperbaytech.com) product.
