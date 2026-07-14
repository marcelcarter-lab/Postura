# Demo Script

A ~5-7 minute walkthrough of Postura, using the seeded demo data
(`python -m scripts.seed_demo_data`). Run the seed script fresh before
presenting to ensure a clean, predictable state.

## Setup (before the audience sees anything)

```bash
docker compose down -v
docker compose up --build -d
docker compose run --rm web python -m scripts.seed_demo_data
```

Have the browser open to `http://localhost:5000/auth/login` before starting.

## 1. Introduce the problem (30 seconds, no screen interaction)

"Web agencies hand off client sites all the time — but security
review before handoff is usually manual, inconsistent, or skipped
entirely. Postura automates that: point it at a site, and it checks
headers, SSL/TLS configuration, common exposure risks, and technology
fingerprinting, then scores it and generates a client-ready report."

## 2. Log in (15 seconds)

- Log in with `demo@postura.local` / `DemoPassword123`
- **Talking point while the dashboard loads:** "This is the agency's
  view — every tracked client website in one place."

## 3. Dashboard walkthrough (45 seconds)

- Point out the three seeded websites and their score badges —
  deliberately one green, one amber, one red.
- **Talking point:** "The color coding gives an at-a-glance read on
  which clients need attention, without opening anything."
- Click "History" on the moderate-scoring site (Riverside Bakery) —
  show the two-scan history, demonstrating this isn't a one-off check,
  it's tracked over time.

## 4. Trigger a live scan (60-90 seconds — this is the "wait" moment, use it deliberately)

- Add a new website: use `http://test-target:5001` (our deliberately
  vulnerable local test fixture) — name it "Live Demo Target."
- Click "Scan Now."
- **While it's running (this genuinely takes real time — SSL/TLS
  checks alone can take 30-60+ seconds):** "This is running all 15
  checks live right now — security headers, SSL/TLS configuration
  checks against a real tool called sslscan for accuracy, and checks
  for exposed files like .git directories. This target is
  intentionally misconfigured so we get real findings to look at."
- Resist the urge to fill dead air by clicking elsewhere — let the
  spinner run, keep talking about what's happening.

## 5. Scan results (90 seconds — the core of the demo)

- Once it redirects: point out the score (should be low/red, given the
  intentional weaknesses).
- Scroll through the severity-grouped findings — specifically show:
  - The `CRITICAL` exposure finding (`.git/HEAD`, `.git/config`
    publicly accessible) — click "Show evidence" to reveal the raw
    evidence text.
  - A couple of `MEDIUM`/`LOW` header findings.
- **Talking point:** "Every finding includes not just what's wrong,
  but a specific recommendation for fixing it — this is written to be
  handed directly to a developer, not just a security analyst."

## 6. PDF report (60 seconds)

- Click "Download PDF Report."
- Open the downloaded PDF, scroll through:
  - Executive summary — **talking point:** "This part is deliberately
    written in plain language, no jargon — it's meant for the
    agency's client to read directly, not just their dev team."
  - Recommendations section — point out the prioritized ordering.
  - Findings table — point out it repeats across pages if it's long
    enough, with proper page numbers.
- **Talking point:** "This is the actual client-facing deliverable —
  an agency can generate this and hand it straight over."

## 7. Wrap-up (30 seconds)

"That's the full flow — add a site, scan it, review results, generate
a report. Everything's built with Docker Compose for easy deployment,
has a full test suite, and I've documented the architecture and
security design decisions in the repo if you want to dig into specifics."

## Anticipated questions and answers

- **"How long does a scan actually take?"** — Typically 30-90 seconds,
  dominated by the SSL/TLS checks (which use an external tool,
  `sslscan`, specifically because Python's built-in TLS library can't
  reliably detect weak/legacy configurations — happy to go into why if
  interested).
- **"Does this scale to many sites/scans?"** — Currently synchronous
  (one scan blocks one request) — documented as a known limitation and
  natural next step (background job queue) in `security-considerations.md`.
- **"Is this safe to point at any URL?"** — Yes, there's an SSRF guard
  that blocks scanning private/internal IP ranges, specifically to
  prevent the tool from being misused to probe internal infrastructure.

## Fallback plan if live scanning fails during the actual demo

If `http://test-target:5001` is unreachable or something goes wrong
live (network hiccup, container not started, etc.), skip step 4
entirely and go straight from the dashboard (step 3) to clicking
directly into one of the **pre-seeded** scans' detail pages (step 5),
which don't depend on anything working live. Mention: "I'll show you a
previously completed scan rather than run a live one, in the interest
of time" — natural, doesn't draw attention to a technical hiccup.
