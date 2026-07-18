"""JS framework detection signatures, researched in
docs/js-framework-signatures.md. Each signature is a (pattern, label,
confidence) tuple checked against the page's raw HTML body via simple
substring/regex matching — consistent with this project's existing
lightweight fingerprinting approach (no JS execution/headless browser).
"""

import re

# Each entry: (compiled regex pattern, human-readable label, confidence)
# Confidence is either "high" (near-certain, specific/unlikely to
# coincide) or "possible" (generic marker that could theoretically
# belong to something else) — see docs/js-framework-signatures.md's
# "Confidence levels" section for the full reasoning.

FRAMEWORK_SIGNATURES = [
    # Next.js (checked before generic React, since it's the more
    # specific/informative match when both would technically apply)
    (re.compile(r'id="__next"'), "Next.js (React)", "high"),
    (re.compile(r'/_next/static/'), "Next.js (React)", "high"),
    # React
    (re.compile(r'data-reactroot'), "React", "high"),
    (re.compile(r'<!--\s*This HTML file is a template\.\s*-->'), "React (Create React App)", "high"),
    (re.compile(r'id="root"'), "React (possible)", "possible"),
    # Nuxt.js
    (re.compile(r'id="__nuxt"'), "Nuxt.js (Vue)", "high"),
    (re.compile(r'/_nuxt/'), "Nuxt.js (Vue)", "high"),
    # Vue
    (re.compile(r'data-v-[a-f0-9]{6,8}'), "Vue", "high"),
    (re.compile(r'id="app"'), "Vue or Angular (possible)", "possible"),
    # Angular
    (re.compile(r'<app-root'), "Angular", "high"),
    (re.compile(r'ng-version="([\d.]+)"'), "Angular", "high"),
    # Generic bundler output patterns (lower confidence individually,
    # useful as corroborating evidence alongside a stronger match)
    (re.compile(r'main\.[a-f0-9]{8,20}\.js'), "Bundled JS (webpack/similar)", "possible"),
    (re.compile(r'polyfills\.[a-f0-9]{8,20}\.js'), "Angular CLI build output", "possible"),
    (re.compile(r'runtime\.[a-f0-9]{8,20}\.js'), "Angular CLI build output", "possible"),
]
