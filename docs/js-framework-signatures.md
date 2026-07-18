# JS Framework Detection Signatures (Research)

Research for Sprint 8's expanded fingerprinting work. Covers React,
Vue, and Angular — the three frameworks explicitly named on the sprint
board. All signals below are detectable via a single HTTP GET request
to a page's HTML (body content + response headers), consistent with
this project's existing fingerprint checks
(`MetaGeneratorCheck`/`CMSFingerprintCheck`) — no JavaScript execution
or headless browser involved.

## Known limitation of this approach

Frameworks using pure client-side rendering with no server-side
markers (e.g. a bare `<div id="root"></div>` with all content injected
by JS after page load, and no build-tool-added comments/attributes)
can be difficult or impossible to detect via static HTML inspection
alone. The signatures below target common, reliable markers that
survive in the *initial* HTML response even for client-rendered apps
(build artifacts, root element conventions, common bundler output
patterns) — but a sufficiently minimal/obfuscated build could evade
all of them. Fully robust detection would require executing the page's
JavaScript (e.g. via a headless browser like Playwright), which is a
meaningfully larger architectural change and out of scope here.

## React

- **Root element convention:** `<div id="root">` or `<div id="app">`
  (the default CRA/Vite scaffold output) — weak signal alone (used by
  other frameworks too), but useful in combination with others below.
- **Script filename patterns:** bundled JS files often contain
  `react`, `react-dom`, or hashed chunk names like `main.[hash].js`
  from Create React App / Vite / webpack's default output conventions.
- **Inline/comment markers:** Create React App's default `index.html`
  includes an HTML comment: `<!-- This HTML file is a template. -->`
  — a fairly distinctive, if optional (developers can remove it),
  marker.
- **`data-reactroot` attribute:** older React versions (pre-18)
  rendered a `data-reactroot` attribute on the root DOM node in
  server-rendered/hydrated output — a strong signal when present, but
  removed in React 18+, so absence doesn't mean "not React."
- **Next.js (React meta-framework) specific:** `<div id="__next">` and
  `/_next/static/` script paths are extremely reliable, distinctive
  signals when present — worth treating Next.js detection as its own
  higher-confidence sub-signature.

## Vue

- **Root element convention:** `<div id="app">` (default Vue CLI/Vite
  scaffold) — same weak-alone caveat as React's `#root`/`#app`.
- **Script filename patterns:** bundled files often contain `vue`,
  `vue-router`, `vuex`/`pinia` in chunk names.
- **`data-v-` scoped CSS attributes:** Vue's single-file-component
  scoped styling adds `data-v-[hash]` attributes to rendered elements
  — a strong, fairly distinctive signal when present in the HTML body.
- **Nuxt.js (Vue meta-framework) specific:** `<div id="__nuxt">` and
  `/_nuxt/` script paths — reliable, similar to Next.js's signals.

## Angular

- **Root element convention:** `<app-root>` custom element tag (the
  Angular CLI default) — notably a custom *tag name*, not a `<div
  id="...">` pattern like React/Vue, making it a comparatively strong
  standalone signal on its own.
- **`ng-version` attribute:** Angular often renders an `ng-version="X.X.X"`
  attribute directly on the root element — when present, this is both
  a strong detection signal AND gives an exact version number for free
  (relevant to this project's broader "version disclosure" pattern
  already used in `ServerHeaderCheck`/`XPoweredByCheck`).
- **Script filename patterns:** `main.[hash].js`, `polyfills.[hash].js`,
  `runtime.[hash].js` — Angular CLI's default build output naming
  convention is fairly distinctive as a *combination* (all three
  typically present together), even though individually generic.

## Confidence levels (feeds into the next task, "Add confidence
labeling to fingerprint matches")

Based on the above, signals naturally fall into two tiers:

- **High confidence (near-certain match):** `ng-version` attribute,
  `data-reactroot`, `data-v-` attributes, `__next`/`__nuxt` root IDs —
  these are specific enough that a false positive is very unlikely.
- **Lower confidence ("possible" match):** generic root element IDs
  (`#root`, `#app`), and script filename patterns alone without a
  corroborating stronger signal — these could theoretically coincide
  with an unrelated framework/hand-rolled app, so should be flagged as
  "possible" rather than asserted outright.

## Sources

Research based on each framework's official CLI/scaffolding tool
default output (Create React App, Vue CLI, Angular CLI, and their
modern equivalents Vite/Next.js/Nuxt.js), which represent the most
common real-world deployment patterns most sites would actually use
in their built/served HTML.
