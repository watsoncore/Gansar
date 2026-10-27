# Tether artwork guidance

Official source checked 2026-10-16: <https://tether.to/en/media/>.

Tether's media page conditionally permits accurate, lawful references to Tether and its tokens, products and services under its trademark guidelines. It requires artwork supplied by Tether, clear undistorted display, no alteration, and no suggestion of sponsorship or endorsement. Trademark ownership stays with Tether. Permission is subject to the current guidelines and may be revoked for breach or objection; no broader license is claimed.

The bundled `tether.svg` is the original circular-display SVG from <https://tether.to/images/logoCircle.svg>, without edits. Its SHA-256 is recorded in `manifest.json`. The renderer fits it proportionally into an existing badge and displays it only for an explicit, non-UNKNOWN `service_id=tether` claim. A token holding, token transfer, or USDT asset name never assigns this service identity or logo.
