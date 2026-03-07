# Countdown App Spec (Non-Negotiable)

- App lives at `/` and `/countdown/`.
- Countdown API lives under `/api/countdown/*`.
- Legacy non-countdown paths are disabled (`404`).
- Users can create public and private countdowns.
- Private countdowns require password unlock for viewers.
- Shared links and embed links work without breaking timer rendering.
- Resolver can populate dates from `/api/resolve-date` when configured.
