# BETA-09: Dashboard and SecurityOla beta website

## Goal

Give an authenticated AppCare customer a usable, honest operating picture and give a prospective beta customer a clear path to understand the product.

## Dashboard contract

- The browser shell is safe to load without credentials, but operational state is returned only by authenticated GET /dashboard/state.
- The response is tenant-scoped and declares state_source=backend.
- Applications, findings, backups, connectors, deployments, and audit events are read from persisted AppCare records.
- Missing evidence is represented as unknown, pending, or empty; the API and browser must not manufacture a successful placeholder.
- Production actions remain disabled with reason BETA06_LIVE_PREVIEW_REQUIRED.

## Website contract

- The public page positions AppCare around Scan, Fix, Back up, and Recover.
- Pricing and assessment/recovery ranges match PRODUCT.md.
- Copy must not imply a guarantee, certification, or complete prevention of incidents.
- The beta CTA uses ordinary email navigation and does not create a lead or external side effect in the application.

## UX and accessibility acceptance

- Mobile and desktop layouts remain usable at the declared breakpoints.
- Loading, authentication/error, empty, and populated states are distinct.
- High-consequence production controls are visually distinct and remain locked.
- Interactive elements have labels, keyboard focus treatment, and a skip link.
- UI data is written through textContent rather than HTML interpolation.
- Color choices use OKLCH tokens, with semantic status color differences paired with text labels.
- No live deployment or production provider calls are part of BETA-09.

Monitoring state is read from persisted `monitoring_events` records scoped to
the authenticated tenant. The dashboard must show unknown when no persisted
observation exists and attention for the latest failed or degraded evidence;
it may not manufacture a healthy monitoring state.
