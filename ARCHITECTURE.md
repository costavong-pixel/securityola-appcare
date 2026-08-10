# Architecture

## Repair workflow

Alert/scan
→ preserve evidence
→ create backup
→ reproduce in staging/isolation
→ prepare fix
→ run tests/security validation
→ approve
→ deploy
→ verify production
→ rollback on failed verification
→ continue monitoring

## Backup strategy

Primary recent backup:
- Backblaze B2
- Object Lock / immutable retention where supported

Long-term archive:
- AWS S3 Glacier Deep Archive

Rules:
- backups remain outside the customer's production server/account
- restore testing is required; backup existence alone is not sufficient

## Initial supported stack

- GitHub
- Vercel
- Supabase
- Lovable-generated or similar web apps

Custom or messy infrastructure is assessed before acceptance.
