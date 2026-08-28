# Requirements Checklist: 013 Product Readiness

## Governance

- [ ] Constitution binds the product-completeness rules.
- [ ] Gap register is linked from binding governance.
- [ ] Pre-beta security gate is linked from binding governance.
- [ ] Readiness terminology is layered and unambiguous.
- [ ] Historical core beta evidence is preserved rather than rewritten.

## Functional completeness

- [ ] Mandatory capability matrix exists.
- [ ] Supportability is deterministic.
- [ ] Evidence class is explicit.
- [ ] Real-target requirements reject fixture/reference substitution.
- [ ] Missing mandatory capability blocks stack readiness.
- [ ] Missing security evidence blocks customer/pilot readiness.
- [ ] Real-pilot gaps can downgrade higher readiness states.
- [ ] Workers/models cannot self-approve readiness/supportability.
- [ ] Global live customer production remains disabled.

## Security

- [ ] Cross-tenant evidence rejected.
- [ ] Cross-application evidence rejected.
- [ ] Stale/mismatched revision/artifact evidence rejected.
- [ ] Approval/release evidence is sanitized.
- [ ] Codex Security diff scan passes.
- [ ] Dependency audit passes or approved blocking action is recorded.
- [ ] Secret/public-safety scan passes.

## Engineering evidence

- [ ] Spec Kit artifacts complete.
- [ ] Graphify pre/post impact reviewed.
- [ ] Saveruflo checkpoint recorded.
- [ ] deterministic tests pass.
- [ ] negative/failure tests pass.
- [ ] exact-head CI passes.
- [ ] coordinator reviewed actual diff.
