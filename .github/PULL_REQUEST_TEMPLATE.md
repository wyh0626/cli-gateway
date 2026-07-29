## Summary

<!-- What problem does this change solve? -->

## Security and compatibility

<!-- Note auth, secret, network, API, manifest, or migration impact. Write "none" when not applicable. -->

## Validation evidence

<!-- List the exact checks run and any relevant manual evidence. -->

## Checklist

- [ ] Tests cover the changed behavior and important deny paths.
- [ ] `make verify` passes.
- [ ] `make test-race` passes when concurrency or shared state changed.
- [ ] User-visible changes are documented and added to `CHANGELOG.md`.
- [ ] No credentials, private endpoints, or personal data are included.
- [ ] Commits are signed off with the Developer Certificate of Origin.
