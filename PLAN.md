## PiDesFire Plan

### Status

Phase 1 is complete.
Phase 2a (shared contract extraction) is complete.

Current focus is Phase 2b: implementing the ESPHome door reader against the shared contract.

### Scope

This repository contains the Raspberry Pi-side DESFire card provisioner.
The door reader will live in a separate repository.

### Phase 1 Goals

1. Finalize the DESFire card layout.
2. Implement the Pi-side provisioner in C++.
3. Register provisioned card identities in Home Assistant.

### Card Model

- Use a dedicated DESFire application per access system.
- Use AES application keys.
- Reader-side trust is based on DESFire mutual authentication, not UID.
- Home Assistant remains the only authority for access policy.

### Initial Repository Structure

- CMakeLists.txt
- PLAN.md
- config.yaml
- docs/card-layout.md
- src/
- tests/

### Near-Term Implementation Order

1. Build ESPHome external component for PN532 + DESFire flow.
2. Implement reader pipeline: detect card, select AID, read File 01, derive Key 1, authenticate, then report to HA only on successful auth.
3. Add end-to-end validation with provisioned cards and HA event checks.
4. Add lifecycle tests for revoke/reissue and reader error handling.

### Completed Milestones

1. Card layout finalized and documented in `docs/card-layout.md`.
2. Pi-side provisioner implemented in C++.
3. Home Assistant registration flow implemented.
4. Identity record unit tests added (`tests/test_identity_record.cpp`).
5. Shared contract extracted to `BlackMatze/pidesfire-contract` and linked as the `contract/` submodule.