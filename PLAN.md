## PiDesFire Plan

### Status

Phase 1 implementation started on 23 April 2026.

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

1. Land card layout and project skeleton.
2. Build a compileable CLI with provision and verify entry points.
3. Add real DESFire operations behind the client wrapper.
4. Add Home Assistant registration flow.