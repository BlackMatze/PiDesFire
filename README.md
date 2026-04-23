# PiDesFire

PiDesFire is a Raspberry Pi-side DESFire card provisioning tool for a Home Assistant based door-access architecture.

This repository covers the Pi provisioning service only.
The door reader implementation is planned in a separate repository.

## Project Status

Phase 1 is implemented and working on hardware:

- DESFire app creation and selection
- Identity file write and read-back verification
- AES diversified key setup
- Home Assistant state registration for provisioned cards
- Interactive card scan/provision loop
- Read-only card inspection mode for debugging and diagnostics

## Architecture (Current)

- Card security uses DESFire mutual-auth flows, not UID-only trust.
- Card identity is stored in a DESFire application/file model.
- Home Assistant is the policy authority (grant/deny, schedules, revocation).
- PiDesFire handles card lifecycle operations (provision/inspect/register).

## CLI Commands

- `pidesfire show-layout [config-path]`
- `pidesfire inspect [config-path]`
- `pidesfire provision-dry-run [config-path]`
- `pidesfire provision [config-path]`
- `pidesfire scan [config-path]`

Typical run from repository root:

```bash
cmake -S . -B build
cmake --build build
./build/pidesfire provision config.local.yaml
```

## Configuration

Base settings are in `config.yaml`.
Local machine and secret overrides belong in `config.local.yaml`.

Important fields:

- `app_aid`
- `nfc_device`
- `site_key_hex`
- `ha_url`
- `ha_token`
- `ha_tag_entity_prefix`

## Home Assistant Integration Notes

PiDesFire currently registers card state via Home Assistant REST `/api/states`.
This is functionally sufficient for state-based automations and policy lookup.

A `unique_id` attribute is included, but Home Assistant may still warn about missing unique ID in UI because `/api/states` entities are not full integration-managed entity registry entries.

## Hardware / Dependency Notes

Expected stack:

- Raspberry Pi (Linux)
- PN532 reader via libnfc
- libfreefare
- OpenSSL
- libcurl
- CMake + GCC (C++17)

## What Was Fixed Recently

- Factory-default PICC authentication fallback (AES, DES, 3DES)
- Robust provisioning sequence for partially initialized cards
- Better DESFire error reporting
- Stable Home Assistant request payload handling
- Config YAML copy into build directory during configure

## Next Steps

1. Formalize Home Assistant automation model for person mapping and schedules.
2. Implement reader-side authenticated scan pipeline in separate repository.
3. Add tests around identity encoding/decoding and provisioning edge cases.
4. Evaluate migration from `/api/states` to integration/discovery path if HA entity-registry behavior is required.
