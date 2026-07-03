# PiDesFire

PiDesFire is a Raspberry Pi-side DESFire card provisioning tool for a Home Assistant based door-access architecture.

This repository covers the Pi provisioning service only.
The door reader implementation is planned in a separate repository.

## Project Status

Phase 1 is implemented and working on hardware:

- DESFire app creation and selection
- Identity file write and read-back verification
- AES diversified key setup
- Native Home Assistant `tag_scanned` registration for provisioned cards
- Interactive card provision loop
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
- `pidesfire provision-loop [config-path]`

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
- `ha_tag_scanner_device_id`
- `ha_tag_entity_prefix` (legacy/deprecated)

## Home Assistant Integration Notes

PiDesFire now registers card scans through Home Assistant REST `/api/events/tag_scanned`.

This aligns provisioning with native HA tag entities (`tag.04_xx_...`) and updates native tag metadata (`last_scanned`, `last_scanned_by_device_id`) when scanner device ID is configured.

Lookup logic is also aligned to native HA tag entity IDs. Legacy custom state entities (`tag.doorcard_*` / `tag.pidesfire_*`) are no longer the active registration path.

## Hardware / Dependency Notes

Expected stack:

- Raspberry Pi (Linux)
- PN532 reader via libnfc
- libfreefare
- OpenSSL
- libcurl
- CMake + GCC (C++17)

## Testing

An initial CTest target covers File 01 identity binary encode/decode behavior and validation failures:

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

## What Was Fixed Recently

- Factory-default PICC authentication fallback (AES, DES, 3DES)
- Robust provisioning sequence for partially initialized cards
- Better DESFire error reporting
- Stable Home Assistant request payload handling
- Config YAML copy into build directory during configure

## Next Steps

1. Formalize Home Assistant automation model for person mapping and schedules.
2. Implement reader-side authenticated scan pipeline in separate repository.
3. Expand tests to cover provisioning edge cases and Home Assistant integration behavior.
4. Expand tests for native `tag_scanned` registration, scanner-device metadata updates, and HA-side automation compatibility.
