# QEMU QEMU-Native TLS with Linux KTLS Offload

**Status:** Proposed  
**Audience:** QEMU developers, Linux networking developers, OpenStack/Nova developers  
**Primary goal:** Enable QEMU's existing native-TLS transport to optionally use Linux Kernel TLS (KTLS) for TLS record processing while preserving the existing TLS protocol, certificate model, migration semantics, and compatibility.

## 1. Executive summary

QEMU supports native TLS for network services, including live migration. This project should add an optional KTLS acceleration path:

```text
                         QEMU
                          |
                    QIOChannelTLS
                          |
                    TLS handshake
                          |
                       GnuTLS
                          |
                +---------+---------+
                |                   |
          KTLS available       KTLS unavailable
                |                   |
             Linux KTLS        existing path
                |                   |
          +-----+-----+             |
          |           |             |
       TLS_SW       TLS_HW          |
          |           |             |
        Linux       NIC             |
        CPU        crypto           |
          |           |             |
          +-----+-----+-------------+
                |
               TCP
```

The implementation must be transparent to the remote endpoint. The peer continues to see an ordinary TLS connection. KTLS is a local transport optimization and must not introduce a new migration protocol or QEMU wire-protocol negotiation.

The initial implementation should prioritize correctness and safe fallback over maximum performance.

## 2. Problem statement

Encrypted live migration is supported by OpenStack Nova through QEMU-native TLS. This provides encryption of migration traffic without requiring an external VPN/IPsec tunnel.

However, TLS processing in userspace can consume significant CPU and involve data movement between userspace and the kernel. Linux KTLS provides a mechanism whereby the TLS record layer can be handled by the Linux kernel. On supported hardware, Linux can additionally expose TLS hardware offload.

The desired capability is:

> When QEMU establishes a native-TLS TCP connection, transparently transition the established TLS session to Linux KTLS when supported, while continuing to use the existing userspace TLS path when KTLS is unavailable or unsuitable.

This should allow deployments to benefit from reduced userspace TLS processing, lower CPU utilization, potentially higher throughput, and a path toward NIC TLS hardware offload.

## 3. Goals

### Primary goals

1. Add optional KTLS support to QEMU's existing TLS channel abstraction.
2. Keep the existing QEMU-native TLS security model.
3. Preserve TLS certificate validation and authentication.
4. Preserve existing TLS versions supported by QEMU/GnuTLS, subject to KTLS limitations.
5. Preserve migration semantics.
6. Fall back automatically to the existing userspace TLS implementation when KTLS cannot be used.
7. Make KTLS availability observable through QEMU tracing/debugging.
8. Add unit/integration tests covering KTLS and fallback.
9. Avoid making KTLS a build-time or runtime hard dependency.
10. Ensure compatibility with ordinary TLS peers that know nothing about KTLS.

### Secondary goals

1. Support TLS software offload (`TLS_SW`).
2. Establish a foundation for TLS hardware offload (`TLS_HW`).
3. Provide instrumentation to measure CPU and throughput impact.
4. Allow future QEMU callers besides migration to benefit from the same abstraction.

## 4. Non-goals

- Replacing GnuTLS.
- Implementing TLS cryptography directly inside QEMU.
- Implementing a new migration protocol.
- Changing Nova/libvirt migration configuration.
- Requiring KTLS on both endpoints.
- Requiring a specific NIC vendor.
- Implementing vendor-specific QEMU TLS APIs.
- Changing TLS certificates or PKI requirements.
- Making KTLS mandatory.
- Designing an OpenStack-specific KTLS protocol.
- Implementing IPsec or WireGuard.
- Changing QEMU's migration data format.

## 5. Architecture

### Current conceptual path

```text
QEMU migration
      |
      v
QIOChannelTLS
      |
      v
QCrypto/GnuTLS
      |
      v
TCP socket
      |
      v
Linux TCP/IP
```

### Proposed path

```text
QEMU migration
      |
      v
QIOChannelTLS
      |
      +---------------------------+
      |                           |
      v                           v
TLS handshake                Existing TLS path
      |
      v
GnuTLS-established session
      |
      v
Attempt KTLS activation
      |
      +-----------------------------+
      |                             |
      | success                     | failure
      v                             v
Linux KTLS                    Continue GnuTLS
      |
      +----------------+
      |                |
      v                v
TLS_SW             TLS_HW
      |                |
      +--------+-------+
               |
               v
              TCP
```

**Critical design principle:** KTLS is an implementation detail below the TLS protocol boundary. The remote peer must not need to know whether the local endpoint uses userspace TLS, KTLS software, or KTLS hardware offload.

## 6. QEMU code investigation

Before modifying code, inspect the current QEMU tree and identify the exact implementation used by the target branch. Do not assume file names from older releases.

Search for:

- `QIOChannelTLS`
- `qio_channel_tls`
- `QCryptoTLS`
- `gnutls`
- `gnutls_record_send`
- `gnutls_record_recv`
- `QIOChannel`
- migration TLS channel creation
- `tls-creds`
- migration channel creation
- multifd TLS handling
- post-copy migration handling

Likely relevant areas include `crypto/`, `io/`, `migration/`, `include/io/`, and `include/crypto/`, but this must be verified against the checked-out QEMU version.

Produce `docs/ktls-qemu-code-map.md` before implementation changes.

## 7. KTLS activation model

Use GnuTLS for the TLS handshake and certificate/authentication processing.

After the handshake succeeds:

1. Obtain the underlying socket FD (`sioc->fd` via `tioc->master`).
2. Determine whether the TLS session is eligible for KTLS (cipher, TLS version, and Linux host support).
3. Extract established symmetric session keys, IV/salt, and sequence numbers from GnuTLS using the public `gnutls_record_get_state()` API.
4. Configure the socket Upper Layer Protocol via `setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"))`.
5. Configure the cryptographic parameters via Linux's `SOL_TLS` API (`TLS_TX` and `TLS_RX`).
6. Transition record processing to KTLS fast-path in `QIOChannelTLS`.
7. Ensure subsequent reads/writes use direct socket `writev` / `readv` operations compatible with KTLS.
8. Record whether KTLS is active (`tioc->ktls_tx`, `tioc->ktls_rx`).

Note on GnuTLS KTLS: Forensic investigation showed that GnuTLS deliberately refuses to enable KTLS automatically when custom push/pull callbacks are registered (`session->internals.push_func != NULL`). Therefore, QEMU must extract the session keys using `gnutls_record_get_state()` and issue the `setsockopt()` calls directly.

## 8. Linux KTLS interface

The Linux socket API for KTLS uses:

```c
setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
setsockopt(fd, SOL_TLS, TLS_TX, &crypto_info, sizeof(crypto_info));
setsockopt(fd, SOL_TLS, TLS_RX, &crypto_info, sizeof(crypto_info));
```

Exact structures (`tls12_crypto_info_aes_gcm_128`, `tls12_crypto_info_aes_gcm_256`, `tls12_crypto_info_chacha20_poly1305`), constants, and supported cipher/version combinations are defined in `linux/tls.h`.

Because `linux/tls.h` is not currently present in QEMU's `linux-headers/linux/`, QEMU must provide a clean internal compatibility header (`crypto/ktls-linux.h`) under `#ifdef __linux__` to ensure portable builds across systems without introducing unnecessary kernel header bump requirements.

## 9. GnuTLS integration

Findings from GnuTLS 3.8.x forensic analysis:

1. **KTLS support:** GnuTLS supports KTLS, but only automatically when built with `--enable-ktls`, enabled in `/etc/gnutls/config` (`[global] ktls = true`), and using raw file descriptors with no custom pull/push callbacks.
2. **QEMU compatibility:** Because QEMU routes TLS transport through `QIOChannel` using custom callbacks, GnuTLS logs `"Not enabling KTLS with custom pull/push function"` and disables KTLS.
3. **Public API for KTLS:** GnuTLS provides `gnutls_record_get_state()` specifically to export MAC key, IV, cipher key, and sequence numbers for hardware/kernel offload.
4. **Socket setup requirement:** QEMU must perform socket `setsockopt` directly.
5. **Directional support:** Supported for both TX and RX independently.

## 10. TLS compatibility

### TLS 1.2

Target for initial KTLS support. Rock-solid stability across Linux 4.17+ and 5.10+ LTS kernels, with no KeyUpdate complications.

### TLS 1.3

Supported in Linux KTLS since kernel 5.2. However, Linux kernels prior to 6.14 do not support active session re-keying (`KeyUpdate`) via KTLS. In Linux 6.14+, re-keying support was added.

If TLS 1.3 is negotiated, either restrict KTLS to kernels >= 6.14, negotiate TLS 1.2 when KTLS is desired, or fall back to userspace TLS if KeyUpdate is required. Never silently weaken the negotiated TLS version.

## 11. Migration-specific concerns

Explicitly investigate:

### Pre-copy

Test source QEMU -> destination QEMU with native TLS + KTLS.

### Post-copy

Test independently because read/write behavior and channel ownership can differ.

### Block migration

Determine whether TLS-protected NBD traffic uses the same QIOChannel TLS/KTLS abstraction. If it is a separate TLS channel, handle it independently.

### Multifd

Each TLS connection should independently determine KTLS availability.

Example:

```text
QEMU source
 |
 +-- multifd channel 0 -- TLS -- KTLS
 +-- multifd channel 1 -- TLS -- KTLS
 +-- multifd channel 2 -- TLS -- KTLS
 +-- multifd channel 3 -- TLS -- userspace fallback
 |
 destination
```

Mixed behavior must be safe.

## 12. Failure and fallback semantics

KTLS must be opportunistic.

If the kernel lacks KTLS, GnuTLS lacks KTLS support, the cipher/version is unsupported, hardware offload is unavailable, or KTLS setup fails, QEMU must continue using userspace TLS.

The migration must not fail solely because KTLS is unavailable.

Security rule:

```text
KTLS -> userspace TLS
```

is allowed.

```text
KTLS -> plaintext
```

is never allowed.

## 13. Configuration

Do not make KTLS mandatory.

Preferred model:

```text
native TLS enabled
        |
        v
attempt KTLS automatically
        |
   +----+----+
   |         |
 success   unavailable
   |         |
 KTLS     userspace TLS
```

If an explicit option is useful for debugging, consider:

```text
tls-ktls=auto|on|off
```

with `auto` as the default. `on` should only be added if there is a strong testing/operational need.

## 14. Observability

Add QEMU tracing/debug information sufficient to determine:

1. KTLS attempted.
2. KTLS successfully activated.
3. TX KTLS active.
4. RX KTLS active.
5. TLS version.
6. Negotiated cipher.
7. KTLS fallback reason.
8. TLS software vs hardware KTLS where this can be determined reliably (via Netlink `inet_diag` socket diagnostics querying `TLS_INFO_TXCONF` / `TLS_INFO_RXCONF`).

Never log private keys or session keys.

Conceptual traces:

```text
qio_channel_tls_ktls_attempt fd=42
qio_channel_tls_ktls_enabled fd=42 tx=1 rx=1
qio_channel_tls_ktls_fallback fd=42 reason="unsupported cipher"
```

Use QEMU's existing tracing conventions.

## 15. Security requirements

Preserve:

- certificate validation;
- host authentication;
- configured identity/hostname validation;
- TLS cipher policy;
- TLS version policy;
- credential lifecycle;
- existing verification behavior.

KTLS activation must occur only after the TLS session has been successfully established and authenticated.

Do not unnecessarily duplicate TLS keys into unrelated QEMU components.

## 16. Build-time portability

QEMU must continue to build where:

- Linux KTLS headers are unavailable;
- GnuTLS has no KTLS support;
- the host is not Linux.

Use compile-time feature detection and isolate Linux-specific code appropriately.

## 17. Testing strategy

### Unit tests

Cover:

1. KTLS capability detection.
2. Activation success.
3. Activation failure.
4. Unsupported cipher fallback.
5. Unsupported TLS version fallback.
6. Missing kernel support.
7. Missing GnuTLS KTLS support.
8. Userspace TLS when KTLS is disabled.
9. Mixed TLS channels.
10. Socket cleanup after activation.

Where direct KTLS testing is impossible in CI, use mocks/dependency injection around the KTLS activation layer.

### Integration tests

On Linux with KTLS:

1. Establish QEMU TLS connection.
2. Verify TLS handshake.
3. Verify KTLS activation.
4. Transfer data in both directions.
5. Verify integrity.
6. Close/reopen.
7. Repeat with KTLS disabled.
8. Repeat with KTLS unavailable.

### Migration tests

Test:

- normal live migration;
- pre-copy;
- post-copy where supported;
- multifd;
- block migration;
- encrypted migration;
- KTLS enabled;
- KTLS unavailable;
- KTLS disabled;
- source with KTLS / destination without KTLS;
- source without KTLS / destination with KTLS.

The destination does not need KTLS for the source to use KTLS. KTLS is local to each TCP endpoint.

### Failure injection

Test failure after:

1. TLS handshake.
2. KTLS TX setup.
3. KTLS RX setup.
4. First encrypted record.
5. Migration channel creation.
6. One multifd channel.

Verify that failures never silently convert the connection to plaintext.

## 18. Performance benchmarking

Compare:

### Baseline

```text
QEMU -> GnuTLS -> TCP
```

### KTLS software

```text
QEMU -> GnuTLS -> KTLS/TLS_SW -> TCP
```

### KTLS hardware

Where hardware supports it:

```text
QEMU -> GnuTLS -> KTLS/TLS_HW -> NIC -> TCP
```

Measure:

- migration throughput;
- source/destination CPU utilization;
- system and userspace CPU time;
- wall-clock migration time;
- migration downtime;
- memory bandwidth;
- network throughput;
- packet rate;
- TLS record rate.

Test representative high-bandwidth links, including 10/25/40/50/100 Gb/s where available. Do not claim improvement without measurements.

## 19. Hardware-offload investigation

Investigate:

- Linux KTLS TLS_HW support;
- NIC driver requirements;
- supported TLS versions;
- supported cipher suites;
- TX vs RX offload;
- NIC firmware requirements;
- VLAN/bridge/OVS interaction;
- SR-IOV/VF interaction;
- eligibility of migration traffic for hardware offload.

Do not implement vendor-specific QEMU code. The desired path is:

```text
QEMU
  |
GnuTLS
  |
KTLS
  |
generic Linux socket API
  |
NIC driver
  |
vendor hardware
```

## 20. OpenStack/Nova integration

No Nova change should be necessary for basic functionality.

Existing Nova configuration such as:

```ini
[libvirt]
live_migration_with_native_tls = true
live_migration_scheme = tls
```

should continue to work unchanged.

After the QEMU work, investigate whether Canonical OpenStack/Sunbeam requires packaging, kernel, or snap changes to benefit.

Potential follow-up work:

- enable native TLS in the Canonical OpenStack hypervisor snap;
- ensure QEMU/GnuTLS versions support KTLS;
- ensure Ubuntu kernel support;
- expose operational status;
- document performance/security implications.

These are separate from the QEMU implementation.

## 21. Deliverables

### D1 — Code analysis

`docs/ktls-qemu-code-map.md`

Include relevant source files, classes/functions, current TLS path, migration TLS path, GnuTLS interaction, socket ownership, and multifd interaction.

### D2 — Design document

`docs/ktls-design.md`

Include architecture, state machine, API changes, fallback behavior, TLS 1.2/1.3 analysis, security analysis, and compatibility matrix.

### D3 — Implementation

QEMU source changes implementing optional KTLS.

### D4 — Unit tests

Capability detection, activation, and fallback.

### D5 — Integration tests

Linux KTLS integration coverage.

### D6 — Migration tests

Native-TLS migration and relevant migration modes.

### D7 — Benchmark tooling

Scripts/documented commands for baseline, KTLS software, and KTLS hardware.

### D8 — Performance report

`docs/ktls-performance.md` with raw measurements and methodology.

### D9 — Documentation

Prerequisites, supported configurations, detection, fallback, limitations, troubleshooting.

## 22. Acceptance criteria

### Functional

- [ ] QEMU builds without KTLS support.
- [ ] QEMU builds with KTLS support.
- [ ] Existing native TLS continues to work.
- [ ] KTLS can be activated for a TLS socket.
- [ ] TLS traffic remains encrypted.
- [ ] Remote peers require no KTLS support.
- [ ] KTLS failure falls back to userspace TLS.
- [ ] No plaintext fallback is possible.
- [ ] Normal migration succeeds.
- [ ] Encrypted migration succeeds.
- [ ] Multifd behavior is correct.
- [ ] Post-copy behavior is explicitly tested or documented.
- [ ] Block migration/NBD TLS behavior is explicitly tested or documented.

### Security

- [ ] Certificate validation is unchanged.
- [ ] TLS policy is unchanged.
- [ ] No secret material is logged.
- [ ] KTLS activation occurs only after TLS establishment.
- [ ] TLS session keys are not unnecessarily duplicated.

### Portability

- [ ] Non-Linux builds remain unaffected.
- [ ] Linux without KTLS remains functional.
- [ ] Supported older GnuTLS configurations remain functional.

### Observability

- [ ] Operators can determine whether KTLS was activated.
- [ ] Operators can determine why KTLS was not activated.
- [ ] TX/RX KTLS state is observable where supported.

### Performance

- [ ] Baseline is established.
- [ ] KTLS software performance is measured.
- [ ] Hardware offload is investigated where available.
- [ ] Measurements are reproducible.

## 23. Suggested implementation sequence

### Phase 1 — Code archaeology

1. Clone the target QEMU repository.
2. Identify exact TLS and migration implementation.
3. Identify QIOChannel abstraction.
4. Identify GnuTLS integration.
5. Identify migration and multifd TLS channel creation.
6. Record findings in `docs/ktls-qemu-code-map.md`.

### Phase 2 — Prototype

Implement a minimal Linux-only KTLS helper.

Goals:

- establish TLS using existing QEMU/GnuTLS code;
- attempt KTLS;
- detect success;
- send/receive test traffic;
- fallback to existing userspace TLS.

Do not change migration behavior yet.

### Phase 3 — TLS channel integration

Integrate KTLS into QEMU's TLS channel abstraction so callers see:

```text
QIOChannelTLS
  |
  +-- userspace TLS
  |
  +-- KTLS
```

### Phase 4 — Migration

Exercise pre-copy, post-copy, multifd, and block migration. Resolve concurrency and record-layer issues.

### Phase 5 — Testing and observability

Add traces, unit tests, and integration tests.

### Phase 6 — Benchmarking

Compare baseline and KTLS.

### Phase 7 — Hardware offload

Investigate and document TLS_HW. Do not block software-KTLS implementation on hardware offload.

### Phase 8 — Upstream preparation

Prepare patch series, commit messages, design rationale, tests, benchmark results, and documentation. The implementation should be suitable for upstream QEMU review and not contain OpenStack- or Canonical-specific assumptions.

## 24. Questions Antigravity must answer

Before finalizing implementation, explicitly answer:
*(Note: Complete, verified answers to all 25 questions are documented in Section 5 of `docs/ktls-feasibility.md`.)*

1. Does the current QEMU TLS abstraction expose the socket FD cleanly enough to activate KTLS?
2. Does the GnuTLS version used by the target QEMU already activate KTLS automatically?
3. If yes, is QEMU required to do anything beyond enabling the relevant GnuTLS capability?
4. If no, what exact socket/session state must QEMU install?
5. Which TLS 1.2 ciphers are supported by Linux KTLS?
6. Which TLS 1.3 ciphers are supported?
7. What happens on TLS 1.3 KeyUpdate?
8. Can QEMU safely use KTLS with concurrent read/write operations?
9. Does migration TLS depend on TLS record boundaries?
10. Does multifd create one TLS session per channel?
11. Does block migration use a separate TLS channel?
12. Can KTLS activation happen after application data has been exchanged?
13. What happens if TX KTLS succeeds but RX KTLS fails?
14. Does Linux require KTLS before application data is exchanged?
15. What is the minimum supported Linux kernel?
16. What is the minimum supported GnuTLS version?
17. Can TLS_HW vs TLS_SW be detected reliably?
18. Does KTLS survive migration channel reconnects?
19. What happens when source supports KTLS but destination does not?
20. Are there security implications of moving record processing into the kernel?
21. Do SELinux/AppArmor/seccomp affect KTLS?
22. Does QEMU snap confinement permit the required socket operations?
23. Does Ubuntu's QEMU/GnuTLS packaging enable KTLS?
24. Does OVS/bridge/VLAN networking affect TLS_HW eligibility?
25. What measurable CPU reduction does KTLS provide for migration workloads?

## 25. Definition of done

The project is complete when:

> A current upstream QEMU build can establish its normal native-TLS connection, transparently use Linux KTLS when available, securely fall back to its existing userspace TLS implementation when KTLS is unavailable, pass migration and TLS regression testing, and provide reproducible evidence of the performance and security characteristics.

The implementation must remain generic QEMU functionality and must not contain OpenStack- or Canonical-specific assumptions.
