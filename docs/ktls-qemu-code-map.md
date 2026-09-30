# QEMU KTLS Code Map & Architectural Trace

## 1. Executive Architecture Summary

This document maps the complete Transport Layer Security (TLS) call chain in QEMU, establishes the exact relationships between the I/O Channel subsystem (`QIOChannel`), the cryptography layer (`QCryptoTLSSession` wrapping GnuTLS), the migration subsystem (`migration/`), and the Linux kernel Transport Layer Security (KTLS) offload interface.

In current QEMU, TLS is abstracted through `QIOChannelTLS` ([io/channel-tls.c](file:///project/io/channel-tls.c)), which implements the standard `QIOChannel` class while encapsulating an underlying transport channel (`tioc->master`, typically a `QIOChannelSocket` in [io/channel-socket.c](file:///project/io/channel-socket.c)) and a crypto session (`tioc->session` in [crypto/tlssession.c](file:///project/crypto/tlssession.c)).

All TLS operations—handshake, framing, encryption, decryption, and alert handling—are delegated by `QCryptoTLSSession` to the GnuTLS library (`gnutls_session_t`). Crucially, `QCryptoTLSSession` connects to GnuTLS using custom I/O callbacks (`gnutls_transport_set_push_function` and `gnutls_transport_set_pull_function`), passing raw ciphertext through `QIOChannelTLS` read/write handlers.

```
+-----------------------------------------------------------------------------------+
| Migration Engine / NBD / Chardev                                                  |
| (Pre-copy, Post-copy Preempt, MultiFD Channels 0..N, NBD Client/Server)           |
+-----------------------------------------------------------------------------------+
                                      |
                                      v [QIOChannel Virtual Methods: readv, writev]
+-----------------------------------------------------------------------------------+
| QIOChannelTLS  (io/channel-tls.c)                                                 |
| - tioc->master: points to QIOChannelSocket                                        |
| - tioc->session: points to QCryptoTLSSession                                      |
|                                                                                   |
|  [Standard Path]                                [KTLS Offload Path]               |
|  qcrypto_tls_session_write()                     writev directly to master fd     |
|         |                                        (Kernel handles AEAD encryption) |
|         v                                                                         |
|  gnutls_record_send()                                                             |
|         | (pushes ciphertext)                                                     |
|         v                                                                         |
|  qio_channel_tls_write_handler()                                                  |
+-----------------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------------+
| QIOChannelSocket (io/channel-socket.c)                                            |
| - sioc->fd: underlying TCP socket file descriptor                                 |
+-----------------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------------+
| Linux Kernel Network Stack (net/tls)                                              |
| - TCP_ULP "tls"                                                                   |
| - SOL_TLS: TLS_TX / TLS_RX (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305)          |
| - Crypto offload: Software (Kernel Crypto API) or Hardware (NIC ASIC)             |
+-----------------------------------------------------------------------------------+
```

---

## 2. Complete TLS Call Chain and Subsystem Inventory

### 2.1 File & Class Hierarchy

| Component | Header | Implementation | Primary Responsibilities |
| :--- | :--- | :--- | :--- |
| **`QIOChannelSocket`** | [`include/io/channel-socket.h`](file:///project/include/io/channel-socket.h) | [`io/channel-socket.c`](file:///project/io/channel-socket.c) | Encapsulates the underlying network file descriptor (`sioc->fd`). Implements TCP/UNIX socket connect, listen, accept, readv, writev. |
| **`QIOChannelTLS`** | [`include/io/channel-tls.h`](file:///project/include/io/channel-tls.h) | [`io/channel-tls.c`](file:///project/io/channel-tls.c) | Subclasses `QIOChannel`. Wraps `tioc->master` (`QIOChannel`) and `tioc->session` (`QCryptoTLSSession`). Orchestrates handshake and I/O. |
| **`QCryptoTLSSession`**| [`include/crypto/tlssession.h`](file:///project/include/crypto/tlssession.h) | [`crypto/tlssession.c`](file:///project/crypto/tlssession.c) | Wraps `gnutls_session_t handle`. Sets priorities, credentials, certificates, authz, and registers push/pull callbacks. |
| **`QCryptoTLSCreds`**  | [`include/crypto/tlscreds.h`](file:///project/include/crypto/tlscreds.h) | [`crypto/tlscreds.c`](file:///project/crypto/tlscreds.c) | Common base object for credentials (`tls-creds-x509`, `tls-creds-anon`, `tls-creds-psk`). |
| **`Migration TLS`**    | [`migration/tls.h`](file:///project/migration/tls.h) | [`migration/tls.c`](file:///project/migration/tls.c) | Helpers to create TLS channels and initiate async handshakes for the main migration channel. |
| **`MultiFD Migration`**| [`migration/multifd.h`](file:///project/migration/multifd.h) | [`migration/multifd.c`](file:///project/migration/multifd.c) | Multi-channel migration engine. Creates independent TLS sessions per channel. |
| **`Post-copy Preempt`**| [`migration/postcopy-ram.h`](file:///project/migration/postcopy-ram.h) | [`migration/postcopy-ram.c`](file:///project/migration/postcopy-ram.c) | Preempt channel establishment with optional TLS upgrade. |
| **`NBD Subsystem`**    | [`include/block/nbd.h`](file:///project/include/block/nbd.h) | [`nbd/client.c`](file:///project/nbd/client.c), [`nbd/server.c`](file:///project/nbd/server.c) | Network Block Device client/server TLS negotiation. |

---

## 3. Detailed Call Chain Traces

### 3.1 Socket Creation & Channel Hierarchy
1. **Outgoing TCP Socket Creation:**
   - [`socket_connect_outgoing()`](file:///project/migration/socket.c#L35) in `migration/socket.c` invokes `qio_channel_socket_connect_async()`.
   - [`qio_channel_socket_new()`](file:///project/io/channel-socket.c#L50) allocates `QIOChannelSocket`.
   - On completion, `sioc->fd` holds the connected non-blocking TCP socket file descriptor.
   - `migration_channel_connect_outgoing()` receives the `ioc` (`QIOChannelSocket`).

2. **Incoming TCP Socket Acceptance:**
   - `socket_accept_incoming()` in `migration/socket.c` runs when the listener socket fires.
   - Creates a new `QIOChannelSocket` for the client connection (`sioc->fd`).
   - Calls `migration_channel_process_incoming(ioc)`.

3. **Wrapping in `QIOChannelTLS`:**
   - Client side: [`migration_tls_client_create()`](file:///project/migration/tls.c#L120) calls:
     ```c
     tioc = qio_channel_tls_new_client(ioc, creds, hostname, errp);
     ```
   - Server side: [`migration_tls_channel_process_incoming()`](file:///project/migration/tls.c#L74) calls:
     ```c
     tioc = qio_channel_tls_new_server(ioc, creds, authzid, errp);
     ```
   - In [`qio_channel_tls_new_client()`](file:///project/io/channel-tls.c#L125) / [`new_server()`](file:///project/io/channel-tls.c#L155):
     - `tioc->master = ioc; object_ref(OBJECT(ioc));`
     - `tioc->session = qcrypto_tls_session_new(...)`
     - Registers transport callbacks:
       ```c
       qcrypto_tls_session_set_callbacks(tioc->session,
                                         qio_channel_tls_write_handler,
                                         qio_channel_tls_read_handler,
                                         tioc);
       ```
   - In [`qcrypto_tls_session_new()`](file:///project/crypto/tlssession.c#L160):
     - Invokes `gnutls_init(&session->handle, ...)`
     - Sets priority string: `gnutls_priority_set_direct(session->handle, prio, ...)`
     - Sets credentials: `gnutls_credentials_set(session->handle, ...)`
     - Binds callbacks:
       ```c
       gnutls_transport_set_ptr(session->handle, session);
       gnutls_transport_set_push_function(session->handle, qcrypto_tls_session_push);
       gnutls_transport_set_pull_function(session->handle, qcrypto_tls_session_pull);
       ```

---

### 3.2 Handshake Initiation and Driving State Machine

1. **Initiation:**
   - [`qio_channel_tls_handshake(tioc, callback, user_data, destroy, context)`](file:///project/io/channel-tls.c#L245) allocates a `QIOTask` and executes [`qio_channel_tls_handshake_task()`](file:///project/io/channel-tls.c#L179).

2. **Step-by-Step Handshake Pump:**
   - `qcrypto_tls_session_handshake(tioc->session, &err)` calls:
     ```c
     ret = gnutls_handshake(session->handle);
     ```
   - If `gnutls_handshake` returns `GNUTLS_E_AGAIN` or `GNUTLS_E_INTERRUPTED`:
     - Direction determined via `gnutls_record_get_direction(session->handle)`:
       - 0 -> `QCRYPTO_TLS_HANDSHAKE_RECV` -> watches `G_IO_IN` on `tioc->master`.
       - 1 -> `QCRYPTO_TLS_HANDSHAKE_SEND` -> watches `G_IO_OUT` on `tioc->master`.
     - `qio_channel_add_watch_full(tioc->master, condition, qio_channel_tls_handshake_io, ...)` arms the glib/AioContext event loop.
     - When the socket becomes readable/writable, `qio_channel_tls_handshake_io()` fires and loops back to `qio_channel_tls_handshake_task()`.

3. **Handshake Ciphertext Transport:**
   - While GnuTLS is driving the handshake, it calls `qcrypto_tls_session_push` / `qcrypto_tls_session_pull`.
   - `qcrypto_tls_session_push()` -> `session->writeFunc()` -> [`qio_channel_tls_write_handler()`](file:///project/io/channel-tls.c#L30):
     ```c
     ret = qio_channel_writev_full(tioc->master, &iov, 1, NULL, 0, 0, errp);
     ```
   - `qcrypto_tls_session_pull()` -> `session->readFunc()` -> [`qio_channel_tls_read_handler()`](file:///project/io/channel-tls.c#L46):
     ```c
     ret = qio_channel_readv_full(tioc->master, &iov, 1, NULL, 0, 0, errp);
     ```

4. **Handshake Completion & Verification:**
   - When `gnutls_handshake` returns 0, `qcrypto_tls_session_handshake` calls:
     ```c
     qcrypto_tls_session_check_certificate(session, errp);
     ```
   - Validates peer certificate chain, hostname verification, expiration, and authorization rule IDs (`authzid`).
   - If successful, returns `QCRYPTO_TLS_HANDSHAKE_COMPLETE`.
   - `qio_channel_tls_handshake_task()` marks the `QIOTask` complete, invoking the user completion callback (e.g., `migration_tls_outgoing_handshake`, `migration_tls_incoming_handshake`, or `multifd_new_send_channel_async`).

---

### 3.3 Post-Handshake Read/Write Data Paths

#### Current Userspace Data Path:
* **Write Path (`qio_channel_writev`):**
  1. Upper layer calls `qio_channel_writev(ioc, iov, niov, ...)` where `ioc` is `QIOChannelTLS`.
  2. Routed to [`qio_channel_tls_writev()`](file:///project/io/channel-tls.c#L440).
  3. Loops through each `iovec`:
     ```c
     ret = qcrypto_tls_session_write(tioc->session, iov[i].iov_base, iov[i].iov_len, errp);
     ```
  4. In [`crypto/tlssession.c`](file:///project/crypto/tlssession.c#L670):
     ```c
     ret = gnutls_record_send(session->handle, buf, len);
     ```
  5. GnuTLS AEAD encrypts the plaintext buffer in userspace memory, formats the TLS record header and auth tag.
  6. GnuTLS invokes callback: `qcrypto_tls_session_push()` -> `qio_channel_tls_write_handler()` -> `qio_channel_writev_full(tioc->master, ...)`.
  7. `QIOChannelSocket` writes the ciphertext to `sioc->fd` via `sendmsg` / `writev`.

* **Read Path (`qio_channel_readv`):**
  1. Upper layer calls `qio_channel_readv(ioc, iov, niov, ...)` on `QIOChannelTLS`.
  2. Routed to [`qio_channel_tls_readv()`](file:///project/io/channel-tls.c#L397).
  3. Loops through `iovec`:
     ```c
     ret = qcrypto_tls_session_read(tioc->session, iov[i].iov_base, iov[i].iov_len, errp);
     ```
  4. In [`crypto/tlssession.c`](file:///project/crypto/tlssession.c#L697):
     ```c
     ret = gnutls_record_recv(session->handle, buf, len);
     ```
  5. GnuTLS invokes callback: `qcrypto_tls_session_pull()` -> `qio_channel_tls_read_handler()` -> `qio_channel_readv_full(tioc->master, ...)`.
  6. GnuTLS AEAD decrypts ciphertext in userspace memory and places plaintext into caller's buffer.

---

## 4. Migration Subsystem Integration & Channels

### 4.1 Pre-Copy Main Channel
- **Source:**
  - `migration_tls_channel_connect(s, ioc, &error)` creates `QIOChannelTLS` over `QIOChannelSocket`.
  - On handshake success: [`migration_channel_connect_outgoing()`](file:///project/migration/channel.c#L240) creates `s->to_dst_file = qemu_file_new_output(ioc)`.
  - All subsequent migration RAM sections and VM state records pass through `qemu_put_buffer()` -> `qio_channel_writev()`.
  - When `migrate_return_path()` or `migrate_postcopy_ram()` is active, `QIO_CHANNEL_FEATURE_CONCURRENT_IO` is asserted on `tioc` for bi-directional communication.
- **Destination:**
  - `migration_channel_process_incoming()` detects `migrate_channel_requires_tls_upgrade(ioc)`.
  - Transitions to `migration_tls_channel_process_incoming()`.
  - On handshake success: Calls `migration_channel_process_incoming(tioc)` again.
  - Channel type identified as `CH_MAIN` via `migration_channel_identify()`.
  - Destination creates `mis->from_src_file = qemu_file_new_input(ioc)` and enters incoming migration loop.

### 4.2 MultiFD Channels
- **Source:**
  - In [`migration/multifd.c`](file:///project/migration/multifd.c#L811), `multifd_tls_channel_connect()` wraps each worker channel's `ioc` in `migration_tls_client_create()`.
  - Each channel starts its own handshake:
    ```c
    qio_channel_tls_handshake(tioc, multifd_new_send_channel_async, args->p, NULL, NULL);
    ```
  - On completion, `p->c = ioc;` (where `p->c` is `QIOChannelTLS`).
  - Worker thread executes [`multifd_send_thread()`](file:///project/migration/multifd.c#L705).
  - RAM page transmission in `multifd_send_thread()`:
    ```c
    ret = qio_channel_writev_full_all(p->c, p->iov, p->iovs_num, NULL, 0, 0, &local_err);
    ```
- **Destination:**
  - Each incoming TCP connection is accepted independently and routed through `migration_channel_process_incoming()`.
  - TLS upgrade is performed per connection.
  - Identified as `CH_MULTIFD`.
  - Passed to `multifd_recv_new_channel(ioc)`.
  - Spawns `multifd_recv_thread()`, which loops on:
    ```c
    ret = qio_channel_read_all_eof(p->c, (void *)p->packet, p->packet_len, &local_err);
    ret = qio_channel_readv_all(p->c, p->iov, p->iovs_num, &local_err);
    ```

### 4.3 Post-Copy Preempt Channel
- Established on demand in [`migration/postcopy-ram.c`](file:///project/migration/postcopy-ram.c#L2220).
- Handshake driven by `postcopy_preempt_tls_handshake()`.
- On completion: assigns `s->postcopy_qemufile_src = qemu_file_new_output(ioc)`.
- Used exclusively for high-priority urgent RAM page transfers during post-copy.

### 4.4 NBD / Block Migration Channel
- Negotiated independently in [`nbd/server.c`](file:///project/nbd/server.c#L799) and [`nbd/client.c`](file:///project/nbd/client.c#L635).
- Upgrades existing `QIOChannelSocket` to `QIOChannelTLS` after initial NBD handshake negotiation flags (`NBD_OPT_STARTTLS`).
- Completely decoupled from VM migration state.

---

## 5. Underlying Socket FD Availability and KTLS Hook Points

### 5.1 Where Socket FD Becomes Available
In `QIOChannelTLS`, the underlying channel is stored in `tioc->master`.
To inspect the socket file descriptor:
```c
QIOChannelSocket *sioc = (QIOChannelSocket *)object_dynamic_cast(OBJECT(tioc->master),
                                                                 TYPE_QIO_CHANNEL_SOCKET);
if (sioc) {
    int fd = sioc->fd; /* Valid TCP socket file descriptor */
}
```
If `tioc->master` is not a `QIOChannelSocket` (e.g., test mocks, buffer channels), `sioc` is NULL, allowing clean and safe bypassing of KTLS.

### 5.2 Recommended Clean KTLS Integration Point
The single best, cleanest, and most maintainable integration point in QEMU is **inside `QIOChannelTLS`** ([io/channel-tls.c](file:///project/io/channel-tls.c)), specifically at the moment the TLS handshake completes:

```
qio_channel_tls_handshake_task(tioc, task, ...)
    |
    +--> status = qcrypto_tls_session_handshake(...)
    |
    +--> if (status == QCRYPTO_TLS_HANDSHAKE_COMPLETE) {
             /* Handshake succeeded, peer authenticated, 0 application bytes sent/received */
             qio_channel_tls_setup_ktls(tioc);
         }
```

### 5.3 Why `QIOChannelTLS` is the Optimal Integration Point
1. **Zero Subsystem Intrusion:**
   Neither `migration/tls.c`, `migration/multifd.c`, `migration/postcopy-ram.c`, nor `nbd/` needs any custom socket ioctls or crypto manipulation. They continue calling `qio_channel_writev()` and `qio_channel_readv()` unchanged.
2. **Encapsulation of Both Layers:**
   `QIOChannelTLS` is the only object that holds both:
   - The transport channel (`tioc->master`), providing access to `sioc->fd`.
   - The cryptographic session (`tioc->session`), providing access to GnuTLS handle and keys.
3. **Transparent Read/Write Fast-Path:**
   When KTLS TX is active on `tioc`:
   `qio_channel_tls_writev()` writes directly to `tioc->master` via `qio_channel_writev_full()`, eliminating userspace GnuTLS crypto copies and locks.
   When KTLS RX is active on `tioc`:
   `qio_channel_tls_readv()` reads directly from `tioc->master` via `qio_channel_readv_full()`.
4. **Opportunistic Fallback:**
   If KTLS setup fails at handshake completion, `tioc->ktls_tx` and `tioc->ktls_rx` remain `false`. `QIOChannelTLS` continues using its existing userspace GnuTLS path without any interruption.

---

## 6. Architectural Couplings, Constraints & Invariants

1. **GnuTLS Custom Pull/Push Incompatibility:**
   GnuTLS's automatic internal KTLS activation explicitly refuses to run when custom push/pull callbacks are registered (`_gnutls_audit_log("Not enabling KTLS with custom pull/push function")`). Therefore, QEMU cannot rely on GnuTLS to configure the socket; QEMU must extract the keys via `gnutls_record_get_state()` and issue the `setsockopt` calls itself.
2. **Clean Termination Invariant (`qio_channel_tls_bye`):**
   When closing a TLS session, `qio_channel_tls_bye()` calls `gnutls_bye()`. When KTLS is active, GnuTLS needs to send `close_notify`. If KTLS is active on the socket, sending a control record requires `TLS_SET_RECORD_TYPE` via `sendmsg` or using GnuTLS's sync state back (`gnutls_record_set_state`). If migration terminates cleanly via TCP shutdown, this must be handled consistently.
3. **Non-Socket Channels:**
   `QIOChannelTLS` must never assume `tioc->master` is a socket without dynamic type verification.
4. **Zero Copy Compatibility:**
   `QIOChannelSocket` has existing zero-copy features (`sioc->zero_copy_queued`). KTLS TX supports `TLS_TX_ZEROCOPY_RO` on Linux kernels supporting zerocopy offload. Standard scatter-gather `writev()` into a KTLS socket immediately benefits from single-copy kernel crypto.
