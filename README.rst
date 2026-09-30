==============================================
QEMU with Kernel TLS (KTLS) Offload Support
==============================================

This repository is an experimental fork of `QEMU <https://github.com/qemu/qemu>`_
maintained for prototyping, evaluating, and benchmarking **Kernel TLS (KTLS) Offload**
in QEMU virtualization workflows.

This fork introduces zero-copy kernel-space TLS cryptographic offload for QEMU's
I/O channels, focusing on high-throughput live migration (including MultiFD and
Post-Copy) over encrypted TCP connections.


About Kernel TLS (KTLS) Offload
===============================

What is KTLS?
-------------
Standard TLS in QEMU is performed in userspace by GnuTLS. Every byte sent or
received over TLS must be copied into userspace buffers, encrypted/decrypted on
the host CPU cores, framed into TLS records, and copied back into kernel socket
buffers. At multi-gigabit and 100GbE network speeds, this userspace cryptographic
pipeline becomes a major CPU bottleneck.

**Kernel TLS (KTLS)** offloads the symmetric encryption, decryption, and record
framing directly into the Linux kernel network stack (via ``tls.ko``) or down to
compatible network interface cards (NICs) supporting inline hardware TLS offload
(e.g., NVIDIA/Mellanox ConnectX, Intel).

How it Works in this Repository
-------------------------------
1. **Standard Handshake in Userspace**: GnuTLS executes the TLS handshake,
   certificate validation, and session negotiation in userspace as normal.
2. **Cryptographic State Export**: Once the handshake successfully completes,
   QEMU queries the session parameters (ciphers, keys, IVs, sequence numbers)
   from GnuTLS via ``gnutls_record_get_state()``.
3. **Kernel Socket ULP Attachment**: QEMU attaches the ``tls`` Upper Layer
   Protocol (ULP) to the connected TCP socket (``TCP_ULP``) and installs the
   TX/RX crypto context using ``setsockopt(..., SOL_TLS, ...)``.
4. **Zero-Copy Fast-Path**: Subsequent ``readv`` and ``writev`` operations on
   ``QIOChannelTLS`` bypass userspace encryption/decryption routines entirely,
   streaming data directly through the master socket.
5. **Opportunistic Fallback**: If the socket is non-TCP (e.g. UNIX domain socket),
   the kernel module is unavailable, or the cipher is unsupported, QEMU
   transparently falls back to userspace GnuTLS. There is **no plaintext fallback**
   under any circumstances.

Supported Ciphers & Protocols:
- **Protocols**: TLS 1.2, TLS 1.3
- **Ciphers**: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305


Operator Quickstart Guide
=========================

1. Host Prerequisites
---------------------
* **Linux Kernel**: Version 4.13 or newer (kernel >= 5.1 recommended for TLS 1.3).
* **Kernel Module**: The ``tls`` kernel module must be loaded:

  .. code-block:: shell

     sudo modprobe tls

  Verify that the module is active:

  .. code-block:: shell

     lsmod | grep tls

* **Libraries**: GnuTLS development headers (``libgnutls28-dev`` on Debian/Ubuntu,
  ``gnutls-devel`` on Fedora/RHEL).

2. Building QEMU
----------------
Configure and build QEMU with GnuTLS support enabled:

.. code-block:: shell

   mkdir build && cd build
   ../configure --target-list=x86_64-softmmu --enable-gnutls
   ninja qemu-system-x86_64 tests/unit/test-io-channel-tls

3. Running Unit & Integration Tests
-----------------------------------
Verify that KTLS is functioning properly on your host kernel using the test suite:

.. code-block:: shell

   ./build/tests/unit/test-io-channel-tls

Expected output:

.. code-block:: text

   TAP version 14
   1..3
   # Start of qio tests
   # Start of channel tests
   # Start of tls tests
   ok 1 /qio/channel/tls/basic
   ok 2 /qio/channel/tls/ktls_tcp
   ok 3 /qio/channel/tls/ktls_disabled
   # End of tls tests
   # End of channel tests
   # End of qio tests


Configuring & Using KTLS in Live Migration
==========================================

KTLS offload is enabled by default in QEMU migration whenever TLS credentials
are configured.

1. Defining TLS Credentials
---------------------------
Define standard QEMU x509 TLS certificate credentials on the QEMU command line:

.. code-block:: shell

   qemu-system-x86_64 ... \
     -object tls-creds-x509,id=tls0,dir=/etc/pki/qemu,endpoint=client,verify-peer=yes

2. Checking Migration Parameters via QMP
----------------------------------------
Query the migration parameters to inspect the status of ``tls-ktls``:

.. code-block:: json

   {"execute": "qmp_capabilities"}
   {"execute": "query-migrate-parameters"}

Response will include:

.. code-block:: json

   {
     "return": {
       "tls-ktls": true,
       "tls-creds": "tls0",
       ...
     }
   }

3. Toggling KTLS Offload at Runtime
-----------------------------------
To explicitly enable or disable KTLS offload via QMP:

* **Disable KTLS (force userspace GnuTLS encryption)**:

  .. code-block:: json

     {"execute": "migrate-set-parameters", "arguments": {"tls-ktls": false}}

* **Enable KTLS (opportunistic kernel offload)**:

  .. code-block:: json

     {"execute": "migrate-set-parameters", "arguments": {"tls-ktls": true}}

4. MultiFD TLS Migration with KTLS
----------------------------------
Combine KTLS with MultiFD migration for maximum throughput across high-speed links:

.. code-block:: json

   {"execute": "migrate-set-capabilities", "arguments": {"capabilities": [{"capability": "multifd", "state": true}]}}
   {"execute": "migrate-set-parameters", "arguments": {"multifd-channels": 8, "tls-creds": "tls0", "tls-ktls": true}}
   {"execute": "migrate", "arguments": {"uri": "tcp:destination-host.example.com:49152"}}


Observability and Diagnostics
=============================

QEMU Tracing
------------
Monitor KTLS establishment and fast-path execution using QEMU trace points:

.. code-block:: shell

   qemu-system-x86_64 ... \
     -trace "qcrypto_tls_session_ktls*" \
     -trace "qio_channel_tls_ktls*"

* ``qcrypto_tls_session_ktls_enable``: Emitted when keys are transferred and ``SOL_TLS`` succeeds.
* ``qcrypto_tls_session_ktls_fail``: Emitted if KTLS setup fails and userspace fallback is triggered.
* ``qio_channel_tls_ktls_setup``: Emitted when a TLS channel enables TX and/or RX offload.
* ``qio_channel_tls_ktls_fastpath``: Emitted when data frames bypass userspace encryption.

Kernel Socket Diagnostics
-------------------------
Inspect active TCP sockets on the Linux host to verify that the TLS ULP is attached:

.. code-block:: shell

   ss -t --ulp

Check host-wide KTLS packet and byte counters:

.. code-block:: shell

   nstat -a | grep -i tls
   cat /proc/net/tls_stat
