/*
 * QEMU I/O channel TLS test
 *
 * Copyright (C) 2015 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */


#include "qemu/osdep.h"

#include "crypto-tls-x509-helpers.h"
#include "io/channel-tls.h"
#include "io/channel-socket.h"
#include "io-channel-helpers.h"
#include "crypto/init.h"
#include "crypto/tlscredsx509.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "authz/list.h"
#include "qom/object_interfaces.h"

#define WORKDIR "tests/test-io-channel-tls-work/"
#define KEYFILE WORKDIR "key-ctx.pem"

struct QIOChannelTLSTestData {
    const char *servercacrt;
    const char *clientcacrt;
    const char *servercrt;
    const char *clientcrt;
    bool expectServerFail;
    bool expectClientFail;
    const char *hostname;
    const char *const *wildcards;
    bool use_tcp;
    bool disable_ktls;
    bool expect_ktls;
};

struct QIOChannelTLSHandshakeData {
    bool finished;
    bool failed;
};

static void test_tls_handshake_done(QIOTask *task,
                                    gpointer opaque)
{
    struct QIOChannelTLSHandshakeData *data = opaque;

    data->finished = true;
    data->failed = qio_task_propagate_error(task, NULL);
}


static QCryptoTLSCreds *test_tls_creds_create(QCryptoTLSCredsEndpoint endpoint,
                                              const char *certdir)
{
    Object *parent = object_get_objects_root();
    Object *creds = object_new_with_props(
        TYPE_QCRYPTO_TLS_CREDS_X509,
        parent,
        (endpoint == QCRYPTO_TLS_CREDS_ENDPOINT_SERVER ?
         "testtlscredsserver" : "testtlscredsclient"),
        &error_abort,
        "endpoint", (endpoint == QCRYPTO_TLS_CREDS_ENDPOINT_SERVER ?
                     "server" : "client"),
        "dir", certdir,
        "verify-peer", "yes",
        "priority", "NORMAL",
        /* We skip initial sanity checks here because we
         * want to make sure that problems are being
         * detected at the TLS session validation stage,
         * and the test-crypto-tlscreds test already
         * validate the sanity check code.
         */
        "sanity-check", "no",
        NULL
        );

    return QCRYPTO_TLS_CREDS(creds);
}


/*
 * This tests validation checking of peer certificates
 *
 * This is replicating the checks that are done for an
 * active TLS session after handshake completes. To
 * simulate that we create our TLS contexts, skipping
 * sanity checks. When then get a socketpair, and
 * initiate a TLS session across them. Finally do
 * do actual cert validation tests
 */
static void test_io_channel_tls(const void *opaque)
{
    struct QIOChannelTLSTestData *data =
        (struct QIOChannelTLSTestData *)opaque;
    QCryptoTLSCreds *clientCreds;
    QCryptoTLSCreds *serverCreds;
    QIOChannelTLS *clientChanTLS;
    QIOChannelTLS *serverChanTLS;
    QIOChannelSocket *clientChanSock;
    QIOChannelSocket *serverChanSock;
    QAuthZList *auth;
    const char * const *wildcards;
    int channel[2] = { -1, -1 };
    QIOChannelSocket *listenSock = NULL;
    struct QIOChannelTLSHandshakeData clientHandshake = { false, false };
    struct QIOChannelTLSHandshakeData serverHandshake = { false, false };
    QIOChannelTest *test;
    GMainContext *mainloop;

#define CLIENT_CERT_DIR "tests/test-io-channel-tls-client/"
#define SERVER_CERT_DIR "tests/test-io-channel-tls-server/"
    g_mkdir_with_parents(CLIENT_CERT_DIR, 0700);
    g_mkdir_with_parents(SERVER_CERT_DIR, 0700);

    unlink(SERVER_CERT_DIR QCRYPTO_TLS_CREDS_X509_CA_CERT);
    unlink(SERVER_CERT_DIR QCRYPTO_TLS_CREDS_X509_SERVER_CERT);
    unlink(SERVER_CERT_DIR QCRYPTO_TLS_CREDS_X509_SERVER_KEY);

    unlink(CLIENT_CERT_DIR QCRYPTO_TLS_CREDS_X509_CA_CERT);
    unlink(CLIENT_CERT_DIR QCRYPTO_TLS_CREDS_X509_CLIENT_CERT);
    unlink(CLIENT_CERT_DIR QCRYPTO_TLS_CREDS_X509_CLIENT_KEY);

    g_assert(link(data->servercacrt,
                  SERVER_CERT_DIR QCRYPTO_TLS_CREDS_X509_CA_CERT) == 0);
    g_assert(link(data->servercrt,
                  SERVER_CERT_DIR QCRYPTO_TLS_CREDS_X509_SERVER_CERT) == 0);
    g_assert(link(KEYFILE,
                  SERVER_CERT_DIR QCRYPTO_TLS_CREDS_X509_SERVER_KEY) == 0);

    g_assert(link(data->clientcacrt,
                  CLIENT_CERT_DIR QCRYPTO_TLS_CREDS_X509_CA_CERT) == 0);
    g_assert(link(data->clientcrt,
                  CLIENT_CERT_DIR QCRYPTO_TLS_CREDS_X509_CLIENT_CERT) == 0);
    g_assert(link(KEYFILE,
                  CLIENT_CERT_DIR QCRYPTO_TLS_CREDS_X509_CLIENT_KEY) == 0);

    clientCreds = test_tls_creds_create(
        QCRYPTO_TLS_CREDS_ENDPOINT_CLIENT,
        CLIENT_CERT_DIR);
    g_assert(clientCreds != NULL);

    serverCreds = test_tls_creds_create(
        QCRYPTO_TLS_CREDS_ENDPOINT_SERVER,
        SERVER_CERT_DIR);
    g_assert(serverCreds != NULL);

    auth = qauthz_list_new("channeltlsacl",
                           QAUTHZ_LIST_POLICY_DENY,
                           &error_abort);
    wildcards = data->wildcards;
    while (wildcards && *wildcards) {
        qauthz_list_append_rule(auth, *wildcards,
                                QAUTHZ_LIST_POLICY_ALLOW,
                                QAUTHZ_LIST_FORMAT_GLOB,
                                &error_abort);
        wildcards++;
    }

    if (data->use_tcp) {
        SocketAddress *listen_addr = g_new0(SocketAddress, 1);
        SocketAddress *connect_addr = g_new0(SocketAddress, 1);
        SocketAddress *laddr;

        listenSock = qio_channel_socket_new();
        listen_addr->type = SOCKET_ADDRESS_TYPE_INET;
        listen_addr->u.inet = (InetSocketAddress) {
            .host = g_strdup("127.0.0.1"),
            .port = NULL,
        };
        qio_channel_socket_listen_sync(listenSock, listen_addr,
                                       1, &error_abort);

        laddr = qio_channel_socket_get_local_address(listenSock, &error_abort);
        connect_addr->type = SOCKET_ADDRESS_TYPE_INET;
        connect_addr->u.inet = (InetSocketAddress) {
            .host = g_strdup("127.0.0.1"),
            .port = g_strdup(laddr->u.inet.port),
        };
        qapi_free_SocketAddress(laddr);

        clientChanSock = qio_channel_socket_new();
        qio_channel_socket_connect_sync(clientChanSock, connect_addr,
                                        &error_abort);
        qio_channel_set_delay(QIO_CHANNEL(clientChanSock), false);

        qio_channel_wait(QIO_CHANNEL(listenSock), G_IO_IN);
        serverChanSock = qio_channel_socket_accept(listenSock, &error_abort);
        g_assert(serverChanSock != NULL);

        qapi_free_SocketAddress(listen_addr);
        qapi_free_SocketAddress(connect_addr);
    } else {
        g_assert(qemu_socketpair(AF_UNIX, SOCK_STREAM, 0, channel) == 0);
        clientChanSock = qio_channel_socket_new_fd(
            channel[0], &error_abort);
        g_assert(clientChanSock != NULL);
        serverChanSock = qio_channel_socket_new_fd(
            channel[1], &error_abort);
        g_assert(serverChanSock != NULL);
    }

    /*
     * We have an evil loop to do the handshake in a single
     * thread, so we need these non-blocking to avoid deadlock
     * of ourselves
     */
    qio_channel_set_blocking(QIO_CHANNEL(clientChanSock), false, &error_abort);
    qio_channel_set_blocking(QIO_CHANNEL(serverChanSock), false, &error_abort);

    /* Now the real part of the test, setup the sessions */
    clientChanTLS = qio_channel_tls_new_client(
        QIO_CHANNEL(clientChanSock), clientCreds,
        data->hostname, &error_abort);
    g_assert(clientChanTLS != NULL);

    serverChanTLS = qio_channel_tls_new_server(
        QIO_CHANNEL(serverChanSock), serverCreds,
        "channeltlsacl", &error_abort);
    g_assert(serverChanTLS != NULL);

    if (data->disable_ktls) {
        qio_channel_tls_set_ktls_enabled(clientChanTLS, false);
        qio_channel_tls_set_ktls_enabled(serverChanTLS, false);
    }

    qio_channel_tls_handshake(clientChanTLS,
                              test_tls_handshake_done,
                              &clientHandshake,
                              NULL,
                              NULL);
    qio_channel_tls_handshake(serverChanTLS,
                              test_tls_handshake_done,
                              &serverHandshake,
                              NULL,
                              NULL);

    /*
     * Finally we loop around & around doing handshake on each
     * session until we get an error, or the handshake completes.
     * This relies on the socketpair being nonblocking to avoid
     * deadlocking ourselves upon handshake
     */
    mainloop = g_main_context_default();
    do {
        g_main_context_iteration(mainloop, TRUE);
    } while (!clientHandshake.finished ||
             !serverHandshake.finished);

    g_assert(clientHandshake.failed == data->expectClientFail);
    g_assert(serverHandshake.failed == data->expectServerFail);

    if (!clientHandshake.failed && !serverHandshake.failed) {
        bool c_tx = false, c_rx = false, s_tx = false, s_rx = false;
        qio_channel_tls_is_ktls_active(clientChanTLS, &c_tx, &c_rx);
        qio_channel_tls_is_ktls_active(serverChanTLS, &s_tx, &s_rx);

        if (data->expect_ktls) {
            g_assert(c_tx && c_rx);
            g_assert(s_tx && s_rx);
        } else if (data->disable_ktls || !data->use_tcp) {
            g_assert(!c_tx && !c_rx);
            g_assert(!s_tx && !s_rx);
        }
    }

    test = qio_channel_test_new();
    qio_channel_test_run_threads(test, false,
                                 QIO_CHANNEL(clientChanTLS),
                                 QIO_CHANNEL(serverChanTLS));
    qio_channel_test_validate(test);

    test = qio_channel_test_new();
    qio_channel_test_run_threads(test, true,
                                 QIO_CHANNEL(clientChanTLS),
                                 QIO_CHANNEL(serverChanTLS));
    qio_channel_test_validate(test);

    unlink(SERVER_CERT_DIR QCRYPTO_TLS_CREDS_X509_CA_CERT);
    unlink(SERVER_CERT_DIR QCRYPTO_TLS_CREDS_X509_SERVER_CERT);
    unlink(SERVER_CERT_DIR QCRYPTO_TLS_CREDS_X509_SERVER_KEY);

    unlink(CLIENT_CERT_DIR QCRYPTO_TLS_CREDS_X509_CA_CERT);
    unlink(CLIENT_CERT_DIR QCRYPTO_TLS_CREDS_X509_CLIENT_CERT);
    unlink(CLIENT_CERT_DIR QCRYPTO_TLS_CREDS_X509_CLIENT_KEY);

    rmdir(CLIENT_CERT_DIR);
    rmdir(SERVER_CERT_DIR);

    object_unparent(OBJECT(serverCreds));
    object_unparent(OBJECT(clientCreds));

    object_unref(OBJECT(serverChanTLS));
    object_unref(OBJECT(clientChanTLS));

    object_unref(OBJECT(serverChanSock));
    object_unref(OBJECT(clientChanSock));

    object_unparent(OBJECT(auth));

    if (listenSock) {
        object_unref(OBJECT(listenSock));
    }
    if (channel[0] != -1) {
        close(channel[0]);
    }
    if (channel[1] != -1) {
        close(channel[1]);
    }
}


int main(int argc, char **argv)
{
    int ret;

    g_assert(qcrypto_init(NULL) == 0);

    module_call_init(MODULE_INIT_QOM);
    g_test_init(&argc, &argv, NULL);
    g_setenv("GNUTLS_FORCE_FIPS_MODE", "2", 1);

    g_mkdir_with_parents(WORKDIR, 0700);

    test_tls_init(KEYFILE);

# define TEST_CHANNEL(name, caCrt,                                      \
                      serverCrt, clientCrt,                             \
                      expectServerFail, expectClientFail,               \
                      hostname, wildcards)                              \
    struct QIOChannelTLSTestData name = {                               \
        caCrt, caCrt, serverCrt, clientCrt,                             \
        expectServerFail, expectClientFail,                             \
        hostname, wildcards, false, false, false                        \
    };                                                                  \
    g_test_add_data_func("/qio/channel/tls/" # name,                    \
                         &name, test_io_channel_tls);

# define TEST_CHANNEL_KTLS(name, caCrt,                                 \
                           serverCrt, clientCrt,                        \
                           expectServerFail, expectClientFail,          \
                           hostname, wildcards,                         \
                           disableKtls, expectKtls)                     \
    struct QIOChannelTLSTestData name = {                               \
        caCrt, caCrt, serverCrt, clientCrt,                             \
        expectServerFail, expectClientFail,                             \
        hostname, wildcards, true, disableKtls, expectKtls              \
    };                                                                  \
    g_test_add_data_func("/qio/channel/tls/" # name,                    \
                         &name, test_io_channel_tls);

    /* A perfect CA, perfect client & perfect server */

    /* Basic:CA:critical */
    TLS_ROOT_REQ(cacertreq,
                 "UK", "qemu CA", NULL, NULL, NULL, NULL,
                 true, true, true,
                 true, true, GNUTLS_KEY_KEY_CERT_SIGN,
                 false, false, NULL, NULL,
                 0, 0);
    TLS_CERT_REQ(servercertreq, cacertreq,
                 "UK", "qemu.org", NULL, NULL, NULL, NULL,
                 true, true, false,
                 true, true,
                 GNUTLS_KEY_DIGITAL_SIGNATURE,
                 true, true, GNUTLS_KP_TLS_WWW_SERVER, NULL,
                 0, 0);
    TLS_CERT_REQ(clientcertreq, cacertreq,
                 "UK", "qemu", NULL, NULL, NULL, NULL,
                 true, true, false,
                 true, true,
                 GNUTLS_KEY_DIGITAL_SIGNATURE,
                 true, true, GNUTLS_KP_TLS_WWW_CLIENT, NULL,
                 0, 0);

    const char *const wildcards[] = {
        "C=UK,CN=qemu*",
        NULL,
    };
    TEST_CHANNEL(basic, cacertreq.filename, servercertreq.filename,
                 clientcertreq.filename, false, false,
                 "qemu.org", wildcards);

    TEST_CHANNEL_KTLS(ktls_tcp, cacertreq.filename, servercertreq.filename,
                      clientcertreq.filename, false, false,
                      "qemu.org", wildcards, false, true);

    TEST_CHANNEL_KTLS(ktls_disabled, cacertreq.filename, servercertreq.filename,
                      clientcertreq.filename, false, false,
                      "qemu.org", wildcards, true, false);

    ret = g_test_run();

    test_tls_discard_cert(&clientcertreq);
    test_tls_discard_cert(&servercertreq);
    test_tls_discard_cert(&cacertreq);

    test_tls_cleanup(KEYFILE);
    rmdir(WORKDIR);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
