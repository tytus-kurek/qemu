/*
 * QEMU Linux KTLS definitions
 *
 * Copyright (c) 2026 Canonical Ltd. / QEMU contributors
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * (at your option) any later version. See the COPYING file in the
 * top-level directory.
 */

#ifndef QCRYPTO_KTLS_LINUX_H
#define QCRYPTO_KTLS_LINUX_H

#ifdef __linux__
#include <linux/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

#if defined(__has_include)
#if __has_include("linux/tls.h")
#include <linux/tls.h>
#endif
#endif

#ifndef TCP_ULP
#define TCP_ULP 31
#endif

#ifndef SOL_TLS
#define SOL_TLS 282
#endif

#ifndef TLS_TX
#define TLS_TX 1
#endif

#ifndef TLS_RX
#define TLS_RX 2
#endif

#ifndef TLS_1_2_VERSION
#define TLS_1_2_VERSION 0x0303
#endif

#ifndef TLS_1_3_VERSION
#define TLS_1_3_VERSION 0x0304
#endif

#ifndef TLS_CIPHER_AES_GCM_128
#define TLS_CIPHER_AES_GCM_128 51
#define TLS_CIPHER_AES_GCM_128_IV_SIZE 8
#define TLS_CIPHER_AES_GCM_128_KEY_SIZE 16
#define TLS_CIPHER_AES_GCM_128_SALT_SIZE 4
#define TLS_CIPHER_AES_GCM_128_TAG_SIZE 16
#define TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE 8

#define TLS_CIPHER_AES_GCM_256 52
#define TLS_CIPHER_AES_GCM_256_IV_SIZE 8
#define TLS_CIPHER_AES_GCM_256_KEY_SIZE 32
#define TLS_CIPHER_AES_GCM_256_SALT_SIZE 4
#define TLS_CIPHER_AES_GCM_256_TAG_SIZE 16
#define TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE 8

#define TLS_CIPHER_CHACHA20_POLY1305 54
#define TLS_CIPHER_CHACHA20_POLY1305_IV_SIZE 12
#define TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE 32
#define TLS_CIPHER_CHACHA20_POLY1305_SALT_SIZE 0
#define TLS_CIPHER_CHACHA20_POLY1305_TAG_SIZE 16
#define TLS_CIPHER_CHACHA20_POLY1305_REC_SEQ_SIZE 8

struct tls_crypto_info {
    __u16 version;
    __u16 cipher_type;
};

struct tls12_crypto_info_aes_gcm_128 {
    struct tls_crypto_info info;
    unsigned char iv[TLS_CIPHER_AES_GCM_128_IV_SIZE];
    unsigned char key[TLS_CIPHER_AES_GCM_128_KEY_SIZE];
    unsigned char salt[TLS_CIPHER_AES_GCM_128_SALT_SIZE];
    unsigned char rec_seq[TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE];
};

struct tls12_crypto_info_aes_gcm_256 {
    struct tls_crypto_info info;
    unsigned char iv[TLS_CIPHER_AES_GCM_256_IV_SIZE];
    unsigned char key[TLS_CIPHER_AES_GCM_256_KEY_SIZE];
    unsigned char salt[TLS_CIPHER_AES_GCM_256_SALT_SIZE];
    unsigned char rec_seq[TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE];
};

struct tls12_crypto_info_chacha20_poly1305 {
    struct tls_crypto_info info;
    unsigned char iv[TLS_CIPHER_CHACHA20_POLY1305_IV_SIZE];
    unsigned char key[TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE];
    unsigned char salt[TLS_CIPHER_CHACHA20_POLY1305_SALT_SIZE];
    unsigned char rec_seq[TLS_CIPHER_CHACHA20_POLY1305_REC_SEQ_SIZE];
};
#endif /* TLS_CIPHER_AES_GCM_128 */

#endif /* __linux__ */

#endif /* QCRYPTO_KTLS_LINUX_H */
