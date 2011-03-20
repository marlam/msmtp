/*
 * tls.h
 *
 * This file is part of msmtp, an SMTP client.
 *
 * Copyright (C) 2000, 2003, 2004, 2005, 2006, 2007, 2008, 2010
 * Martin Lambers <marlam@marlam.de>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef TLS_H
#define TLS_H

#ifdef HAVE_LIBGNUTLS
# include <gnutls/gnutls.h>
#endif /* HAVE_LIBGNUTLS */
#ifdef HAVE_LIBSSL
# include <openssl/ssl.h>
#endif /* HAVE_LIBSSL */

#include "readbuf.h"


/*
 * If a function with an 'errstr' argument returns a value != TLS_EOK,
 * '*errstr' either points to an allocates string containing an error
 * description or is NULL.
 * If such a function returns TLS_EOK, 'errstr' will not be changed.
 */
#define TLS_EOK         0       /* no error */
#define TLS_ELIBFAILED  1       /* The underlying library failed */
#define TLS_ESEED       2       /* Cannot seed pseudo random number generator */
#define TLS_ECERT       3       /* Certificate check or verification failed */
#define TLS_EIO         4       /* Input/output error */
#define TLS_EFILE       5       /* A file does not exist/cannot be read */
#define TLS_EHANDSHAKE  6       /* TLS handshake failed */

/*
 * Always use tls_clear() before using a tls_t!
 * Never call a tls_*() function with tls_t NULL!
 */

typedef struct
{
    int is_active;
    int have_trust_file;
    int have_sha1_fingerprint;
    int have_md5_fingerprint;
    unsigned char fingerprint[20];
#ifdef HAVE_LIBGNUTLS
    gnutls_session_t session;
    gnutls_certificate_credentials_t cred;
#endif /* HAVE_LIBGNUTLS */
#ifdef HAVE_LIBSSL
    SSL_CTX *ssl_ctx;
    SSL *ssl;
#endif /* HAVE_LIBSSL */
} tls_t;

/*
 * Information about a X509 certificate.
 * The 6 owner_info and issuer_info fields are:
 *   Common Name
 *   Organization
 *   Organizational unit
 *   Locality
 *   State/Province
 *   Country
 * Each of these entries may be NULL if it was not provided.
 */
typedef struct
{
    unsigned char sha1_fingerprint[20];
    unsigned char md5_fingerprint[16];
    time_t activation_time;
    time_t expiration_time;
    char *owner_info[6];
    char *issuer_info[6];
} tls_cert_info_t;

/*
 * tls_lib_init()
 *
 * Initialize underlying TLS library. If this function returns TLS_ELIBFAILED,
 * *errstr will always point to an error string.
 * Used error codes: TLS_ELIBFAILED
 */
int tls_lib_init(char **errstr);

/*
 * tls_clear()
 *
 * Clears a tls_t type (marks it inactive).
 */
void tls_clear(tls_t *tls);

/*
 * tls_init()
 *
 * Initializes a tls_t. If both 'key_file' and 'cert_file' are not NULL, they
 * are set to be used when the peer request a certificate. If 'trust_file' is
 * not NULL, it will be used to verify the peer certificate. If additionally
 * 'crl_file' is not NULL, then this file will be used during verification to
 * check if a certificate has been revoked. If 'trust_file' is NULL and one of
 * 'sha1_fingerprint' or 'md5_fingerprint' is not NULL, then the fingerprint of
 * the peer certificate will be compared to the given fingerprint and the
 * certificate is trusted when they match.
 * All files must be in PEM format.
 * If 'force_sslv3' is set, then only the SSLv3 protocol will be accepted. This
 * option might be needed to talk to some obsolete broken servers. Only use this
 * if you have to.
 * If 'min_dh_prime_bits' is greater than or equal to zero, then only DH primes
 * that have at least the given size will be accepted. For values less than
 * zero, the library default is used.
 * If 'priorities' is not NULL, it must contain a string describing the TLS
 * priorities. This is library dependent; see gnutls_priority_init().
 * Used error codes: TLS_ELIBFAILED, TLS_EFILE
 */
int tls_init(tls_t *tls,
        const char *key_file, const char *cert_file,
        const char *trust_file, const char *crl_file,
        const unsigned char *sha1_fingerprint,
        const unsigned char *md5_fingerprint,
        int force_sslv3, int min_dh_prime_bits, const char *priorities,
        char **errstr);

/*
 * tls_start()
 *
 * Starts TLS encryption on a socket.
 * 'tls' must be initialized using tls_init().
 * If 'no_certcheck' is true, then no checks will be performed on the peer
 * certificate. If it is false and no trust file was set with tls_init(),
 * only sanity checks are performed on the peer certificate. If it is false
 * and a trust file was set, real verification of the peer certificate is
 * performed.
 * 'hostname' is the host to start TLS with. It is needed for sanity checks/
 * verification.
 * 'tci' must be allocated with tls_cert_info_new(). Information about the
 * peer's certificata will be stored in it. It can later be freed with
 * tls_cert_info_free(). 'tci' is allowed to be NULL; no certificate
 * information will be passed in this case.
 * Used error codes: TLS_ELIBFAILED, TLS_ECERT, TLS_EHANDSHAKE
 */
int tls_start(tls_t *tls, int fd, const char *hostname, int no_certcheck,
        tls_cert_info_t *tci, char **errstr);

/*
 * tls_is_active()
 *
 * Returns whether 'tls' is an active TLS connection.
 */
int tls_is_active(tls_t *tls);

/*
 * tls_cert_info_new()
 * Returns a new tls_cert_info_t
 */
tls_cert_info_t *tls_cert_info_new(void);

/*
 * tls_cert_info_free()
 * Frees a tls_cert_info_t
 */
void tls_cert_info_free(tls_cert_info_t *tci);

/*
 * tls_cert_info_get()
 *
 * Extracts certificate information from the TLS connection 'tls' and stores
 * it in 'tci'. See the description of tls_cert_info_t above.
 * Used error codes: TLS_ECERT
 */
int tls_cert_info_get(tls_t *tls, tls_cert_info_t *tci, char **errstr);

/*
 * tls_gets()
 *
 * Reads in at most one less than 'size' characters from 'tls' and stores them
 * into the buffer pointed 'str'. Reading stops after an EOF or a newline.
 * If a newline is read, it is stored into the buffer. A '\0' is stored after
 * the last character in the buffer. The length of the resulting string (the
 * number of characters excluding the terminating '\0') will be stored in 'len'.
 * 'readbuf' will be used as an input buffer and must of course be the same for
 * all read operations on 'tls'.
 * Used error codes: TLS_EIO
 */
int tls_gets(tls_t *tls, readbuf_t *readbuf,
        char *str, size_t size, size_t *len, char **errstr);

/*
 * tls_puts()
 *
 * Writes 'len' characters from the string 's' using TLS.
 * Used error codes: TLS_EIO
 */
int tls_puts(tls_t *tls, const char *s, size_t len, char **errstr);

/*
 * tls_close()
 *
 * Close a TLS connection and mark it inactive
 */
void tls_close(tls_t *tls);

/*
 * tls_lib_deinit()
 *
 * Deinit underlying TLS library.
 */
void tls_lib_deinit(void);

#endif
