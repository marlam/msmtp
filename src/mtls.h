/*
 * mtls.h
 *
 * This file is part of msmtp, an SMTP client.
 *
 * Copyright (C) 2000, 2003, 2004, 2005, 2006, 2007, 2008, 2010, 2014, 2016,
 * 2018, 2019, 2020
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

#ifndef MTLS_H
#define MTLS_H

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

struct mtls_internals_t;

typedef struct
{
    int is_active;
    int have_trust_file;
    int have_sha256_fingerprint;
    int have_sha1_fingerprint;
    int have_md5_fingerprint;
    unsigned char fingerprint[32];
    int no_certcheck;
    char *hostname;
    struct mtls_internals_t *internals;
} mtls_t;

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
    unsigned char sha256_fingerprint[32];
    unsigned char sha1_fingerprint[20];
    time_t activation_time;
    time_t expiration_time;
    char *owner_info[6];
    char *issuer_info[6];
} mtls_cert_info_t;

/*
 * mtls_lib_init()
 *
 * Initialize underlying TLS library. If this function returns TLS_ELIBFAILED,
 * *errstr will always point to an error string.
 * Used error codes: TLS_ELIBFAILED
 */
int mtls_lib_init(char **errstr);

/*
 * mtls_clear()
 *
 * Clears a mtls_t type (marks it inactive).
 */
void mtls_clear(mtls_t *mtls);

/*
 * mtls_init()
 *
 * Initializes a mtls_t. If both 'key_file' and 'cert_file' are not NULL, they
 * are set to be used when the peer request a certificate.
 * If 'key_file' and 'cert_file' are PKCS11 URIS, a PIN might be needed to access
 * e.g. a smart card; this must be given in 'pin' (which can be NULL if there is no PIN).
 * If 'trust_file' is
 * not NULL, it will be used to verify the peer certificate. If additionally
 * 'crl_file' is not NULL, then this file will be used during verification to
 * check if a certificate has been revoked. If 'trust_file' is NULL and one of
 * 'sha256_fingerprint' or 'sha1_fingerprint' or 'md5_fingerprint' is not NULL,
 * then the fingerprint of the peer certificate will be compared to the given
 * fingerprint and the certificate is trusted when they match.
 * All files must be in PEM format.
 * If 'min_dh_prime_bits' is greater than or equal to zero, then only DH primes
 * that have at least the given size will be accepted. For values less than
 * zero, the library default is used.
 * If 'priorities' is not NULL, it must contain a string describing the TLS
 * priorities. This is library dependent; see gnutls_priority_init().
 * 'hostname' is the host to start TLS with. It is needed for sanity checks/
 * verification.
 * If 'no_certcheck' is true, then no checks will be performed on the peer
 * certificate. If it is false and no trust file was set with mtls_init(),
 * only sanity checks are performed on the peer certificate. If it is false
 * and a trust file was set, real verification of the peer certificate is
 * performed.
 * Used error codes: TLS_ELIBFAILED, TLS_EFILE
 */
int mtls_init(mtls_t *mtls,
        const char *key_file, const char *cert_file, const char* pin,
        const char *trust_file, const char *crl_file,
        const unsigned char *sha256_fingerprint,
        const unsigned char *sha1_fingerprint,
        const unsigned char *md5_fingerprint,
        int min_dh_prime_bits, const char *priorities,
        const char *hostname,
        int no_certcheck,
        char **errstr);

/*
 * mtls_start()
 *
 * Starts TLS encryption on a socket.
 * 'mtls' must be initialized using mtls_init().
 * 'tci' must be allocated with mtls_cert_info_new(). Information about the
 * peer's certificata will be stored in it. It can later be freed with
 * mtls_cert_info_free(). 'tci' is allowed to be NULL; no certificate
 * information will be passed in this case.
 * 'mtls_parameter_description' may be NULL; if it is not, it will be used
 * to return an allocated string describing the TLS session parameters.
 * Used error codes: TLS_ELIBFAILED, TLS_ECERT, TLS_EHANDSHAKE
 */
int mtls_start(mtls_t *mtls, int fd,
        mtls_cert_info_t *tci, char **mtls_parameter_description, char **errstr);

/*
 * mtls_is_active()
 *
 * Returns whether 'mtls' is an active TLS connection.
 */
int mtls_is_active(mtls_t *mtls);

/*
 * mtls_cert_info_new()
 * Returns a new mtls_cert_info_t
 */
mtls_cert_info_t *mtls_cert_info_new(void);

/*
 * mtls_cert_info_free()
 * Frees a mtls_cert_info_t
 */
void mtls_cert_info_free(mtls_cert_info_t *tci);

/*
 * mtls_cert_info_get()
 *
 * Extracts certificate information from the TLS connection 'mtls' and stores
 * it in 'tci'. See the description of mtls_cert_info_t above.
 * Used error codes: TLS_ECERT
 */
int mtls_cert_info_get(mtls_t *mtls, mtls_cert_info_t *tci, char **errstr);

/*
 * mtls_print_info()
 *
 * Prints information about a TLS session.
 */
void mtls_print_info(const char *mtls_parameter_description,
        const mtls_cert_info_t *tci);

/*
 * mtls_gets()
 *
 * Reads in at most one less than 'size' characters from 'mtls' and stores them
 * into the buffer pointed 'str'. Reading stops after an EOF or a newline.
 * If a newline is read, it is stored into the buffer. A '\0' is stored after
 * the last character in the buffer. The length of the resulting string (the
 * number of characters excluding the terminating '\0') will be stored in 'len'.
 * 'readbuf' will be used as an input buffer and must of course be the same for
 * all read operations on 'mtls'.
 * Used error codes: TLS_EIO
 */
int mtls_gets(mtls_t *mtls, readbuf_t *readbuf,
        char *str, size_t size, size_t *len, char **errstr);

/*
 * mtls_puts()
 *
 * Writes 'len' characters from the string 's' using TLS.
 * Used error codes: TLS_EIO
 */
int mtls_puts(mtls_t *mtls, const char *s, size_t len, char **errstr);

/*
 * mtls_close()
 *
 * Close a TLS connection and mark it inactive
 */
void mtls_close(mtls_t *mtls);

/*
 * mtls_lib_deinit()
 *
 * Deinit underlying TLS library.
 */
void mtls_lib_deinit(void);

/*
 * mtls_exitcode()
 *
 * Translate TLS_* error code to an error code from sysexits.h
 */
int mtls_exitcode(int mtls_error_code);


/*** THE FOLLOWING ARE ONLY USED INTERNALLY ***/

/*
 * mtls_readbuf_read()
 *
 * Wraps TLS read function to provide buffering for mtls_gets().
 */
int mtls_readbuf_read(mtls_t *mtls, readbuf_t *readbuf, char *ptr, char **errstr);


#endif
