/*
 * mtls-sspi.c Schannel SSP implementation for TLS using SSPI (W32 ONLY)
 *
 * This file is part of msmtp, an SMTP client, and of mpop, a POP3 client.
 *
 * Copyright (C) 2024 Mikhail Titov <mlt@gmx.us>
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#pragma warning(error:4013)

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#define SECURITY_WIN32
#include <security.h>
#define SCHANNEL_USE_BLACKLISTS
#include <subauth.h>
#include <schnlsp.h>
#include <assert.h>

#pragma comment (lib, "secur32.lib")
#pragma comment(lib, "crypt32.Lib")

#include "gettext.h"
#define _(string) gettext(string)
#define N_(string) gettext_noop(string)

#include "xalloc.h"
#include "readbuf.h"
#include "tools.h"
#include "mtls.h"

/*
 * epoch is Jan. 1, 1601: 134774 days to Jan. 1, 1970
 * https://learn.microsoft.com/en-us/windows/win32/sysinfo/converting-a-time-t-value-to-a-file-time
 * https://devblogs.microsoft.com/oldnewthing/20220602-00/?p=106706
 */
#define filetime_to_timet(ft) (*(ULONGLONG*)&ft / 10000000ULL - 11644473600ULL)
#define MAKE_DESC(buf) { SECBUFFER_VERSION, ARRAYSIZE(buf), buf };
#define TLS_MAX_PACKET_SIZE (16384+512) // payload + extra over head for header/mac/padding (probably an overestimate)

/* very handy private functions from net.c */
int net_send(int fd, const void* buf, size_t len, char** errstr);
int net_recv(int fd, void* buf, size_t len, char** errstr);

struct mtls_internals_t
{
    int fd;
    CredHandle handle;
    CtxtHandle context;
    SecPkgContext_StreamSizes sizes;
    char incoming[TLS_MAX_PACKET_SIZE];
    char* incoming_ptr; // where we left off decrypting (SECBUFFER_EXTRA only actually)
};

/*
 * mtls_lib_init()
 *
 * see mtls.h
 */

int mtls_lib_init(char **errstr)
{
    return TLS_EOK;
}

/*
 * mtls_cert_info_get()
 *
 * see mtls.h
 */

int mtls_cert_info_get(mtls_t *mtls, mtls_cert_info_t *mtci, char **errstr)
{
    const char *errmsg = _("cannot get TLS certificate info");
    CHAR name[200];
    DWORD hashsize;
    PCCERT_CONTEXT cert_context;

    QueryContextAttributes(&mtls->internals->context, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &cert_context);
	if (CertNameToStr(cert_context->dwCertEncodingType, &cert_context->pCertInfo->Subject,
		CERT_X500_NAME_STR, name, sizeof(name)))
    {
        mtci->subject_info = xstrdup(name);
    }

	if (CertNameToStr(cert_context->dwCertEncodingType, &cert_context->pCertInfo->Issuer,
		CERT_X500_NAME_STR, name, sizeof(name)))
    {
        mtci->issuer_info = xstrdup(name);
    }

    mtci->activation_time = filetime_to_timet(cert_context->pCertInfo->NotBefore);
    mtci->expiration_time = filetime_to_timet(cert_context->pCertInfo->NotAfter);

    hashsize = ARRAYSIZE(mtci->sha256_fingerprint);
    if (!CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM, 0, NULL, cert_context->pbCertEncoded,
        cert_context->cbCertEncoded, mtci->sha256_fingerprint, &hashsize))
    {
        *errstr = xasprintf(_("%s: error getting SHA256 fingerprint"), errmsg);
        return TLS_ECERT;
    }
    /* deprecated
    hashsize = ARRAYSIZE(mtci->sha1_fingerprint);
    if (!CryptHashCertificate2(BCRYPT_SHA1_ALGORITHM, 0, NULL, cert_context->pbCertEncoded,
        cert_context->cbCertEncoded, mtci->sha1_fingerprint, &hashsize))
    {
        *errstr = xasprintf(_("%s: error getting SHA1 fingerprint"), errmsg);
        return TLS_ECERT;
    }
    */

    return TLS_EOK;
}

/*
 * mtls_check_cert()
 *
 * Schannel will perform a full certificate verification automatically
 * if SCH_CRED_AUTO_CRED_VALIDATION and SCH_CRED_REVOCATION_CHECK_CHAIN are set
 * and SCH_CRED_NO_SERVERNAME_CHECK is cleared.
 *
 * If 'mtls->have_sha256_fingerprint' flags is set, compare the
 * 'mtls->fingerprint' data with the peer certificate's fingerprint. If this
 * succeeds, the connection can be considered secure.
 *
 * Used error codes: TLS_ECERT
 */

static int mtls_check_cert(mtls_t *mtls, char **errstr)
{
    const char* error_msg = _("TLS certificate verification failed");

    if (mtls->have_sha256_fingerprint)
    {
        unsigned char sha256_fingerprint[32];
        DWORD cbComputedHash = ARRAYSIZE(sha256_fingerprint);
        PCCERT_CONTEXT pRemoteCertContext;

        if (SEC_E_OK != QueryContextAttributes(&mtls->internals->context,
            SECPKG_ATTR_REMOTE_CERT_CONTEXT, &pRemoteCertContext))
        {
            *errstr = xasprintf(_("%s: no certificate was sent"), error_msg);
            return TLS_ECERT;
        }

        if (!CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM, 0, NULL, pRemoteCertContext->pbCertEncoded,
            pRemoteCertContext->cbCertEncoded, sha256_fingerprint, &cbComputedHash))
        {
            *errstr = xasprintf(_("%s: error getting SHA256 fingerprint"), error_msg);
            return TLS_ECERT;
        }

        if (memcmp(sha256_fingerprint, mtls->fingerprint, 32) != 0)
        {
            *errstr = xasprintf(_("%s: the certificate fingerprint does not match"), error_msg);
            return TLS_ECERT;
        }
    }

    return TLS_EOK;
}


/*
 * mtls_init()
 *
 * see mtls.h
 */

int mtls_init(mtls_t *mtls,
        const char *key_file, const char *cert_file, const char *pin,
        const char *trust_file, const char *crl_file,
        const unsigned char *sha256_fingerprint,
        const unsigned char *sha1_fingerprint,
        const unsigned char *md5_fingerprint,
        int min_dh_prime_bits, const char *priorities,
        const char *hostname,
        int no_certcheck,
        char **errstr)
{
    char* prio_copy;
    TLS_PARAMETERS tls_params = { 0 };
    SCH_CREDENTIALS cred =
    {
        .dwVersion = SCH_CREDENTIALS_VERSION,
        .dwFlags = SCH_USE_STRONG_CRYPTO | SCH_CRED_NO_DEFAULT_CREDS
                 | SCH_CRED_REVOCATION_CHECK_CHAIN * (!no_certcheck)
                 | SCH_CRED_AUTO_CRED_VALIDATION * (!no_certcheck)
                 | SCH_CRED_NO_SERVERNAME_CHECK * no_certcheck,
        .cTlsParameters = 1,
        .pTlsParameters = &tls_params
    };

    if (sha1_fingerprint || md5_fingerprint)
    {
        *errstr = xasprintf(
                _("cannot use deprecated fingerprints, please update to SHA256"));
        return TLS_ELIBFAILED;
    }
    if (min_dh_prime_bits >= 0)
    {
        /* This will never need to be implemented because it is deprecated.
         * But we should report it and not just silently ignore it. */
        *errstr = xasprintf(
                _("cannot set minimum number of DH prime bits for TLS: %s"),
                _("feature not yet implemented for Schannel SSP"));
        return TLS_ELIBFAILED;
    }
    /*
     * Basic support for protocol restrictions.
     * We mimic libtls string but will unofficially accept minor deviations from that format.
     */
    if (priorities)
    {
        size_t len = strlen(priorities);
        prio_copy = xmalloc(len+1); /* for modification by strtok() */
        const char* key;
        char* value;
        char* token = NULL;
        DWORD enabled = 0;
        int failed = 0;
        for (int i = 0; i <= len; ++i)
            prio_copy[i] = __isascii(priorities[i]) && isupper(priorities[i]) ? _tolower(priorities[i]) : priorities[i];
        if ((key = strstr(prio_copy, "protocols=")) != NULL)
        {
            const DWORD tls = 't' | 'l' << 8 | 's' << 16; // little-endian only
            value = prio_copy + (key + strlen("protocols=") - prio_copy);
            (void)strtok(value, " ");
            token = strtok(value, ",");
            while (token)
            {
                if ((*(DWORD*)token & 0x00fffffful) != tls)
                {
                    *errstr = xasprintf(
                        _("error in priority string at position %d"),
                        token - prio_copy + 1);
                    goto error_prio2;
                }
                token += 3;
                if (*token == 'v')
                    token++;
                if (*token++ != '1')
                    goto error_prio;
                if (*token == '.' || *token == '_')
                    token++;
                switch (*token)
                {
                case '1': enabled |= SP_PROT_TLS1_1_CLIENT; break;
                case '2': enabled |= SP_PROT_TLS1_2_CLIENT; break;
                case '3': enabled |= SP_PROT_TLS1_3_CLIENT; break;
                default: goto error_prio;
                }

                token = strtok(NULL, ",");
            }
            free(prio_copy);
            tls_params.grbitDisabledProtocols = ~enabled;
        }
    }
    /* FIXME: Implement support for 'crl_file' */
    if (trust_file && crl_file)
    {
        *errstr = xasprintf(
            _("cannot load CRL file: %s"),
            _("feature not yet implemented for Schannel SSP"));
        return TLS_ELIBFAILED;
    }

    if (sha256_fingerprint && !no_certcheck)
    {
        memcpy(mtls->fingerprint, sha256_fingerprint, 32);
        mtls->have_sha256_fingerprint = 1;
    }

    mtls->internals = xmalloc(sizeof(struct mtls_internals_t));
    memset(mtls->internals, 0, sizeof(struct mtls_internals_t));

    SECURITY_STATUS status = AcquireCredentialsHandle(NULL, UNISP_NAME, SECPKG_CRED_OUTBOUND, NULL,
        &cred, NULL, NULL, &mtls->internals->handle, NULL);
    if (SEC_E_OK == status)
    {
        mtls->hostname = xstrdup(hostname);
        mtls->no_certcheck = no_certcheck;
        return TLS_EOK;
    }

    char buf[11];
    sprintf(buf, "0x%0x", status);
    *errstr = xasprintf(_("cannot initialize TLS library: %s"), buf);
    free(mtls->internals);
    mtls->internals = NULL;
    return TLS_ELIBFAILED;

error_prio:
    *errstr = xasprintf(
        _("cannot set priorities for TLS session: %s"),
        _("protocol not supported"));
error_prio2:
    free(prio_copy);
    return TLS_ELIBFAILED;
}

/*
 * mtls_start()
 *
 * see mtls.h
 */

int mtls_start(mtls_t* mtls, int fd,
    mtls_cert_info_t* mtci, char** mtls_parameter_description, char** errstr)
{
    int error_code = TLS_EHANDSHAKE;
    struct mtls_internals_t* const s = mtls->internals;
    s->fd = fd;
    PCtxtHandle context = NULL;
    int received = 0;
    s->incoming_ptr = s->incoming;
    for (;;)
    {
        SecBuffer inbuffers[2] = { 0 };
        inbuffers[0].BufferType = SECBUFFER_TOKEN;
        inbuffers[0].pvBuffer = s->incoming_ptr;
        inbuffers[0].cbBuffer = received;
        inbuffers[1].BufferType = SECBUFFER_EMPTY;

        SecBuffer outbuffers[3] = { 0 };
        outbuffers[0].BufferType = SECBUFFER_TOKEN;
        outbuffers[1].BufferType = SECBUFFER_ALERT;
        outbuffers[2].BufferType = SECBUFFER_EMPTY;

        SecBufferDesc indesc = MAKE_DESC(inbuffers);
        SecBufferDesc outdesc = MAKE_DESC(outbuffers);

        DWORD flags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_INTEGRITY
            | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;
        SECURITY_STATUS status = InitializeSecurityContext(
            &s->handle,
            context,
            context ? NULL : mtls->hostname,
            flags,
            0,
            0,
            context ? &indesc : NULL,
            0,
            context ? NULL : &s->context,
            &outdesc,
            &flags,
            NULL);
        context = &s->context;

        if (inbuffers[1].BufferType == SECBUFFER_EXTRA)
        {
            s->incoming_ptr += received - inbuffers[1].cbBuffer;
            received = inbuffers[1].cbBuffer;
        }
        else if (inbuffers[1].BufferType != SECBUFFER_MISSING)
        {
            received = 0;
            s->incoming_ptr = s->incoming;
        }

        if (status == SEC_E_OK)
        {
            if (outbuffers[0].BufferType != SECBUFFER_TOKEN || outbuffers[0].cbBuffer == 0)
                break;
            
            /* TLS1.3 send token back to server */
            if (net_send(fd, outbuffers[0].pvBuffer, outbuffers[0].cbBuffer, errstr) < 0)
            {
                return TLS_EHANDSHAKE;
            }
            break;
        }
        else if (status == SEC_I_CONTINUE_NEEDED)
        {
            char* buffer = outbuffers[0].pvBuffer;
            int size = outbuffers[0].cbBuffer;

            while (size)
            {
                int d = net_send(fd, buffer, size, errstr);
                if (d <= 0)
                    break;

                size -= d;
                buffer += d;
            }
            if (outbuffers[0].pvBuffer)
                status = FreeContextBuffer(outbuffers[0].pvBuffer);
            if (size != 0)
                goto error;
        }
        else if (status == SEC_E_WRONG_PRINCIPAL)
        {
            *errstr = xasprintf(_("%s: the certificate owner does not match hostname %s"),
                _("TLS certificate verification failed"), mtls->hostname);
            goto error;
        }
        else if (status != SEC_E_INCOMPLETE_MESSAGE)
        {
            char* buf;
            FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, status, GetUserDefaultLangID(), (LPSTR)&buf, 0, NULL);
            int len = strlen(buf);
            buf[len - 2] = 0; /* remove \r\n */
            *errstr = xasprintf(_("cannot initialize TLS session: %s"), buf);
            LocalFree(buf);
            goto error;
        }

        if (received == sizeof(s->incoming))
        {
            *errstr = xasprintf(_("cannot initialize TLS session: %s"), _("no buffer space available"));
            goto error;
        }
        int r = net_recv(fd, s->incoming_ptr + received, sizeof(s->incoming) - received - (s->incoming_ptr - s->incoming), errstr);
        
        if (r <= 0)
            goto error;

        received += r;
    }

    if (mtci && ((error_code = mtls_cert_info_get(mtls, mtci, errstr)) != TLS_EOK))
        goto error;
    if (mtls_parameter_description)
    {
        size_t converted;
        char suite[SZ_ALG_MAX_SIZE];
        char proto[11];
        static const int desc_size = 200;
        SecPkgContext_CipherInfo cipher_info;
        SecPkgContext_ConnectionInfo conn_info;

        *mtls_parameter_description = xmalloc(desc_size);
        QueryContextAttributes(context, SECPKG_ATTR_CIPHER_INFO, &cipher_info);
        wcstombs_s(&converted, suite, SZ_ALG_MAX_SIZE, cipher_info.szCipherSuite, _TRUNCATE);
        QueryContextAttributes(context, SECPKG_ATTR_CONNECTION_INFO, &conn_info);
        switch (conn_info.dwProtocol)
        {
        case SP_PROT_TLS1_1_CLIENT:
            strcpy(proto, "TLS1.1");
            break;
        case SP_PROT_TLS1_2_CLIENT:
            strcpy(proto, "TLS1.2");
            break;
        case SP_PROT_TLS1_3_CLIENT:
            mtls->is_tls_1_3_or_newer = 1;
            strcpy(proto, "TLS1.3");
            break;
        default:
            sprintf(proto, "0x%x ", conn_info.dwProtocol);
        }
        sprintf(*mtls_parameter_description,
            "%s \x1B]8;;https://ciphersuite.info/cs/%s/\x1b\\%s\x1b]8;;\x1b\\",
            proto, suite, suite);
    }
    if (!mtls->no_certcheck && ((error_code = mtls_check_cert(mtls, errstr)) != TLS_EOK))
        goto error;

    QueryContextAttributes(context, SECPKG_ATTR_STREAM_SIZES, &s->sizes);
    mtls->is_active = 1;
    return TLS_EOK;

error:
    DeleteSecurityContext(context);
    FreeCredentialsHandle(&s->handle);
    return error_code;
}


/*
 * mtls_readbuf_read()
 *
 * Wraps TLS read function to provide buffering for mtls_gets().
 */

int mtls_readbuf_read(mtls_t *mtls, readbuf_t *readbuf, char *ptr,
        char **errstr)
{
    struct mtls_internals_t* const s = mtls->internals;

    s->incoming_ptr = s->incoming;
    int received = 0;
    while (readbuf->count <= 0)
    {
        if (received != 0)
        {
            SecBuffer buffers[4];
            assert(s->sizes.cBuffers == ARRAYSIZE(buffers));

            buffers[0].BufferType = SECBUFFER_DATA;
            buffers[0].pvBuffer = s->incoming_ptr;
            buffers[0].cbBuffer = received;
            buffers[1].BufferType = SECBUFFER_EMPTY;
            buffers[2].BufferType = SECBUFFER_EMPTY;
            buffers[3].BufferType = SECBUFFER_EMPTY;

            SecBufferDesc desc = MAKE_DESC(buffers);

            SECURITY_STATUS sec = DecryptMessage(&s->context, &desc, 0, NULL);
            if (sec == SEC_E_OK)
            {
                assert(buffers[0].BufferType == SECBUFFER_STREAM_HEADER);
                assert(buffers[1].BufferType == SECBUFFER_DATA);
                assert(buffers[2].BufferType == SECBUFFER_STREAM_TRAILER);

                readbuf->ptr = buffers[1].pvBuffer;
                readbuf->count = buffers[1].cbBuffer;
                if (buffers[3].BufferType == SECBUFFER_EXTRA)
                {
                    s->incoming_ptr += received - buffers[3].cbBuffer;
                    received = buffers[3].cbBuffer;
                }
                else
                {
                    received = 0;
                    s->incoming_ptr = s->incoming;
                }

                break;
            }
            else if (sec == SEC_I_RENEGOTIATE && mtls->is_tls_1_3_or_newer)
            {
                /*
                 * TLS1.3 repurposed status code.
                 * If TLS<1.3 server wants to renegotiate TLS connection that we don't support.
                 */
                assert(buffers[3].BufferType == SECBUFFER_EXTRA);
                /* new_session_ticket */
                assert(((BYTE*)buffers[3].pvBuffer)[5] == 0x04);
                SecBuffer inbuffers[2] = { 0 };
                inbuffers[0].BufferType = SECBUFFER_TOKEN;
                inbuffers[0].pvBuffer = buffers[3].pvBuffer;
                inbuffers[0].cbBuffer = buffers[3].cbBuffer;
                inbuffers[1].BufferType = SECBUFFER_EMPTY;

                SecBuffer outbuffers[3] = { 0 };
                outbuffers[0].BufferType = SECBUFFER_TOKEN;
                outbuffers[1].BufferType = SECBUFFER_ALERT;
                outbuffers[2].BufferType = SECBUFFER_EMPTY;

                SecBufferDesc indesc = MAKE_DESC(inbuffers);
                SecBufferDesc outdesc = MAKE_DESC(outbuffers);

                DWORD flags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT
                    | ISC_REQ_STREAM | ISC_RET_EXTENDED_ERROR;
                SECURITY_STATUS sec = InitializeSecurityContext(
                    &s->handle,
                    &s->context,
                    NULL,
                    flags,
                    0,
                    0,
                    &indesc,
                    0,
                    NULL,
                    &outdesc,
                    &flags,
                    NULL);
                if (sec != SEC_E_OK || inbuffers[1].BufferType != SECBUFFER_EXTRA)
                {
                    return TLS_EIO;
                }

                s->incoming_ptr += received - inbuffers[1].cbBuffer;
                received = inbuffers[1].cbBuffer;
                assert(received>=0);
                continue;
            }
            else if (sec != SEC_E_INCOMPLETE_MESSAGE)
            {
                return TLS_EIO;
            }
        }

        if (received == sizeof(s->incoming))
        {
            *errstr = xasprintf(_("network read error: %s"), _("no buffer space available"));
            return TLS_EIO;
        }

        int r = net_recv(s->fd, s->incoming_ptr + received, sizeof(s->incoming) - received - (s->incoming_ptr - s->incoming), errstr);
        if (r <= 0)
            return TLS_EIO;

        received += r;
    }

    readbuf->count--;
    *ptr = *((readbuf->ptr)++);

    return 1;
}


/*
 * mtls_puts()
 *
 * see mtls.h
 */
char wbuffer[TLS_MAX_PACKET_SIZE];

int mtls_puts(mtls_t *mtls, const char *ss, size_t len, char **errstr)
{
    struct mtls_internals_t* const s = mtls->internals;
    assert(s->sizes.cbHeader + s->sizes.cbMaximumMessage + s->sizes.cbTrailer <= sizeof(wbuffer));
    assert(len <= s->sizes.cbMaximumMessage);

    SecBuffer buffers[3];
    buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
    buffers[0].pvBuffer = wbuffer;
    buffers[0].cbBuffer = s->sizes.cbHeader;
    buffers[1].BufferType = SECBUFFER_DATA;
    buffers[1].pvBuffer = wbuffer + s->sizes.cbHeader;
    buffers[1].cbBuffer = (unsigned long)len;
    buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
    buffers[2].pvBuffer = wbuffer + s->sizes.cbHeader + len;
    buffers[2].cbBuffer = s->sizes.cbTrailer;

    memcpy(buffers[1].pvBuffer, ss, len);

    SecBufferDesc desc = { SECBUFFER_VERSION, ARRAYSIZE(buffers), buffers };
    SECURITY_STATUS status = EncryptMessage(&s->context, 0, &desc, 0);
    if (status != SEC_E_OK)
    {
        char buf[11];
        sprintf(buf, "0x%0x", status);
        *errstr = xasprintf(_("cannot write to TLS connection: %s"), buf);
        return TLS_ELIBFAILED;
    }

    int total = buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer;
    int sent = 0;
    while (sent != total)
    {
        int d = net_send(mtls->internals->fd, wbuffer + sent, total - sent, errstr);
        if (d <= 0)
            return TLS_EIO;

        sent += d;
    }

    return TLS_EOK;
}

/*
 * mtls_close()
 *
 * see mtls.h
 */

void mtls_close(mtls_t *mtls)
{
    SECURITY_STATUS ss;
    if (mtls->is_active)
    {
        ss = DeleteSecurityContext(&mtls->internals->context);
        assert(SEC_E_OK == ss);
        ss = FreeCredentialsHandle(&mtls->internals->handle);
        assert(SEC_E_OK == ss);
    }
    free(mtls->internals);
    mtls->internals = NULL;
    if (mtls->hostname)
    {
        free(mtls->hostname);
    }
    mtls_clear(mtls);
}


/*
 * mtls_lib_deinit()
 *
 * see mtls.h
 */

void mtls_lib_deinit(void)
{
}
