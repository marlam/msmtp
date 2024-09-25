/*
 * password.c
 *
 * This file is part of msmtp, an SMTP client, and of mpop, a POP3 client.
 *
 * Copyright (C) 2019, 2020, 2021  Martin Lambers <marlam@marlam.de>
 * Jay Soffian <jaysoffian@gmail.com> (Mac OS X keychain support)
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#if defined HAVE_LIBSECRET
# include <libsecret/secret.h>
#elif defined HAVE_MACOSXKEYRING
# include <Security/Security.h>
#elif defined USE_CREDMAN
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
# include <wincred.h>
# include <objbase.h>
# ifndef CRED_PACK_GENERIC_CREDENTIALS
#  define CRED_PACK_GENERIC_CREDENTIALS        0x4
# endif
# pragma comment (lib, "credui.lib")
#endif

#include "gettext.h"
#define _(string) gettext(string)

#include "netrc.h"
#include "tools.h"
#include "xalloc.h"
#include "password.h"

#ifdef W32_NATIVE
#define SYSNETRCFILE    "netrc.txt"
#define USERNETRCFILE   "netrc.txt"
#else /* UNIX */
#define SYSNETRCFILE    "netrc"
#define USERNETRCFILE   ".netrc"
#endif


/*
 * password_get()
 *
 * see password.h
 */

#ifdef HAVE_LIBSECRET
static const SecretSchema *get_schema(void)
{
    static const SecretSchema schema = {
        "de.marlam." PACKAGE_NAME ".password", SECRET_SCHEMA_DONT_MATCH_NAME,
        {
            {  "host", SECRET_SCHEMA_ATTRIBUTE_STRING },
            {  "service", SECRET_SCHEMA_ATTRIBUTE_STRING },
            {  "user", SECRET_SCHEMA_ATTRIBUTE_STRING },
            {  "NULL", 0 },
        }
    };
    return &schema;
}
static const char *service_string(password_service_t service)
{
    switch (service)
    {
    case password_service_smtp:
        return "smtp";
    case password_service_pop3:
        return "pop3";
    }
    return NULL;
}
#endif

char *password_get(const char *hostname, const char *user,
        password_service_t service,
        int consult_netrc,
        int getpass_only_via_tty)
{
    char *password = NULL;

#ifdef HAVE_LIBSECRET
    if (!password)
    {
        gchar* libsecret_pw = secret_password_lookup_sync(
                get_schema(),
                NULL, NULL,
                "host", hostname,
                "service", service_string(service),
                "user", user,
                NULL);
        if (!libsecret_pw)
        {
            /* for compatibility with passwords stored by the older
             * libgnome-keyring */
            libsecret_pw = secret_password_lookup_sync(
                    SECRET_SCHEMA_COMPAT_NETWORK,
                    NULL, NULL,
                    "user", user,
                    "protocol", service_string(service),
                    "server", hostname,
                    NULL);
        }
        if (libsecret_pw)
        {
            password = xstrdup(libsecret_pw);
            secret_password_free(libsecret_pw);
        }
    }
#endif /* HAVE_LIBSECRET */

#ifdef HAVE_MACOSXKEYRING
    if (!password)
    {
        void *password_data;
        UInt32 password_length;
        if (SecKeychainFindInternetPassword(
                    NULL,
                    strlen(hostname), hostname,
                    0, NULL,
                    strlen(user), user,
                    0, (char *)NULL,
                    0,
                    service == password_service_smtp ? kSecProtocolTypeSMTP : kSecProtocolTypePOP3,
                    kSecAuthenticationTypeDefault,
                    &password_length, &password_data,
                    NULL) == noErr)
        {
            password = xmalloc((password_length + 1) * sizeof(char));
            strncpy(password, password_data, (size_t)password_length);
            password[password_length] = '\0';
            SecKeychainItemFreeContent(NULL, password_data);
        }
    }
#endif /* HAVE_MACOSXKEYRING */

#ifdef USE_CREDMAN
    if (!password)
    {
        PCREDENTIAL cred = NULL;
        LPVOID buf = NULL;
        ULONG buf_len;
        char target[1025 /* NI_MAXHOST */ + sizeof(PACKAGE_NAME) + 1] = PACKAGE_NAME "_";
        strcat(target, hostname);
        BOOL success = CredRead(target, CRED_TYPE_GENERIC, 0, &cred);
        if (success)
        {
            buf = cred->CredentialBlob;
            buf_len = cred->CredentialBlobSize;
        }
        else
        {
            DWORD err = GetLastError();
            if (err == ERROR_NOT_FOUND)
            {
                wchar_t caption[CRED_MAX_STRING_LENGTH];
                wsprintfW(caption, L"Password for %S at %S", user, hostname);

                /* Only -W works https://stackoverflow.com/a/25896444/673826 */
                CREDUI_INFOW ciw = {
                    .cbSize = sizeof(CREDUI_INFOW),
                    .pszCaptionText = caption,
                    .pszMessageText = L"The user name prefix does not matter."
                    "Neither does the actual user name. Leave it as is.\n"
                    "Only one credential per host name can be stored this way.\n"
                    "Although your password is stored encrypted, any application you run can read that password.\n"
                    "You can find saved credentials in Credential Manager with " PACKAGE_NAME "_ prefix."
                };
                wchar_t user_wide[CRED_MAX_STRING_LENGTH];
                mbstowcs(user_wide, user, CRED_MAX_STRING_LENGTH);

                char bufin[CRED_MAX_CREDENTIAL_BLOB_SIZE];
                DWORD inlen = CRED_MAX_CREDENTIAL_BLOB_SIZE;
                success = CredPackAuthenticationBufferW(CRED_PACK_GENERIC_CREDENTIALS, user_wide, L"", bufin, &inlen);
                if (success)
                {
                    ULONG auth_package = 0;
                    BOOL should_save = 1;
                    err = CredUIPromptForWindowsCredentialsW(&ciw, 0, &auth_package, bufin, inlen, &buf, &buf_len, &should_save, CREDUIWIN_GENERIC | CREDUIWIN_CHECKBOX);
                    if (err == ERROR_SUCCESS)
                    {
                        CREDENTIAL c = {
                            .Type = CRED_TYPE_GENERIC,
                            .TargetName = target,
                            .Persist = CRED_PERSIST_ENTERPRISE * should_save,
                            .CredentialBlob = buf,
                            .CredentialBlobSize = buf_len,
                            .UserName = (LPSTR)user
                        };
                        CredWrite(&c, 0);
                    }
                }
            }
        }
        if (buf)
        {
            wchar_t name[CRED_MAX_USERNAME_LENGTH];
            wchar_t pass[CRED_MAX_STRING_LENGTH];
            wchar_t domain[CRED_MAX_STRING_LENGTH]; /* not used, will be empty */
            DWORD name_size = CRED_MAX_USERNAME_LENGTH, pass_size = CRED_MAX_STRING_LENGTH,
                domain_size = CRED_MAX_STRING_LENGTH;
            success = CredUnPackAuthenticationBufferW(0, buf, buf_len, name, &name_size, domain, &domain_size, pass, &pass_size);
            if (success)
            {
                size_t len = wcslen(pass) + 1;
                password = xmalloc(len);
                wcstombs(password, pass, len);
            }
        }
        if (cred)
            CredFree(cred);
        else if (buf)
        {
            SecureZeroMemory(buf, buf_len);
            CoTaskMemFree(buf);
        }
    }
#endif

    if (!password && consult_netrc)
    {
        char *netrc_directory;
        char *netrc_filename;
        netrc_entry *netrc_hostlist;
        netrc_entry *netrc_host;

        netrc_directory = get_homedir();
        netrc_filename = get_filename(netrc_directory, USERNETRCFILE);
        free(netrc_directory);
        if ((netrc_hostlist = parse_netrc(netrc_filename)))
        {
            if ((netrc_host = search_netrc(netrc_hostlist, hostname, user)))
            {
                password = xstrdup(netrc_host->password);
            }
            free_netrc(netrc_hostlist);
        }
        free(netrc_filename);
        if (!password)
        {
            netrc_directory = get_sysconfdir();
            netrc_filename = get_filename(netrc_directory, SYSNETRCFILE);
            free(netrc_directory);
            if ((netrc_hostlist = parse_netrc(netrc_filename)))
            {
                if ((netrc_host = search_netrc(netrc_hostlist, hostname, user)))
                {
                    password = xstrdup(netrc_host->password);
                }
                free_netrc(netrc_hostlist);
            }
            free(netrc_filename);
        }
    }

    if (!password)
    {
        int getpass_is_allowed = 1;
        if (getpass_only_via_tty)
        {
            /* Do not let getpass() read from stdin, because we read the mail from
             * there. Our W32 getpass() uses _getch(), which always reads from the
             * 'console' and not stdin. On other systems, we test if /dev/tty can be
             * opened before calling getpass(). */
            int getpass_uses_tty;
            FILE *tty;
#if defined W32_NATIVE || defined __CYGWIN__
            getpass_uses_tty = 1;
#else
            getpass_uses_tty = 0;
            if ((tty = fopen("/dev/tty", "w+")))
            {
                getpass_uses_tty = 1;
                fclose(tty);
            }
#endif
            if (!getpass_uses_tty)
            {
                getpass_is_allowed = 0;
            }
        }
        if (getpass_is_allowed)
        {
            char *prompt = xasprintf(_("password for %s at %s: "), user, hostname);
            char *gpw = getpass(prompt);
            free(prompt);
            if (gpw)
            {
                password = xstrdup(gpw);
            }
        }
    }

    return password;
}
