/*
 * msgid.c
 *
 * This file is part of msmtp, an SMTP client.
 *
 * Copyright (C) 2022  Martin Lambers <marlam@marlam.de>
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

#include <unistd.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

#include "msgid.h"
#include "net.h"
#include "xalloc.h"
#include "md5-apps.h"

#ifndef CLOCK_BOOTTIME
# define CLOCK_BOOTTIME CLOCK_MONOTONIC
#endif

char* create_msgid(const char* envelope_from)
{
    struct timespec ts_real;
    struct timespec ts_boot;
    pid_t pid;
    char* hostname;
    size_t hostname_len;
    unsigned char* data;
    size_t data_size;
    char digest[33];
    char *msgid;

    /* The following information should unqiuely identify this mail:
     * the system is identified via hostname and boot time, and
     * the mail on this system via real time and pid. */
    clock_gettime(CLOCK_REALTIME, &ts_real);
    clock_gettime(CLOCK_BOOTTIME, &ts_boot);
    pid = getpid();
    hostname = net_get_canonical_hostname(NULL);
    hostname_len = strlen(hostname);

    /* Compute a hash over this data so that it cannot be recovered. */
    data_size = sizeof(ts_real) + sizeof(ts_boot) + sizeof(pid) + hostname_len;
    data = xmalloc(data_size);
    memcpy(data, &ts_real, sizeof(ts_real));
    memcpy(data + sizeof(ts_real), &ts_boot, sizeof(ts_boot));
    memcpy(data + sizeof(ts_real) + sizeof(ts_boot), &pid, sizeof(pid));
    memcpy(data + sizeof(ts_real) + sizeof(ts_boot) + sizeof(pid), hostname, hostname_len);
    md5_digest(data, data_size, digest);
    free(data);

    if (strchr(envelope_from, '@'))
        msgid = xasprintf("<%s.%s>", digest, envelope_from);
    else
        msgid = xasprintf("<%s.%s@%s>", digest, envelope_from, hostname);
    free(hostname);
    return msgid;
}
