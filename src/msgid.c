/*
 * msgid.c
 *
 * This file is part of msmtp, an SMTP client.
 *
 * Copyright (C) 2022, 2023  Martin Lambers <marlam@marlam.de>
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

char* create_msgid(const char* host, const char* domain, const char* envelope_from)
{
    struct timespec ts_real;
    struct timespec ts_boot;
    pid_t pid;
    char* hostname;
    size_t hostname_len;
    size_t envelope_from_len;
    size_t data_size;
    unsigned char* data;
    size_t data_index;
    char digest[33];
    const char* dom;

    /* The following information should uniquely identify this mail
     * for this particular envelope from address:
     * the system is identified via hostname and boot time, and
     * the mail on this system via real time and pid. */
    clock_gettime(CLOCK_REALTIME, &ts_real);
    clock_gettime(CLOCK_BOOTTIME, &ts_boot);
    pid = getpid();
    hostname = net_get_canonical_hostname(NULL);
    hostname_len = strlen(hostname);
    envelope_from_len = strlen(envelope_from);

    /* Compute a hash over this data so that it cannot be recovered. */
    data_size = sizeof(ts_real) + sizeof(ts_boot) + sizeof(pid)
        + hostname_len + envelope_from_len;
    data = xmalloc(data_size);
    data_index = 0;
    memcpy(data + data_index, &ts_real, sizeof(ts_real));
    data_index += sizeof(ts_real);
    memcpy(data + data_index, &ts_boot, sizeof(ts_boot));
    data_index += sizeof(ts_boot);
    memcpy(data + data_index, &pid, sizeof(pid));
    data_index += sizeof(pid);
    memcpy(data + data_index, hostname, hostname_len);
    data_index += hostname_len;
    memcpy(data + data_index, envelope_from, envelope_from_len);
    free(hostname);
    md5_digest(data, data_size, digest);
    free(data);

    /* Find the domain part to use */
    if (strcmp(domain, "localhost") != 0)
    {
        dom = domain;
    }
    else if ((dom = strchr(envelope_from, '@')))
    {
        dom = dom + 1;
    }
    else
    {
        dom = host;
    }

    /* Create the Message ID */
    return xasprintf("<%s@%s>", digest, dom);
}
