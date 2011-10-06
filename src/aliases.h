/*
 * aliases.h
 *
 * This file is part of msmtp, an SMTP client.
 *
 * Copyright (C) 2011
 * Scott Shumate <sshumate@austin.rr.com>
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

#ifndef ALIASES_H
#define ALIASES_H

#include "list.h"

/*
 * If a function with an 'errstr' argument returns a value != ALIASES_EOK,
 * '*errstr' either points to an allocates string containing an error
 * description or is NULL.
 * If such a function returns ALIASES_EOK, 'errstr' will not be changed.
 */
#define ALIASES_EOK        0       /* no error */
#define ALIASES_ECANTOPEN  1       /* Cannot open file */
#define ALIASES_EIO        2       /* Input/output error */
#define ALIASES_EPARSE     3       /* Parse error */

/*
 * aliases()
 *
 * Read 'aliases' and replace all recipients matching an alias with
 * its list of addresses.
 * Used error codes: ALIASES_EOK, ALIASES_ECANTOPEN, ALIASES_EIO,
 * ALIASES_EPARSE, ALIASES_EINSECURE
 */
int aliases_replace(const char *aliases, list_t *recipient_list, char **errstr);

#endif
