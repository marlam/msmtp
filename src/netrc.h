/*
 * netrc.h
 *
 * This file was taken from fetchmail 6.2.5.
 * Gordon Matzigkeit <gord@gnu.ai.mit.edu>, 1996
 * Copyright assigned to Eric S. Raymond, October 2001.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software Foundation,
 *   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef _NETRC_H_
#define _NETRC_H_ 1

/* The structure used to return account information from the .netrc. */
typedef struct _netrc_entry {
  /* The exact host name given in the .netrc, NULL if default. */
  char *host;

  /* The login name of the user. */
  char *login;

  /* Password for the account (NULL, if none). */
  char *password;

  /* Pointer to the next entry in the list. */
  struct _netrc_entry *next;
} netrc_entry;

/* Parse FILE as a .netrc file (as described in ftp(1)), and return a
   list of entries.  NULL is returned if the file could not be
   parsed. */
netrc_entry *parse_netrc(const char *file);

/* Return the netrc entry from LIST corresponding to HOST.  NULL is
   returned if no such entry exists. */
netrc_entry *search_netrc(netrc_entry *list, 
	const char *host, const char *account);

/* Free a netrc list */
void free_netrc_entry_list(netrc_entry *list);

#endif /* _NETRC_H_ */
