/*
 * netrc.c
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "xalloc.h"
#include "netrc.h"

#define POPBUFSIZE 512

/* Free a netrc list */
void 
free_netrc_entry_list(netrc_entry *list)
{
    netrc_entry *current = list;
    netrc_entry *tmp;

    while (current)
    {
	free(current->host);
	free(current->login);
	free(current->password);
	tmp = current;
	current = current->next;
	free(tmp);
    }
}
    
/* Maybe add NEWENTRY to the account information list, LIST.  NEWENTRY is
   set to a ready-to-use netrc_entry, in any event. */
void
maybe_add_to_list (netrc_entry **newentry, netrc_entry **list)
{
    netrc_entry *a, *l;
    a = *newentry;
    l = *list;

    /* We need a login name in order to add the entry to the list. */
    if (a && ! a->login)
    {
	/* Free any allocated space. */
	if (a->host)
	    free (a->host);
	if (a->password)
	    free (a->password);
    }
    else
    {
	if (a)
	{
	    /* Add the current machine into our list. */
	    a->next = l;
	    l = a;
	}

	/* Allocate a new netrc_entry structure. */
	a = (netrc_entry *) xmalloc (sizeof (netrc_entry));
    }

    /* Zero the structure, so that it is ready to use. */
    memset (a, 0, sizeof(*a));

    /* Return the new pointers. */
    *newentry = a;
    *list = l;
    return;
}


/* Parse FILE as a .netrc file (as described in ftp(1)), and return a
   list of entries.  NULL is returned if the file could not be
   parsed. */
netrc_entry *
parse_netrc (const char *file)
{
    FILE *fp;
    char buf[POPBUFSIZE+1], *p, *tok;
    const char *premature_token;
    netrc_entry *current, *retval;
    int ln;

    /* The latest token we've seen in the file. */
    enum
    {
	tok_nothing, tok_account, tok_login, tok_macdef, tok_machine, tok_password
    } last_token = tok_nothing;

    current = retval = NULL;

    fp = fopen (file, "r");
    if (!fp)
    {
	/* Just return NULL if we can't open the file. */
	return NULL;
    }

    /* Initialize the file data. */
    ln = 0;
    premature_token = NULL;

    /* While there are lines in the file... */
    while (fgets(buf, POPBUFSIZE, fp))
    {
	ln++;

	/* Strip trailing CRLF */
	for (p = buf + strlen(buf) - 1; (p >= buf) && isspace((unsigned char)*p); p--)
	    *p = '\0';

	/* Parse the line. */
	p = buf;

	/* If the line is empty... */
	if (!*p)
	{
	    if (last_token == tok_macdef)	/* end of macro */
		last_token = tok_nothing;
	    else
		continue;			/* otherwise ignore it */
	}

	/* If we are defining macros, then skip parsing the line. */
	while (*p && last_token != tok_macdef)
	{
	    char quote_char = 0;
	    char *pp;

	    /* Skip any whitespace. */
	    while (*p && isspace((unsigned char)*p))
		p++;

	    /* Discard end-of-line comments. */
	    if (*p == '#')
		break;

	    tok = pp = p;

	    /* Find the end of the token. */
	    while (*p && (quote_char || !isspace((unsigned char)*p)))
	    {
		if (quote_char)
		{
		    if (quote_char == *p)
		    {
			quote_char = 0;
			p ++;
		    }
		    else
		    {
			*pp = *p;
			p ++;
			pp ++;
		    }
		}
		else
		{
		    if (*p == '"' || *p == '\'')
			quote_char = *p;
		    else
		    {
			*pp = *p;
			pp ++;
		    }
		    p ++;
		}
	    }
	    /* Null-terminate the token, if it isn't already. */
	    if (*p)
		*p ++ = '\0';
	    *pp = 0;

	    switch (last_token)
	    {
	    case tok_login:
		if (current)
		    current->login = (char *) xstrdup (tok);
		else
		    premature_token = "login";
		break;

	    case tok_machine:
		/* Start a new machine entry. */
		maybe_add_to_list (&current, &retval);
		current->host = (char *) xstrdup (tok);
		break;

	    case tok_password:
		if (current)
		    current->password = (char *) xstrdup (tok);
		else
		    premature_token = "password";
		break;

		/* We handle most of tok_macdef above. */
	    case tok_macdef:
		if (!current)
		    premature_token = "macdef";
		break;

		/* We don't handle the account keyword at all. */
	    case tok_account:
		if (!current)
		    premature_token = "account";
		break;

		/* We handle tok_nothing below this switch. */
	    case tok_nothing:
		break;
	    }

	    if (premature_token)
	    {
/*
#ifdef HAVE_ERROR
		error_at_line (0, file, ln,
			       GT_("warning: found \"%s\" before any host names"),
			       premature_token);
#else
		fprintf (stderr,
			 GT_("%s:%d: warning: found \"%s\" before any host names\n"),
			 file, ln, premature_token);
#endif
*/
		premature_token = NULL;
	    }

	    if (last_token != tok_nothing)
		/* We got a value, so reset the token state. */
		last_token = tok_nothing;
	    else
	    {
		/* Fetch the next token. */
		if (!strcmp (tok, "default"))
		{
		    maybe_add_to_list (&current, &retval);
		}
		else if (!strcmp (tok, "login"))
		    last_token = tok_login;

		else if (!strcmp (tok, "user"))
		    last_token = tok_login;

		else if (!strcmp (tok, "macdef"))
		    last_token = tok_macdef;

		else if (!strcmp (tok, "machine"))
		    last_token = tok_machine;

		else if (!strcmp (tok, "password"))
		    last_token = tok_password;

		else if (!strcmp (tok, "passwd"))
		    last_token = tok_password;

		else if (!strcmp (tok, "account"))
		    last_token = tok_account;

		else
		{
		    /*
		    fprintf (stderr, GT_("%s:%d: warning: unknown token \"%s\"\n"),
			     file, ln, tok);
		    */
		}
	    }
	}
    }

    fclose (fp);

    /* Finalize the last machine entry we found. */
    maybe_add_to_list (&current, &retval);
    free (current);

    /* Reverse the order of the list so that it appears in file order. */
    current = retval;
    retval = NULL;
    while (current)
    {
	netrc_entry *saved_reference;

	/* Change the direction of the pointers. */
	saved_reference = current->next;
	current->next = retval;

	/* Advance to the next node. */
	retval = current;
	current = saved_reference;
    }

    return retval;
}


/* Return the netrc entry from LIST corresponding to HOST.  NULL is
   returned if no such entry exists. */
netrc_entry *
search_netrc (netrc_entry *list, const char *host, const char *login)
{
    /* Look for the HOST in LIST. */
    while (list)
    {
	if (list->host && !strcmp(list->host, host))
	    if (!list->login || !strcmp(list->login, login))
		/* We found a matching entry. */
		break;

	list = list->next;
    }

    /* Return the matching entry, or NULL. */
    return list;
}
