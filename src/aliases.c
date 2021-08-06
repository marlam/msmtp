/*
 * aliases.c
 *
 * This file is part of msmtp, an SMTP client.
 *
 * Copyright (C) 2011, 2019
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

#define MAXTOKS 32
#define MAXLINE 512
#define MAXDEPTH 16

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "gettext.h"
#define _(string) gettext(string)

#include "aliases.h"
#include "list.h"
#include "xalloc.h"


typedef struct alias
{
    char *alias_str;
    list_t *addr_list;
} alias_t;

static char *trim(char *str)
{
    char *end;

    while (isspace(*str))
        str++;

    end = str + strlen(str) - 1;
    while (end > str && isspace(*end))
        end--;

    *(++end) = '\0';

    return str;
}

static int split(char *str, char delim, char *tokv[])
{
    int tokc = 0;
    char *loc;

    while (tokc < MAXTOKS && (loc = strchr(str, delim)) != NULL)
    {
        *loc = '\0';
        *tokv++ = trim(str);
        tokc++;
        str = loc + 1;
    }

    if (tokc < MAXTOKS)
    {
        *tokv++ = trim(str);
        tokc++;
    }

    return tokc;
}

static int is_alias(const char *str)
{
    return (*str != '\0' && strchr(str, '@') == NULL);
}

static alias_t *alias_find(const char *alias_str, list_t *alias_list)
{
    alias_t *entry;

    while (!list_is_empty(alias_list))
    {
        entry = alias_list->next->data;
        if (strcmp(alias_str, entry->alias_str) == 0)
            return entry;
        alias_list = alias_list->next;
    }

    return NULL;
}

static int aliases_read(FILE *f, list_t *alias_list, char **errstr)
{
    char line[MAXLINE];
    char *tokv[MAXTOKS];
    int tokc;
    int i;
    int lnum = 1;
    alias_t *entry;
    list_t *addr_list;
    list_t *alias_itr = alias_list;

    while (fgets(line, MAXLINE, f) != NULL)
    {
        /* Check line length */
        if (strlen(line) == MAXLINE - 1)
        {
            *errstr = xasprintf(_("line %d: longer than %d characters"),
                    lnum, MAXLINE - 1);
            return ALIASES_EPARSE;
        }

        /* Split off comments */
        tokc = split(line, '#', tokv);

        /* Split on the colon delimiter */
        tokc = split(tokv[0], ':', tokv);

        /* If line is not empty */
        if (tokc != 1 || *tokv[0] != '\0')
        {
            /* Expect a single delimiter */
            if (tokc != 2)
            {
                *errstr = xasprintf(_("line %d: single ':' delimiter expected"),
                        lnum);
                return ALIASES_EPARSE;
            }

            /* Check for a valid alias */
            if (!is_alias(tokv[0]))
            {
                *errstr = xasprintf(_("line %d: invalid alias '%s'"),
                        lnum, tokv[0]);
                return ALIASES_EPARSE;
            }

            if (alias_find(tokv[0], alias_list))
            {
                *errstr = xasprintf(_("line %d: duplicate alias '%s'"),
                        lnum, tokv[0]);
                return ALIASES_EPARSE;
            }

            entry = xmalloc(sizeof(alias_t));
            entry->alias_str = xstrdup(tokv[0]);
            entry->addr_list = list_new();
            addr_list = entry->addr_list;

            list_insert(alias_itr, entry);
            alias_itr = alias_itr->next;

            /* Add addresses to the list*/
            tokc = split(tokv[1], ',', tokv);
            for (i = 0; i < tokc; i++)
            {
                list_insert(addr_list, xstrdup(tokv[i]));
                addr_list = addr_list->next;
            }
        }
        lnum++;
    }
    if (ferror(f))
    {
        *errstr = xasprintf(_("input error"));
        return ALIASES_EIO;
    }

    return ALIASES_EOK;
}

static void alias_free(void *ptr)
{
    alias_t *entry = ptr;

    if (entry)
    {
        list_xfree(entry->addr_list, free);
        free(entry->alias_str);
        free(entry);
    }
}

static int expand_alias(char *alias, list_t *alias_list, int depth, list_t *addr_list)
{
    alias_t *e;
    int rc;
    list_t *a;

    if (depth > MAXDEPTH)
        return ALIASES_ELOOP;

    e = alias_find(alias, alias_list);
    if (e == NULL)
        e = alias_find("default", alias_list);

    if (e == NULL)
    {
        /* Can't find it in aliases, use as-is */
        list_insert(addr_list, xstrdup(alias));
        return ALIASES_EOK;
    }

    for (a = e->addr_list; !list_is_empty(a); a = a->next)
    {
        if (! is_alias(a->next->data))
        {
            list_insert(addr_list, xstrdup(a->next->data));
            continue;
        }
        /* found an alias, recursively expand */
        rc = expand_alias(a->next->data, alias_list, depth+1, addr_list);
        if (rc != ALIASES_EOK)
            return rc;
    }

    return ALIASES_EOK;
}

int aliases_replace(const char *aliases, list_t *recipient_list, char **errstr)
{
    FILE *f;
    int e;
    list_t *alias_list;
    list_t *addr_list, *addr_itr;
    list_t *rec_itr;

    /* Make sure there is at least one alias */
    for (rec_itr = recipient_list;
         !list_is_empty(rec_itr);
         rec_itr = rec_itr->next)
    {
        if (is_alias(rec_itr->next->data))
            break;
    }
    if (list_is_empty(rec_itr))
        return ALIASES_EOK;

    /* Open and read the alias file */
    if (!(f = fopen(aliases, "r")))
    {
        *errstr = xasprintf("%s", strerror(errno));
        return ALIASES_ECANTOPEN;
    }

    alias_list = list_new();

    if ((e = aliases_read(f, alias_list, errstr))
            != ALIASES_EOK)
    {
        fclose(f);
        list_xfree(alias_list, alias_free);
        return e;
    }

    fclose(f);

    /* Process all aliases in the recipient list */
    for (rec_itr = recipient_list;
         !list_is_empty(rec_itr);
         rec_itr = rec_itr->next)
    {
        if (is_alias(rec_itr->next->data))
        {
            addr_list = list_new();
            e = expand_alias(rec_itr->next->data, alias_list, 0, addr_list);
            if (e != ALIASES_EOK)
            {
                *errstr = xasprintf(
                    _("Too many redirects when expanding alias %s."),
                    (char *) rec_itr->next->data);
                list_xfree(addr_list, free);
                list_xfree(alias_list, alias_free);
                return e;
            }
            list_xremove(rec_itr, free);
            for (addr_itr = addr_list;
                 !list_is_empty(addr_itr);
                 addr_itr = addr_itr->next)
            {
                list_insert(rec_itr, addr_itr->next->data);
                rec_itr = rec_itr->next;
            }
            list_free(addr_list);
        }
    }

    list_xfree(alias_list, alias_free);

    return ALIASES_EOK;
}
