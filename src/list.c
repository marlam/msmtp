/*
 * list.c
 *
 * This file is part of msmtp, an SMTP client.
 *
 * Copyright (C) 2000, 2003, 2004, 2005, 2006, 2007
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>

#include "xalloc.h"
#include "list.h"


/*
 * list_new()
 */

list_t *list_new(void)
{
    list_t *head, *foot;

    head = xmalloc(sizeof(list_t));
    foot = xmalloc(sizeof(list_t));
    head->next = foot;
    head->data = NULL;
    foot->next = foot;
    foot->data = NULL;
    return head;
}


/*
 * list_free()
 */

void list_free(list_t *l)
{
    list_t *p;

    while (l->next != l)
    {
        p = l;
        l = l->next;
        free(p);
    }
    free(l);
}


/*
 * list_xfree()
 */

void list_xfree(list_t *l, void (*destruct)(void *))
{
    list_t *p;

    while (l->next != l)
    {
        p = l;
        l = l->next;
        destruct(p->data);
        free(p);
    }
    free(l);
}


/*
 * list_insert()
 */

void list_insert(list_t *l, void *data)
{
    list_t *t;

    t = xmalloc(sizeof(list_t));
    t->data = data;
    t->next = l->next;
    l->next = t;
}


/*
 * list_remove()
 */

void list_remove(list_t *l)
{
    list_t *p;

    p = l->next;
    l->next = l->next->next;
    free(p);
}


/*
 * list_xremove()
 */

void list_xremove(list_t *l, void (*destruct)(void *))
{
    list_t *p;

    p = l->next;
    l->next = l->next->next;
    destruct(p->data);
    free(p);
}


/*
 * list_is_empty()
 */

int list_is_empty(list_t *l)
{
    return (l->next->next == l->next);
}


/*
 * list_last()
 */

list_t *list_last(list_t *e)
{
    while (!(list_is_empty(e)))
    {
        e = e->next;
    }
    return e;
}
