/*
 * list.h
 *
 * This file is part of msmtp, an SMTP client.
 *
 * Copyright (C) 2000, 2003, 2004, 2005, 2007
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

#ifndef LIST_H
#define LIST_H

/*
 * A list element stores a pointer to arbitrary data. A list consists of
 * at least one head element and one foot element, both without data
 * (pointer data = NULL). foot->next points to foot.
 */

typedef struct _list
{
    void *data;
    struct _list *next;
} list_t;


/*
 * All list functions use xmalloc() and friends, so they cannot fail.
 */


/*
 * Creates a new, empty list. Returns the pointer to the head element.
 */
list_t *list_new(void);

/*
 * Deletes a complete list, freeing its memory. Needs the head element
 * as parameter. See also list_xfree().
 */
void list_free(list_t *head);

/*
 * Deletes a complete list, freeing its memory and calling destruct() on
 * every data pointer in it. Needs the head element as parameter.
 * See also list_free().
 */
void list_xfree(list_t *head, void (*destruct)(void *));

/*
 * Inserts a new list element storing the pointer data behind the element e.
 */
void list_insert(list_t *e, void *data);

/*
 * Removes the list element behind element e from the list.
 * See also list_xremove().
 */
void list_remove(list_t *e);

/*
 * Removes the list element behind element e from the list and does a free()
 * on the data pointer in this element. See also list_remove().
 */
void list_xremove(list_t *e, void (*destruct)(void *));

/*
 * Returns 1 if the list is empty, 0 otherwise. Needs a pointer to the head
 * element of the list.
 */
int list_is_empty(list_t *head);

/*
 * Returns a pointer to the last element of the list.
 */
list_t *list_last(list_t *e);

#endif
