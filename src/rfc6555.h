/*
 * Simple C implementation of [rfc6555] (Happy Eyeballs)
 * Copyright (C) 2019 Olivier Mehani <shtrom@ssji.net>
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * The aim is to provide a (almost) drop-in replacement to the standard
 * [`connect`(3)] system call, so it can be used in the Example loop from
 * [`getaddrinfo`(3)], for ease of integration in existing projects.
 *
 * The latest version of this code is available in Git from:
 *  * https://scm.narf.ssji.net/git/happy-eyeballs-c (authoritative)
 *  * https://github.com/shtrom/happy-eyeballs-c (mirror)
 *
 * What follows is an example diff between a simple GAI implementation based on
 * the manpage, and the updated version to use this drop-in.
 *
 *	--- gai.c	2019-07-10 21:39:59.827667939 +1000
 *	+++ happy.c	2019-07-12 17:15:06.288931156 +1000
 *	@@ -12,10 +12,13 @@
 *	 #include <netdb.h>
 *	 #include <unistd.h>
 *
 *	+#include "rfc6555.h"
 *	+
 *	 int connect_host(char *host, char *service) {
 *		struct addrinfo hints;
 *		struct addrinfo *result, *rp;
 *		int sfd, s;
 *	+	rfc6555_ctx *ctx;
 *
 *		memset(&hints, 0, sizeof(struct addrinfo));
 *		hints.ai_family = AF_UNSPEC;    // Allow IPv4 or IPv6
 *	@@ -34,6 +37,9 @@
 *		  // If socket(2) (or connect(2)) fails, we (close the socket
 *		  // and) try the next address.
 *
 *	+	rfc6555_reorder(result);
 *	+	ctx = rfc6555_context_create();
 *	+
 *		for (rp = result; rp != NULL; rp = rp->ai_next) {
 *			fprintf(stderr, "connecting using rp %p (%s, af %d) ...",
 *					rp,
 *	@@ -44,13 +50,13 @@
 *			if (sfd == -1)
 *				continue;
 *
 *	-		if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
 *	+		if ((sfd = rfc6555_connect(ctx, sfd, &rp)) != -1)
 *				break;                  // Success
 *
 *			fprintf(stderr, " failed!\n");
 *			perror("error: connecting: ");
 *	-		close(sfd);
 *		}
 *	+	rfc6555_context_destroy(ctx);
 *
 *		if (rp == NULL) {               // No address succeeded
 *			fprintf(stderr, "failed! (last attempt)\n");
 *
 * [rfc6555]: https://tools.ietf.org/rfcmarkup/6555
 */
#ifndef __RFC6555_H

#include <unistd.h>
#include <sys/types.h>

typedef struct {
	int* fds;
	int* original_flags;
	struct addrinfo* *rps;
	size_t len;
	size_t max_len;
	int successful_fd;
} rfc6555_ctx;

/* Create context */
rfc6555_ctx *rfc6555_context_create();
/* Destroy context and cleanup resources, except for successful socket, if any */
void rfc6555_context_destroy(rfc6555_ctx *ctx);

/* Loop through result, and place the first-found af_inet entry just after
 * the first af_inet6 entry.
 * Return 0 if this happened, -1 otherwise.
 */
int rfc6555_reorder(struct addrinfo *result);

/* Add a new socket, for rp, to the list, and perform a new select().
 * Return the first socket to successfully connect, or -1 otherwise.
 * Additionally, on successful connection, the rp pointer is updated
 * to match the returned socket.
 */
int rfc6555_connect(rfc6555_ctx *ctx, int sockfd, struct addrinfo **rp);

#endif /*__RFC6555_H */
