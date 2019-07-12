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
#include <stdlib.h>
#include <netdb.h>

#include <fcntl.h>
#include <sys/select.h>

#include <errno.h>

#include "rfc6555.h"

/* Minimal amount of entries to allocate in the context
 *
 * This is 2*2 (A + AAAA, doubled for wiggle room)
 */
#define MIN_CTX_LEN 4

#define CONNECT_TIMEOUT_MS 300

static int rfc6555_context_append(rfc6555_ctx *ctx, int fd, struct addrinfo *rp, int flags);
static int rfc6555_context_grow(rfc6555_ctx *ctx);

rfc6555_ctx *rfc6555_context_create()
{
	rfc6555_ctx *ctx = malloc(sizeof(rfc6555_ctx));
	if (!ctx) {
		return NULL;
	}

	ctx->fds = NULL;
	ctx->original_flags = NULL;
	ctx->rps = NULL;
	ctx->len = 0;
	ctx->max_len = 0;
	ctx->successful_fd = -1;

	if(rfc6555_context_grow(ctx) < 0) {
		rfc6555_context_destroy(ctx);
		return NULL;
	}

	return ctx;
}

/* Append an fd and associated rp to the context.
 * Return the index of the newly-added entries, or -1 on error */
static int rfc6555_context_append(rfc6555_ctx *ctx, int fd, struct addrinfo *rp, int flags)
{
	int idx;
	if(rfc6555_context_grow(ctx) < 0) {
		return -1;
	}

	/* The length is also the next index */
	idx = ctx->len;

	ctx->fds[idx] = fd;
	ctx->original_flags[idx] = flags;
	ctx->rps[idx] = rp;
	ctx->len++;

	return idx;
}

/* Double (or initialise) the size of the allocated storage if the max_len has
 * been reached.
 * Return -1 on error.
 */
#define ALLOC_FIELD(field, dtype, new_len) \
	do { \
		(field) = realloc((field), (new_len) * sizeof(dtype)); \
		if (!(field)) { \
			return -1; \
		} \
	} while(0)

static int rfc6555_context_grow(rfc6555_ctx *ctx)
{
	size_t new_len;

	if(!ctx) {
		return -1;
	}

	if(ctx->len < ctx->max_len) {
		return 0;
	}

	new_len = ctx->max_len * 2;
	if (new_len <= MIN_CTX_LEN) {
		new_len = MIN_CTX_LEN;
	}

	ALLOC_FIELD(ctx->fds, int, new_len);
	ALLOC_FIELD(ctx->original_flags, int, new_len);
	ALLOC_FIELD(ctx->rps, struct addrinfo*, new_len);

	return 0;
}

#define FREE_FIELD(field) \
	do { \
		if((field)) { \
			free((field)); \
		} \
	} while(0)

void rfc6555_context_destroy(rfc6555_ctx *ctx)
{
	int i;

	if(!ctx) {
		return;
	};

	if(ctx->fds) {
		for (i=0; i<ctx->len; i++) {
			/* Cleanup all but the successful sockfd */
			if (ctx->successful_fd != i) {
				close(ctx->fds[i]);
			}
		}
		free(ctx->fds);
	}

	FREE_FIELD(ctx->original_flags);
	FREE_FIELD(ctx->rps);

	free(ctx);
}

int rfc6555_reorder(struct addrinfo *result)
{
	int ret = -1;
	struct addrinfo *rp, *rp6 = NULL, *prev = NULL;

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		if (!rp6 && AF_INET6 == rp->ai_family) {
			rp6 = rp;
		}
		if (AF_INET == rp->ai_family) {
			if (!rp6) {
				/* Found an IPv4 before an IPv6, don't mess up this weird order */
				return -1;
			}
			if (prev != rp6) {
				prev->ai_next = rp->ai_next;
				rp->ai_next = rp6->ai_next;
				rp6->ai_next = rp;
				ret = 0;
			}
			break;
		}
		prev = rp;
	}

	return ret;
}

int rfc6555_connect(rfc6555_ctx *ctx, int sockfd, struct addrinfo **rp)
{
	int fd = -1, maxfd = -1;
	int flags;
	int i;
	fd_set readfds, writefds, errorfds;
	struct timeval timeout = { 0, CONNECT_TIMEOUT_MS * 1000 }, *timeoutp = &timeout;

	flags = fcntl(sockfd, F_GETFL,0);
	fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

	if(connect(sockfd, (*rp)->ai_addr, (*rp)->ai_addrlen) < 0
	   && EINPROGRESS != errno
	) {
		fcntl(sockfd, F_SETFL, flags);
		return -1;
	}
	rfc6555_context_append(ctx, sockfd, *rp, flags);

	FD_ZERO(&readfds);
	for(i=0; i<ctx->len; i++) {
		if(ctx->fds[i]<0) {
			continue;
		}
		FD_SET(ctx->fds[i], &readfds);
		FD_SET(ctx->fds[i], &writefds);
		FD_SET(ctx->fds[i], &errorfds);
		if(ctx->fds[i] > maxfd) {
			maxfd = ctx->fds[i];
		}
	}

	if(NULL == (*rp)->ai_next) {
		/* Don't time out or error on the last RP */
		timeoutp = NULL;
		FD_ZERO(&errorfds);
	}

	if(select(maxfd+1, &readfds, &writefds, &errorfds, timeoutp) <= 0)  {
		if(0 == errno) {
			errno = ETIMEDOUT;
		}
		return -1;
	}

	for(i=0; i<ctx->len; i++) {
		if(FD_ISSET(ctx->fds[i], &readfds)
		   || FD_ISSET(ctx->fds[i], &writefds)
		) {
			fd = ctx->fds[i];
			ctx->successful_fd = i;
			break;
		} else if(FD_ISSET(ctx->fds[i], &errorfds)) {
			/* Neutralise erroneous fd */
			ctx->fds[i] = -1;
			ctx->original_flags[i] = -1;
			ctx->rps[i] = NULL;
		}
	}

	if (-1 != ctx->successful_fd) {
		i = ctx->successful_fd;
		fd = ctx->fds[i];
		fcntl(fd, F_SETFL, ctx->original_flags[i]);
		*rp = ctx->rps[i];
	}
	return fd;
}
