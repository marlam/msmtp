#ifndef INET_H
#define INET_H
#define INET_PROTOCOLS_IPV4  (1 << 0) /* Only use IPv4 address resolution. */
#define INET_PROTOCOLS_IPV6  (1 << 1) /* Only use IPv6 address resolution. */
#define INET_PROTOCOLS_ALL   (INET_PROTOCOLS_IPV4 | INET_PROTOCOLS_IPV6) /* Use both IPv4 and IPv6 address resolution. */
#endif
