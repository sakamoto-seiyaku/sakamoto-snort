/* SPDX-License-Identifier: Apache-2.0 */
/* Wire-only POSIX profile, shared by Linux Host and Android NDK. No channel,
 * resolver configuration, randomness, event backend or thread implementation. */
#ifndef SAKAMOTO_CARES_CONFIG_H
#define SAKAMOTO_CARES_CONFIG_H
#define HAVE_ARPA_INET_H 1
#define HAVE_ASSERT_H 1
#define HAVE_ERRNO_H 1
#define HAVE_GETENV 1
#define HAVE_INTTYPES_H 1
#define HAVE_LIMITS_H 1
#define HAVE_NETDB_H 1
#define HAVE_NETINET_IN_H 1
#define HAVE_STDINT_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRINGS_H 1
#define HAVE_STRING_H 1
#define HAVE_STRUCT_ADDRINFO 1
#define HAVE_STRUCT_IN6_ADDR 1
#define HAVE_STRUCT_SOCKADDR_IN6 1
#define HAVE_STRUCT_SOCKADDR_STORAGE 1
#define HAVE_STRUCT_TIMEVAL 1
#define HAVE_SYS_SOCKET_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_TIME_H 1
#define HAVE_UNISTD_H 1
#define HAVE_AF_INET6 1
#define HAVE_PF_INET6 1
#define HAVE_INET_NTOP 1
#define HAVE_INET_PTON 1
#define HAVE_STRCASECMP 1
#define HAVE_STRNCASECMP 1
#define HAVE_STRNLEN 1
#endif
