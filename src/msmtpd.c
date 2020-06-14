/*
 * msmtpd.c
 *
 * This file is part of msmtp, an SMTP client.
 *
 * Copyright (C) 2018, 2019  Martin Lambers <marlam@marlam.de>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <getopt.h>
extern char *optarg;
extern int optind;


/* Built-in defaults */
static const char* DEFAULT_INTERFACE = "127.0.0.1";
static const int DEFAULT_PORT = 25;
static const char* DEFAULT_COMMAND = BINDIR "/msmtp -f %F";
static const size_t SMTP_BUFSIZE = 1024; /* must be at least 512 according to RFC2821 */
static const size_t CMD_BLOCK_SIZE = 4096; /* initial buffer size for command */
static const size_t CMD_MAX_BLOCKS = 16; /* limit memory allocation */

/* Read SMTP command from client */
int read_smtp_cmd(FILE* in, char* buf, int bufsize)
{
    if (!fgets(buf, bufsize, in))
        return 1;
    size_t len = strlen(buf);
    if (buf[len - 1] != '\n')
        return 1;
    buf[len - 1] = '\0';
    if (len - 1 > 0 && buf[len - 2] == '\r')
        buf[len - 2] = '\0';
    return 0;
}

/* Read a mail address enclosed in < and > */
int get_addr(const char* inbuf, char* outbuf, int allow_empty, size_t* addrlen)
{
    char* p;

    /* Skip spaces */
    while (*inbuf == ' ')
        inbuf++;
    /* Copy content between '<' and '>' */
    if (inbuf[0] != '<')
        return 1;
    strcpy(outbuf, inbuf + 1);
    size_t len = strlen(outbuf);
    if (len == 0 || outbuf[len - 1] != '>')
        return 1;
    outbuf[--len] = '\0';
    /* Check if characters are valid */
    for (p = outbuf; *p; p++) {
        if ((*p >= 'a' && *p <= 'z')
                || (*p >= 'A' && *p <= 'Z')
                || (*p >= '0' && *p <= '9')
                || *p == '.' || *p == '@' || *p == '_' || *p == '-'
                || *p == '+' || *p == '/') {
            /* Character allowed. Note that this set is very restrictive;
             * more characters might be added to the whitelist if the need
             * arises */
            continue;
        } else {
            /* Invalid character */
            return 1;
        }
    }
    /* Check for special case of zero length */
    if (outbuf[0] == '\0') {
        if (allow_empty) {
            strcpy(outbuf, "MAILER-DAEMON");
            len = 13;
        } else {
            return 1;
        }
    }
    /* Store length */
    *addrlen = len;
    return 0;
}

/* Pipe a mail */
int smtp_pipe(FILE* in, FILE* pipe, char* buf, size_t bufsize)
{
    int line_starts;
    int line_continues;
    size_t len;
    char *p;

    line_continues = 0;
    for (;;) {
        line_starts = !line_continues;
        if (!fgets(buf, bufsize, in))
            return 1;
        len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n') {
            /* first case: we have a line end */
            buf[--len] = '\0';
            if (len > 0 && buf[len - 1] == '\r')
                buf[--len] = '\0';
            line_continues = 0;
        } else if (len == bufsize - 1) {
            /* second case: the line continues */
            if (buf[len - 1] == '\r') {
                /* We have CRLF that is divided by the buffer boundary. Since CR
                 * may not appear alone in a mail according to RFC2822, we
                 * know that the next buffer will be "\n\0", so it's safe to
                 * just delete the CR. */
                buf[--len] = '\0';
            }
            line_continues = 1;
        } else {
            /* third case: this is the last line, and it lacks a newline
             * character */
            line_continues = 0;
        }
        p = buf;
        if (line_starts && buf[0] == '.') {
            if (buf[1] == '\0') {
                /* end of mail */
                break;
            } else {
                /* remove leading dot */
                p = buf + 1;
                len--;
            }
        }
        if (fwrite(p, sizeof(char), len, pipe) != len)
            return 1;
        if (!line_continues && fputc('\n', pipe) == EOF)
            return 1;
    }
    if (fflush(pipe) != 0)
        return 1;
    return 0;
}

/* SMTP session with input and output from FILE descriptors.
 * Mails are piped to the given command, where the first occurrence of %F
 * will be replaced with the envelope-from address, and all recipient addresses
 * will be appended as arguments. */
int msmtpd_session(FILE* in, FILE* out, const char* command)
{
    char buf[SMTP_BUFSIZE];
    char addrbuf[SMTP_BUFSIZE];
    size_t addrlen;
    char* cmd;
    char* tmpcmd;
    size_t cmd_blocks;
    size_t cmd_index;
    int envfrom_was_handled;
    int recipient_was_seen;
    FILE* pipe;
    int pipe_status;
    size_t i;

    setlinebuf(out);
    fprintf(out, "220 localhost ESMTP msmtpd\r\n");
    if (read_smtp_cmd(in, buf, SMTP_BUFSIZE) != 0)
        return 1;
    if (strncmp(buf, "EHLO ", 5) != 0 && strncmp(buf, "HELO ", 5) != 0) {
        fprintf(out, "500 Expected EHLO or HELO\r\n");
        return 1;
    }
    fprintf(out, "250 localhost\r\n");
    if (read_smtp_cmd(in, buf, SMTP_BUFSIZE) != 0)
        return 1;

    for (;;) {
        cmd_index = 0;
        envfrom_was_handled = 0;
        recipient_was_seen = 0;

        if (strncmp(buf, "MAIL FROM:", 10) != 0 && strcmp(buf, "QUIT") != 0) {
            fprintf(out, "500 Expected MAIL FROM:<addr> or QUIT\r\n");
            return 1;
        }
        if (strcmp(buf, "QUIT") == 0) {
            fprintf(out, "221 Bye\r\n");
            return 0;
        }
        if (get_addr(buf + 10, addrbuf, 1, &addrlen) != 0) {
            fprintf(out, "501 Invalid address\r\n");
            return 1;
        }

        cmd_blocks = 1;
        while (cmd_blocks * CMD_BLOCK_SIZE < strlen(command) + addrlen + 2 * SMTP_BUFSIZE)
            cmd_blocks++;
        cmd = malloc(cmd_blocks * CMD_BLOCK_SIZE);
        if (!cmd) {
            fprintf(out, "554 %s\r\n", strerror(ENOMEM));
            return 1;
        }

        for (i = 0; command[i];) {
            if (!envfrom_was_handled && command[i] == '%' && command[i + 1] == 'F') {
                memcpy(cmd + cmd_index, addrbuf, addrlen);
                cmd_index += addrlen;
                i += 2;
                envfrom_was_handled = 1;
            } else {
                cmd[cmd_index] = command[i];
                cmd_index++;
                i++;
            }
        }
        fprintf(out, "250 Ok\r\n");

        for (;;) {
            if (read_smtp_cmd(in, buf, SMTP_BUFSIZE) != 0) {
                free(cmd);
                return 1;
            }
            if (!recipient_was_seen) {
                if (strncmp(buf, "RCPT TO:", 8) != 0) {
                    fprintf(out, "500 Expected RCPT TO:<addr>\r\n");
                    free(cmd);
                    return 1;
                }
            } else {
                if (strncmp(buf, "RCPT TO:", 8) != 0 && strcmp(buf, "DATA") != 0) {
                    fprintf(out, "500 Expected RCPT TO:<addr> or DATA\r\n");
                    free(cmd);
                    return 1;
                }
            }
            if (strcmp(buf, "DATA") == 0) {
                break;
            } else {
                if (get_addr(buf + 8, addrbuf, 0, &addrlen) != 0) {
                    fprintf(out, "501 Invalid address\r\n");
                    free(cmd);
                    return 1;
                }
                if (cmd_index + 1 + addrlen + 1 >= cmd_blocks * CMD_BLOCK_SIZE) {
                    cmd_blocks++;
                    if (cmd_blocks > CMD_MAX_BLOCKS) {
                        fprintf(out, "554 Too many recipients\r\n");
                        free(cmd);
                        return 1;
                    }
                    tmpcmd = realloc(cmd, cmd_blocks * CMD_MAX_BLOCKS);
                    if (!tmpcmd) {
                        free(cmd);
                        fprintf(out, "554 %s\r\n", strerror(ENOMEM));
                        return 1;
                    }
                    cmd = tmpcmd;
                }
                cmd[cmd_index++] = ' ';
                memcpy(cmd + cmd_index, addrbuf, addrlen);
                cmd_index += addrlen;
                fprintf(out, "250 Ok\r\n");
                recipient_was_seen = 1;
            }
        }
        cmd[cmd_index++] = '\0';

        pipe = popen(cmd, "w");
        free(cmd);
        if (!pipe) {
            fprintf(out, "554 Cannot start pipe command\r\n");
            return 1;
        }
        fprintf(out, "354 Send data\r\n");
        if (smtp_pipe(in, pipe, buf, SMTP_BUFSIZE) != 0) {
            fprintf(out, "554 Cannot pipe mail to command\r\n");
            return 1;
        }
        pipe_status = pclose(pipe);
        if (pipe_status == -1 || !WIFEXITED(pipe_status)) {
            fprintf(out, "554 Pipe command failed to execute\r\n");
            return 1;
        } else if (WEXITSTATUS(pipe_status) != 0) {
            fprintf(out, "554 Pipe command reported error %d\r\n", WEXITSTATUS(pipe_status));
            return 1;
        }

        fprintf(out, "250 Ok, mail was piped\r\n");
        if (read_smtp_cmd(in, buf, SMTP_BUFSIZE) != 0)
            break; /* ignore missing QUIT */
    }
    return 0;
}

/* Parse the command line */
int parse_command_line(int argc, char* argv[],
        int* print_version, int* print_help,
        int* inetd,
        const char** interface, int* port,
        const char** command)
{
    enum {
        msmtpd_option_version,
        msmtpd_option_help,
        msmtpd_option_inetd,
        msmtpd_option_port,
        msmtpd_option_interface,
        msmtpd_option_command
    };

    struct option options[] = {
        { "version", no_argument, 0, msmtpd_option_version },
        { "help", no_argument, 0, msmtpd_option_help },
        { "inetd", no_argument, 0, msmtpd_option_inetd },
        { "port", required_argument, 0, msmtpd_option_port },
        { "interface", required_argument, 0, msmtpd_option_interface },
        { "command", required_argument, 0, msmtpd_option_command },
        { 0, 0, 0, 0 }
    };

    for (;;) {
        int c = getopt_long(argc, argv, "", options, NULL);
        if (c == -1)
            break;
        switch (c) {
        case msmtpd_option_version:
            *print_version = 1;
            break;
        case msmtpd_option_help:
            *print_help = 1;
            break;
        case msmtpd_option_inetd:
            *inetd = 1;
            break;
        case msmtpd_option_port:
            *port = atoi(optarg);
            break;
        case msmtpd_option_interface:
            *interface = optarg;
            break;
        case msmtpd_option_command:
            *command = optarg;
            break;
        default:
            return 1;
            break;
        }
    }
    if (argc - optind > 0) {
        fprintf(stderr, "%s: too many arguments\n", argv[0]);
        return 1;
    }
    return 0;
}

int main(int argc, char* argv[])
{
    /* Exit status values according to LSB init script recommendations */
    const int exit_ok = 0;
    const int exit_not_running = 3;

    /* Configuration */
    int print_version = 0;
    int print_help = 0;
    int inetd = 0;
    const char* interface = DEFAULT_INTERFACE;
    int port = DEFAULT_PORT;
    const char* command = DEFAULT_COMMAND;

    /* Command line */
    if (parse_command_line(argc, argv,
                &print_version, &print_help,
                &inetd, &interface, &port, &command) != 0) {
        return exit_not_running;
    }
    if (print_version) {
        printf("msmtpd version %s\n", VERSION);
        printf("Copyright (C) 2018 Martin Lambers.\n"
                "This is free software.  You may redistribute copies of it under the terms of\n"
                "the GNU General Public License <http://www.gnu.org/licenses/gpl.html>.\n"
                "There is NO WARRANTY, to the extent permitted by law.\n");
        return exit_ok;
    }
    if (print_help) {
        printf("Usage: msmtpd [option...]\n");
        printf("Options:\n");
        printf("  --version       print version\n");
        printf("  --help          print help\n");
        printf("  --inetd         start single SMTP session on stdin/stdout\n");
        printf("  --interface=ip  listen on ip instead of %s\n", DEFAULT_INTERFACE);
        printf("  --port=number   listen on port number instead of %d\n", DEFAULT_PORT);
        printf("  --command=cmd   pipe mails to cmd instead of %s\n", DEFAULT_COMMAND);
        return exit_ok;
    }

    /* Do it */
    signal(SIGPIPE, SIG_IGN); /* Do not terminate when piping fails; we want to handle that error */
    if (inetd) {
        /* We are no daemon, so we can just signal error with exit status 1 and success with 0 */
        return msmtpd_session(stdin, stdout, command);
    } else {
        int ipv6;
        struct sockaddr_in6 sa6;
        struct sockaddr_in sa4;
        int listen_fd;
        int on = 1;

        /* Set interface */
        memset(&sa6, 0, sizeof(sa6));
        if (inet_pton(AF_INET6, interface, &sa6.sin6_addr) != 0) {
            ipv6 = 1;
            sa6.sin6_family = AF_INET6;
            sa6.sin6_port = htons(port);
        } else {
            memset(&sa4, 0, sizeof(sa4));
            if (inet_pton(AF_INET, interface, &sa4.sin_addr) != 0) {
                ipv6 = 0;
                sa4.sin_family = AF_INET;
                sa4.sin_port = htons(port);
            } else {
                fprintf(stderr, "%s: invalid interface\n", argv[0]);
                return exit_not_running;
            }
        }

        /* Create and set up listening socket */
        listen_fd = socket(ipv6 ? PF_INET6 : PF_INET, SOCK_STREAM, 0);
        if (listen_fd < 0) {
            fprintf(stderr, "%s: cannot create socket: %s\n", argv[0], strerror(errno));
            return exit_not_running;
        }
        if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
            fprintf(stderr, "%s: cannot set socket option: %s\n", argv[0], strerror(errno));
            return exit_not_running;
        }
        if (bind(listen_fd,
                    ipv6 ? (struct sockaddr*)&sa6 : (struct sockaddr*)&sa4,
                    ipv6 ? sizeof(sa6) : sizeof(sa4)) < 0) {
            fprintf(stderr, "%s: cannot bind to %s:%d: %s\n", argv[0], interface, port, strerror(errno));
            return exit_not_running;
        }
        if (listen(listen_fd, 128) < 0) {
            fprintf(stderr, "%s: cannot listen on socket: %s\n", argv[0], strerror(errno));
            return exit_not_running;
        }

        /* Set up signal handling, in part conforming to freedesktop.org modern daemon requirements */
        signal(SIGHUP, SIG_IGN); /* Reloading configuration does not make sense for us */
        signal(SIGTERM, SIG_DFL); /* We can be terminated as long as there is no running session */
        signal(SIGCHLD, SIG_IGN); /* Make sure child processes do not become zombies */

        /* Accept connection */
        for (;;) {
            int conn_fd = accept(listen_fd, NULL, NULL);
            if (conn_fd < 0) {
                fprintf(stderr, "%s: cannot accept connection: %s\n", argv[0], strerror(errno));
                return exit_not_running;
            }
            if (fork() == 0) {
                /* Child process */
                FILE* conn;
                int ret;
                signal(SIGTERM, SIG_IGN); /* A running session should not be terminated */
                signal(SIGCHLD, SIG_DFL); /* Make popen()/pclose() work again */
                conn = fdopen(conn_fd, "rb+");
                ret = msmtpd_session(conn, conn, command);
                fclose(conn);
                exit(ret); /* exit status does not really matter since nobody checks it, but still... */
            } else {
                /* Parent process */
                close(conn_fd);
            }
        }
    }

    return exit_ok;
}
