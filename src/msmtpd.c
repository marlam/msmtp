/*
 * msmtpd.c
 *
 * This file is part of msmtp, an SMTP client.
 *
 * Copyright (C) 2018, 2019, 2020, 2021, 2022
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

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/wait.h>
#include <time.h>
#include <syslog.h>
#include <sysexits.h>
#include <getopt.h>
extern char *optarg;
extern int optind;

#include "base64.h"
#include "password.h"
#include "eval.h"
#include "tools.h"
#include "xalloc.h"


/* Built-in defaults */
static const char* DEFAULT_INTERFACE = "127.0.0.1";
static const int DEFAULT_PORT = 25;
static const int MAX_ACTIVE_SESSIONS = 16;
static const int AUTH_DELAY_SECONDS = 1;
static const int AUTH_DELAY_EXPIRATION_SECONDS = 60;
static const char* DEFAULT_COMMAND = BINDIR "/msmtp -f %F --";
static const size_t SMTP_BUFSIZE = 1024; /* must be at least 512 according to RFC2821 */
static const size_t CMD_BLOCK_SIZE = 4096; /* initial buffer size for command */
static const size_t CMD_MAX_BLOCKS = 16; /* limit memory allocation */

/* Logging */

typedef enum {
    log_info = 0,
    log_error = 1,
    log_nothing = 2
} log_level_t;

typedef struct {
    FILE* file; /* if NULL then use syslog */
    log_level_t level;
} log_t;

void log_open(int log_to_syslog, const char* log_file_name, log_t* log)
{
    log->file = NULL;
    log->level = log_info; /* default currently hard-coded */
    int log_file_open_failure = 0;
    if (log_file_name) {
        log->file = fopen(log_file_name, "a");
        if (!log->file) {
            log_file_open_failure = 1;
            log_to_syslog = 1;
        }
    }
    if (log_to_syslog) {
        openlog("msmtpd", LOG_PID, LOG_MAIL);
        if (log_file_open_failure)
            syslog(LOG_ERR, "cannot open log file, using syslog instead");
    }
    if (!log_file_name && !log_to_syslog) {
        log->level = log_nothing;
    }
}

void log_close(log_t* log)
{
    if (log->level < log_nothing) {
        if (log->file)
            fclose(log->file);
        else
            closelog();
    }
}

void
#ifdef __GNUC__
__attribute__ ((format (printf, 3, 4)))
#endif
log_msg(log_t* log,
        log_level_t msg_level,
        const char* msg_format, ...)
{
    if (msg_level >= log->level) {
        if (log->file) {
            long long pid = getpid();
            time_t t = time(NULL);
            struct tm* tm = localtime(&t);
            char time_str[128];
            strftime(time_str, sizeof(time_str), "%F %T", tm);
            fprintf(log->file, "%s msmtpd[%lld] %s: ", time_str, pid,
                    msg_level >= log_error ? "error" : "info");
            va_list args;
            va_start(args, msg_format);
            vfprintf(log->file, msg_format, args);
            va_end(args);
            fputc('\n', log->file);
        } else {
            int priority = (msg_level >= log_error ? LOG_ERR : LOG_INFO);
            va_list args;
            va_start(args, msg_format);
            vsyslog(priority, msg_format, args);
            va_end(args);
        }
    }
}

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
                || (p > outbuf && *p == '-') /* must not start with hyphen */
                || *p == '.' || *p == '@' || *p == '_'
                || *p == '+' || *p == '/'
                || *p == '=') {
            /* Character allowed. Note that this set is very restrictive;
             * more characters might be added to the whitelist if the need
             * arises. But beware: mail addresses will be part of the
             * mail pipe command line and therefore will be passed to a shell. */
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
    if (fflush(pipe) != 0 || ferror(pipe))
        return 1;
    return 0;
}

/* Get the local and remote IP addresses and host names */

typedef struct {
    char local_ip[INET6_ADDRSTRLEN+1];
    char local_name[NI_MAXHOST];
    char remote_ip[INET6_ADDRSTRLEN+1];
    char remote_name[NI_MAXHOST];
} connection_info_t;

void get_connection_info(int socket, connection_info_t* info)
{
    struct sockaddr_storage ss;
    socklen_t ss_len;
    ss_len = sizeof(ss);
    info->local_ip[0] = '\0';
    info->local_name[0] = '\0';
    if (getsockname(socket, (struct sockaddr*)&ss, &ss_len) == 0) {
        if (ss.ss_family == AF_INET6) {
            inet_ntop(AF_INET6, &(((struct sockaddr_in6*)&ss)->sin6_addr), info->local_ip, sizeof(info->local_ip));
        } else if (ss.ss_family == AF_INET) {
            inet_ntop(AF_INET, &(((struct sockaddr_in*)&ss)->sin_addr), info->local_ip, sizeof(info->local_ip));
        }
        getnameinfo((struct sockaddr*)&ss, sizeof(ss), info->local_name, sizeof(info->local_name), NULL, 0, NI_NAMEREQD);
    }
    ss_len = sizeof(ss);
    info->remote_ip[0] = '\0';
    info->remote_name[0] = '\0';
    if (getpeername(socket, (struct sockaddr*)&ss, &ss_len) == 0) {
        if (ss.ss_family == AF_INET6) {
            inet_ntop(AF_INET6, &(((struct sockaddr_in6*)&ss)->sin6_addr), info->remote_ip, sizeof(info->remote_ip));
        } else if (ss.ss_family == AF_INET) {
            inet_ntop(AF_INET, &(((struct sockaddr_in*)&ss)->sin_addr), info->remote_ip, sizeof(info->remote_ip));
        }
        getnameinfo((struct sockaddr*)&ss, sizeof(ss), info->remote_name, sizeof(info->remote_name), NULL, 0, NI_NAMEREQD);
    }
}

/* SMTP session with input and output from FILE descriptors.
 * Mails are piped to the given command, where the first occurrence of %F
 * will be replaced with the envelope-from address, and all recipient addresses
 * will be appended as arguments.
 *
 * Return value:
 * 0 if the session ended normally / successfully
 * 1 if the session had errors and/or was aborted
 * 2 same as 1 and the session had authentication failures
 * */
int msmtpd_session(log_t* log,
        FILE* in, FILE* out,
        const connection_info_t* info,
        const char* command,
        const char* user, const char* password, int impose_auth_delay)
{
    char buf[SMTP_BUFSIZE];
    char buf2[SMTP_BUFSIZE];
    char ehlo_name[SMTP_BUFSIZE];
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

    log_msg(log, log_info, "starting SMTP session");
    setlinebuf(out);
    fprintf(out, "220 localhost ESMTP msmtpd\r\n");
    /* expect EHLO or HELO */
    if (read_smtp_cmd(in, buf, SMTP_BUFSIZE) != 0) {
        log_msg(log, log_error, "client did not send initial command, session aborted");
        return 1;
    }
    if (strncasecmp(buf, "EHLO ", 5) != 0 && strncasecmp(buf, "HELO ", 5) != 0) {
        fprintf(out, "500 Expected EHLO or HELO\r\n");
        log_msg(log, log_error, "client did not start with EHLO or HELO, session aborted");
        return 1;
    }
    /* save EHLO name for the Received header, but sanitize it */
    if (buf[5] == '\0') {
        strcpy(ehlo_name, "unknown");
    } else {
        strcpy(ehlo_name, buf + 5);
        for (i = 0; ehlo_name[i]; i++) {
            if (!((i == 0 && ehlo_name[i] == '[') || (ehlo_name[i + 1] == '\0' && ehlo_name[i] == ']')
                        || (ehlo_name[i] >= 'a' && ehlo_name[i] <= 'z')
                        || (ehlo_name[i] >= 'A' && ehlo_name[i] <= 'Z')
                        || (ehlo_name[i] >= '0' && ehlo_name[i] <= '9')
                        || (ehlo_name[i] == '.' || ehlo_name[i] == ':' || ehlo_name[i] == '-'))) {
                strcpy(ehlo_name, "invalid");
                break;
            }
        }
    }
    /* send EHLO/HELO response */
    if (user && strncasecmp(buf, "EHLO ", 5) == 0) {
        fprintf(out, "250-localhost\r\n");
        fprintf(out, "250 AUTH PLAIN\r\n");
    } else {
        fprintf(out, "250 localhost\r\n");
    }
    if (read_smtp_cmd(in, buf, SMTP_BUFSIZE) != 0) {
        log_msg(log, log_error, "client did not send second command, session aborted");
        return 1;
    }

    if (user) {
        if (strcmp(buf, "QUIT") == 0) {
            fprintf(out, "221 Bye\r\n");
            log_msg(log, log_info, "client ended session");
            return 0;
        }
        if (strncasecmp(buf, "AUTH PLAIN", 10) != 0) {
            fprintf(out, "530 Authentication required\r\n");
            log_msg(log, log_info, "client did not authenticate, session aborted");
            return 1;
        }
        const char* b64 = NULL;
        if (buf[10] == ' ') {
            b64 = buf + 11;
        } else {
            fprintf(out, "334 \r\n");
            if (read_smtp_cmd(in, buf, SMTP_BUFSIZE) != 0) {
                log_msg(log, log_error, "client did not send authentication information, session aborted");
                return 1;
            }
            b64 = buf;
        }
        size_t buf2_len = SMTP_BUFSIZE;
        bool r = base64_decode_ctx(NULL, b64, strlen(b64), buf2, &buf2_len);
        int authenticated = 0;
        if (r && buf2_len == 1 + strlen(user) + 1 + strlen(password)
                && buf2[0] == '\0'
                && strncmp(buf2 + 1, user, strlen(user)) == 0
                && buf2[1 + strlen(user)] == '\0'
                && strncmp(buf2 + 1 + strlen(user) + 1, password, strlen(password)) == 0) {
            authenticated = 1;
        }
        if (impose_auth_delay)
            sleep(AUTH_DELAY_SECONDS);
        if (!authenticated) {
            fprintf(out, "535 Authentication failed\r\n");
            log_msg(log, log_error, "authentication failed, session aborted");
            return 2;
        } else {
            fprintf(out, "235 Authentication successful\r\n");
            log_msg(log, log_info, "authenticated user %s", user);
        }
        if (read_smtp_cmd(in, buf, SMTP_BUFSIZE) != 0) {
            log_msg(log, log_error, "client did not send command after authentication, session aborted");
            return 1;
        }
    }

    for (;;) {
        cmd_index = 0;
        envfrom_was_handled = 0;
        recipient_was_seen = 0;

        if (strncasecmp(buf, "MAIL FROM:", 10) != 0 && strcasecmp(buf, "QUIT") != 0) {
            fprintf(out, "500 Expected MAIL FROM:<addr> or QUIT\r\n");
            log_msg(log, log_error, "client did not send MAIL FROM or QUIT, session aborted");
            return 1;
        }
        if (strcasecmp(buf, "QUIT") == 0) {
            fprintf(out, "221 Bye\r\n");
            log_msg(log, log_info, "client ended session");
            return 0;
        }
        if (get_addr(buf + 10, buf2, 1, &addrlen) != 0) {
            fprintf(out, "501 Invalid address\r\n");
            log_msg(log, log_error, "invalid address in MAIL FROM, session aborted");
            return 1;
        }

        cmd_blocks = 1;
        while (cmd_blocks * CMD_BLOCK_SIZE < strlen(command) + addrlen + 2 * SMTP_BUFSIZE)
            cmd_blocks++;
        cmd = malloc(cmd_blocks * CMD_BLOCK_SIZE);
        if (!cmd) {
            fprintf(out, "554 %s\r\n", strerror(ENOMEM));
            log_msg(log, log_error, "%s, session aborted", strerror(ENOMEM));
            return 1;
        }

        for (i = 0; command[i];) {
            if (!envfrom_was_handled && command[i] == '%' && command[i + 1] == 'F') {
                memcpy(cmd + cmd_index, buf2, addrlen);
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
                log_msg(log, log_error, "client did not send command, session aborted");
                free(cmd);
                return 1;
            }
            if (!recipient_was_seen) {
                if (strncasecmp(buf, "RCPT TO:", 8) != 0) {
                    fprintf(out, "500 Expected RCPT TO:<addr>\r\n");
                    log_msg(log, log_error, "client did not send RCPT TO, session aborted");
                    free(cmd);
                    return 1;
                }
            } else {
                if (strncasecmp(buf, "RCPT TO:", 8) != 0 && strcasecmp(buf, "DATA") != 0) {
                    fprintf(out, "500 Expected RCPT TO:<addr> or DATA\r\n");
                    log_msg(log, log_error, "client did not send RCPT TO or DATA, session aborted");
                    free(cmd);
                    return 1;
                }
            }
            if (strcasecmp(buf, "DATA") == 0) {
                break;
            } else {
                if (get_addr(buf + 8, buf2, 0, &addrlen) != 0) {
                    fprintf(out, "501 Invalid address\r\n");
                    log_msg(log, log_error, "invalid address in RCPT TO, session aborted");
                    free(cmd);
                    return 1;
                }
                if (cmd_index + 1 + addrlen + 1 >= cmd_blocks * CMD_BLOCK_SIZE) {
                    cmd_blocks++;
                    if (cmd_blocks > CMD_MAX_BLOCKS) {
                        fprintf(out, "554 Too many recipients\r\n");
                        log_msg(log, log_error, "too many recipients, session aborted");
                        free(cmd);
                        return 1;
                    }
                    tmpcmd = realloc(cmd, cmd_blocks * CMD_MAX_BLOCKS);
                    if (!tmpcmd) {
                        fprintf(out, "554 %s\r\n", strerror(ENOMEM));
                        log_msg(log, log_error, "%s, session aborted", strerror(ENOMEM));
                        free(cmd);
                        return 1;
                    }
                    cmd = tmpcmd;
                }
                cmd[cmd_index++] = ' ';
                memcpy(cmd + cmd_index, buf2, addrlen);
                cmd_index += addrlen;
                fprintf(out, "250 Ok\r\n");
                recipient_was_seen = 1;
            }
        }
        cmd[cmd_index++] = '\0';

        log_msg(log, log_info, "pipe command is %s", cmd);
        pipe = popen(cmd, "w");
        free(cmd);
        if (!pipe) {
            fprintf(out, "554 Cannot start pipe command\r\n");
            log_msg(log, log_error, "cannot start pipe command, session aborted");
            return 1;
        }
        /* first add a Received: header */
        char rfc2822_timestamp[32];
        print_time_rfc2822(time(NULL), rfc2822_timestamp);
        fprintf(pipe, "Received: from %s (", ehlo_name);
        if (info->remote_name[0])
            fprintf(pipe, "%s ", info->remote_name);
        fprintf(pipe, "[%s])\r\n\tby ", info->remote_ip);
        if (info->local_name[0])
            fprintf(pipe, "%s ", info->local_name);
        fprintf(pipe, "[%s] (msmtpd) with ESMTP;\r\n", info->local_ip);
        fprintf(pipe, "\t%s\r\n", rfc2822_timestamp);
        /* then pipe the mail */
        fprintf(out, "354 Send data\r\n");
        if (smtp_pipe(in, pipe, buf, SMTP_BUFSIZE) != 0) {
            fprintf(out, "554 Cannot pipe mail to command\r\n");
            log_msg(log, log_error, "cannot pipe mail to command, session aborted");
            return 1;
        }
        pipe_status = pclose(pipe);
        if (pipe_status == -1 || !WIFEXITED(pipe_status)) {
            fprintf(out, "554 Pipe command failed to execute\r\n");
            log_msg(log, log_error, "pipe command failed to execute, session aborted");
            return 1;
        } else if (WEXITSTATUS(pipe_status) != 0) {
            int return_code = 554; /* permanent error */
            switch (WEXITSTATUS(pipe_status)) {
            case EX_NOHOST:
            case EX_UNAVAILABLE:
            case EX_OSERR:
            case EX_TEMPFAIL:
                return_code = 451; /* temporary error */
                break;
            case EX_USAGE:
            case EX_DATAERR:
            case EX_NOINPUT:
            case EX_SOFTWARE:
            case EX_OSFILE:
            case EX_CANTCREAT:
            case EX_IOERR:
            case EX_PROTOCOL:
            case EX_NOPERM:
            case EX_CONFIG:
            default:
                break;
            }
            fprintf(out, "%d Pipe command reported error %d\r\n", return_code, WEXITSTATUS(pipe_status));
            log_msg(log, log_error, "pipe command reported error %d, session aborted", WEXITSTATUS(pipe_status));
            return 1;
        }

        fprintf(out, "250 Ok, mail was piped\r\n");
        log_msg(log, log_info, "mail was piped successfully");
        if (read_smtp_cmd(in, buf, SMTP_BUFSIZE) != 0) {
            log_msg(log, log_info, "client ended session without sending QUIT");
            break; /* ignore missing QUIT */
        }
    }
    return 0;
}

/* Manage the maximum number of concurrent sessions and impose a delay to
 * authentication requests after an authentication failure occured, to make
 * brute force attacks infeasible */

volatile sig_atomic_t active_sessions_count;
volatile sig_atomic_t auth_failure_occurred;
volatile time_t last_auth_failure_time;

void sigchld_action(int signum, siginfo_t* si, void* ucontext)
{
    (void)signum;   /* unused */
    (void)ucontext; /* unused */
    int wstatus;
    if (waitpid(si->si_pid, &wstatus, 0) == si->si_pid) {
        int child_exit_status = -1;
        if (WIFEXITED(wstatus))
            child_exit_status = WEXITSTATUS(wstatus);
        if (child_exit_status >= 2) {
            struct timespec tp;
            clock_gettime(CLOCK_MONOTONIC, &tp);
            last_auth_failure_time = tp.tv_sec;
            auth_failure_occurred = 1;
        }
        active_sessions_count--;
    }
}

/* Parse the command line */
int parse_command_line(int argc, char* argv[],
        int* print_version, int* print_help,
        int* inetd,
        const char** interface, int* port,
        int* log_to_syslog, const char** log_file,
        const char** command,
        char** user, char** password)
{
    enum {
        msmtpd_option_version,
        msmtpd_option_help,
        msmtpd_option_inetd,
        msmtpd_option_port,
        msmtpd_option_interface,
        msmtpd_option_log,
        msmtpd_option_command,
        msmtpd_option_auth
    };

    struct option options[] = {
        { "version", no_argument, 0, msmtpd_option_version },
        { "help", no_argument, 0, msmtpd_option_help },
        { "inetd", no_argument, 0, msmtpd_option_inetd },
        { "port", required_argument, 0, msmtpd_option_port },
        { "interface", required_argument, 0, msmtpd_option_interface },
        { "log", required_argument, 0, msmtpd_option_log },
        { "command", required_argument, 0, msmtpd_option_command },
        { "auth", required_argument, 0, msmtpd_option_auth },
        { 0, 0, 0, 0 }
    };

    for (;;) {
        int option_index = -1;
        int c = getopt_long(argc, argv, "", options, &option_index);
        if (c == -1)
            break;
        if (optarg && optarg[0] == '\0') {
            fprintf(stderr, "%s: option '--%s' requires non-empty argument\n", argv[0],
                    options[option_index].name);
            return 1;
        }
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
        case msmtpd_option_log:
            if (strcmp(optarg, "none") == 0) {
                *log_to_syslog = 0;
                *log_file = NULL;
            } else if (strcmp(optarg, "syslog") == 0) {
                *log_to_syslog = 1;
                *log_file = NULL;
            } else {
                *log_to_syslog = 0;
                *log_file = optarg;
            }
            break;
        case msmtpd_option_command:
            *command = optarg;
            break;
        case msmtpd_option_auth:
            {
                char* comma = strchr(optarg, ',');
                if (!comma) {
                    char* tmp_user = xstrdup(optarg);
                    char* tmp_password = password_get("localhost", tmp_user, password_service_smtp, 0, 0);
                    if (!tmp_password) {
                        fprintf(stderr, "%s: cannot get password for (localhost, smtp, %s)\n",
                                argv[0], tmp_user);
                        free(tmp_user);
                        return 1;
                    }
                    free(*user);
                    *user = tmp_user;
                    free(*password);
                    *password = tmp_password;
                } else {
                    char* tmp_user = xstrndup(optarg, comma - optarg);
                    char* tmp_password = NULL;
                    char* errstr = NULL;
                    if (eval(comma + 1, &tmp_password, &errstr) != 0) {
                        fprintf(stderr, "%s: cannot get password: %s\n", argv[0], errstr);
                        free(tmp_user);
                        free(errstr);
                        return 1;
                    }
                    free(*user);
                    *user = tmp_user;
                    free(*password);
                    *password = tmp_password;
                }
            }
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
    int log_to_syslog = 0;
    const char* log_file = NULL;
    const char* command = DEFAULT_COMMAND;
    char* user = NULL;
    char* password = NULL;

    /* Command line */
    if (parse_command_line(argc, argv,
                &print_version, &print_help,
                &inetd, &interface, &port,
                &log_to_syslog, &log_file,
                &command,
                &user, &password) != 0) {
        return exit_not_running;
    }
    if (print_version) {
        printf("msmtpd version %s\n", VERSION);
        printf("Copyright (C) 2021 Martin Lambers.\n"
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
        printf("  --log=none|syslog|FILE  do not log anything (default)\n");
        printf("                  or log to syslog or log to the given file\n");
        printf("  --command=cmd   pipe mails to cmd instead of %s\n", DEFAULT_COMMAND);
        printf("  --auth=user[,passwordeval] require authentication with this user name;\n");
        printf("                  the password will be retrieved from the given\n");
        printf("                  passwordeval command or, if none is given, from\n");
        printf("                  the key ring or, if that fails, from a prompt.\n");
        return exit_ok;
    }

    /* Do it */
    connection_info_t info;
    int ret = exit_ok;
    signal(SIGPIPE, SIG_IGN); /* Do not terminate when piping fails; we want to handle that error */
    if (inetd) {
        /* We are no daemon, so we can just signal error with exit status 1 and success with 0 */
        log_t log;
        log_open(log_to_syslog, log_file, &log);
        int impose_auth_delay = 1; /* since we cannot keep track of auth failures in inetd mode */
        get_connection_info(fileno(stdin), &info);
        ret = msmtpd_session(&log, stdin, stdout, &info, command,
                user, password, impose_auth_delay);
        ret = (ret == 0 ? 0 : 1);
        log_close(&log);
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
                ret = exit_not_running;
                goto exit;
            }
        }

        /* Create and set up listening socket */
        listen_fd = socket(ipv6 ? PF_INET6 : PF_INET, SOCK_STREAM, 0);
        if (listen_fd < 0) {
            fprintf(stderr, "%s: cannot create socket: %s\n", argv[0], strerror(errno));
            ret = exit_not_running;
            goto exit;
        }
        if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
            fprintf(stderr, "%s: cannot set socket option: %s\n", argv[0], strerror(errno));
            ret = exit_not_running;
            goto exit;
        }
        if (bind(listen_fd,
                    ipv6 ? (struct sockaddr*)&sa6 : (struct sockaddr*)&sa4,
                    ipv6 ? sizeof(sa6) : sizeof(sa4)) < 0) {
            fprintf(stderr, "%s: cannot bind to %s:%d: %s\n", argv[0], interface, port, strerror(errno));
            ret = exit_not_running;
            goto exit;
        }
        if (listen(listen_fd, 128) < 0) {
            fprintf(stderr, "%s: cannot listen on socket: %s\n", argv[0], strerror(errno));
            ret = exit_not_running;
            goto exit;
        }

        /* Set up signal handling, in part conforming to freedesktop.org modern daemon requirements */
        signal(SIGHUP, SIG_IGN); /* Reloading configuration does not make sense for us */
        signal(SIGTERM, SIG_DFL); /* We can be terminated as long as there is no running session */

        /* Set SIGCHLD signal handler to manage maximum number of active sessions and impose
         * authentication delays in case of authentication failures (to make brute force attacks unfeasible) */
        active_sessions_count = 0;
        auth_failure_occurred = 0;
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_flags = SA_NOCLDSTOP | SA_SIGINFO | SA_RESTART; /* SA_RESTART: restart accept() after SIGCHLD */
        sa.sa_sigaction = sigchld_action;
        sigaction(SIGCHLD, &sa, NULL); /* cannot fail */

        /* Accept connection */
        for (;;) {
            while (active_sessions_count >= MAX_ACTIVE_SESSIONS) {
                sleep(1);
            }
            socklen_t client_len = ipv6 ? sizeof(sa6) : sizeof(sa4);
            int conn_fd = accept(listen_fd, ipv6 ? (struct sockaddr*)&sa6 : (struct sockaddr*)&sa4, &client_len);
            if (conn_fd < 0) {
                fprintf(stderr, "%s: cannot accept connection: %s\n", argv[0], strerror(errno));
                ret = exit_not_running;
                break;
            }
            get_connection_info(conn_fd, &info);
            pid_t pid = fork();
            if (pid == 0) {
                /* Child process */
                int impose_auth_delay = 0;
                if (auth_failure_occurred) {
                    struct timespec tp;
                    clock_gettime(CLOCK_MONOTONIC, &tp);
                    int seconds_since_last_auth_failure = tp.tv_sec - last_auth_failure_time;
                    if (seconds_since_last_auth_failure <= AUTH_DELAY_EXPIRATION_SECONDS)
                        impose_auth_delay = 1;
                }
                signal(SIGTERM, SIG_IGN); /* A running session should not be terminated */
                signal(SIGCHLD, SIG_DFL); /* Make popen()/pclose() work again */
                log_t log;
                log_open(log_to_syslog, log_file, &log);
                log_msg(&log, log_info, "connection from %s, active sessions %d (max %d), auth_delay=%s",
                        info.remote_ip, active_sessions_count + 1, MAX_ACTIVE_SESSIONS,
                        impose_auth_delay ? "yes" : "no");
                FILE* conn = fdopen(conn_fd, "rb+");
                int ret = msmtpd_session(&log, conn, conn, &info, command,
                        user, password, impose_auth_delay);
                fclose(conn);
                log_msg(&log, log_info, "connection closed");
                log_close(&log);
                exit(ret);
            } else {
                /* Parent process */
                close(conn_fd);
                if (pid > 0) {
                    active_sessions_count++;
                } else {
                    fprintf(stderr, "%s: fork failed: %s\n", argv[0], strerror(errno));
                    ret = exit_not_running;
                    break;
                }
            }
        }
    }

exit:
    free(user);
    free(password);
    return ret;
}

/* Die if memory allocation fails. Note that we only use xalloc() etc
 * during startup; one msmtpd is running, out of memory conditions are
 * handled gracefully. */

void xalloc_die(void)
{
    fputs(strerror(ENOMEM), stderr);
    fputc('\n', stderr);
    exit(3);
}
