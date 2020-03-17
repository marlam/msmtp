;;; msmtp-config-mode.el --- Mode for msmtp config -*- lexical-binding: t; -*-
;; Copyright (C) 2020 Augustin Fabre

;; Author:      Augustin Fabre <augustin@augfab.fr>
;; Created:     2020-03-15
;; Homepage:    https://git.augfab.fr/mstmp-config-mode
;; Keywords:    msmtp
;; License:     GPL v3+ (https://www.gnu.org/licenses/gpl-3.0.txt)

;; This file is not part of GNU Emacs.

;; This file is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation; either version 3, or (at your option)
;; any later version.

;; This file is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <https://www.gnu.org/licenses/>.

;;; Commentary:

;; * Fontify the configuration file of msmtp <https://marlam.de/msmtp/>.

;;; Code:

(require 'generic)

(defvar msmtp-config--keywords
  '("account"
    "add_missing_date_header"
    "add_missing_from_header"
    "aliases"
    "auth"
    "auto_from"
    "defaults"
    "domain"
    "dsn_notify"
    "dsn_return"
    "from"
    "host"
    "logfile"
    "logfile_time_format"
    "maildomain"
    "ntlmdomain"
    "password"
    "passwordeval"
    "port"
    "protocol"
    "proxy_host"
    "proxy_port"
    "remove_bcc_headers"
    "source_ip"
    "syslog"
    "timeout"
    "tls"
    "tls_cert_file"
    "tls_certcheck"
    "tls_crl_file"
    "tls_fingerprint"
    "tls_key_file"
    "tls_min_dh_prime_bits"
    "tls_priorities"
    "tls_starttls"
    "tls_trust_file"
    "user"))

(define-generic-mode 'msmtp-config-mode
  '("#")
  msmtp-config--keywords
  nil
  '("/\\(\\.msmtprc\\|msmtp/config\\)\\'")
  nil
  "Major mode for msmtp configuration file.")

(provide 'msmtp-config-mode)
;;; msmtp-config-mode.el ends here
