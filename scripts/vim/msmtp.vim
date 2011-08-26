" Vim syntax file
" Language:     msmtp rc files
" Maintainer:   Simon Ruderich <simon@ruderich.com>
"               Eric Pruitt <eric.pruitt@gmail.com>
" Last Change:  2011-08-21
" Filenames:    msmtprc
" Version:      0.2


if version < 600
  syntax clear
elseif exists("b:current_syntax")
  finish
endif


" Comments.
syn match msmtpComment /#.*$/ contains=@Spell

" General commands.
syntax match msmtpOption /\<\(defaults\|account\|host\|port\|timeout\|protocol\|domain\)\>/
" Authentication commands.
syntax match msmtpOption /\<\(auth\|user\|password\|passwordeval\|ntlmdomain\)\>/
" TLS commands.
syntax match msmtpOption /\<\(tls\|tls_trust_file\|tls_crl_file\|tls_fingerprint\|tls_key_file\|tls_cert_file\|tls_certcheck\|tls_starttls\|tls_force_sslv3\|tls_min_dh_prime_bits\|tls_priorities\)\>/
" Sendmail mode specific commands.
syntax match msmtpOption /\<\(auto_from\|from\|maildomain\|dsn_notify\|dsn_return\|keepbcc\|logfile\|syslog\)\>/

" Options which accept only an on/off value.
syn match msmtpWrongOption /\<\(tls\|tls_certcheck\|tls_starttls\|tls_force_sslv3\|auto_from\|keepbcc\) \(on$\|off$\)\@!.*$/
" Option port accepts numeric values.
syn match msmtpWrongOption /\<port \(\d\+$\)\@!.*$/
" Option timeout accepts off and numeric values.
syn match msmtpWrongOption /\<timeout \(off$\|\d\+$\)\@!.*$/
" Option protocol accepts smtp and lmtp.
syn match msmtpWrongOption /\<protocol \(smtp$\|lmtp$\)\@!.*$/
" Option auth accepts on, off and the method.
syn match msmtpWrongOption /\<auth \(on$\|off$\|plain$\|cram-md5$\|digest-md5$\|scram-sha-1$\|gssapi$\|external$\|login$\|ntlm$\)\@!.*$/
" Option auth accepts on, off and the facility.
syn match msmtpWrongOption /\<syslog \(on$\|off$\|LOG_USER$\|LOG_MAIL$\|LOG_LOCAL\d$\)\@!.*$/

" Marks all wrong option values as errors.
syn match msmtpWrongOptionValue /\S* \zs.*$/ contained containedin=msmtpWrongOption

" Mark the option part as a normal option.
highlight default link msmtpWrongOption msmtpOption

"Email addresses (yanked from esmptrc)
syntax match msmtpAddress /[a-z0-9_.-]*[a-z0-9]\+@[a-z0-9_.-]*[a-z0-9]\+\.[a-z]\+/
" Host names
syn match msmtpHost "\%(host\s*\)\@<=\h\%(\w\|\.\|-\)*"
" Numeric values
syn match msmtpNumber /\<\(\d\+$\)/
"Strings
syntax region msmtpString start=/"/ end=/"/
syntax region msmtpString start=/'/ end=/'/

highlight default link msmtpComment Comment
highlight default link msmtpOption Type
highlight default link msmtpWrongOptionValue Error
highlight default link msmtpString String
highlight default link msmtpAddress Constant
highlight default link msmtpNumber Number
highlight default link msmtpHost Identifier


let b:current_syntax = "msmtp"
