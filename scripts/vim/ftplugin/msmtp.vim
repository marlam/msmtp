setlocal commentstring=#\ %s
let b:undo_ftplugin = 'setlocal commmentstring<'

if !has('unix')
  finish
endif

if !has('gui_running')
  command! -buffer -nargs=1 MsmtpKeywordPrg
    \ silent exe '!' . 'LESS= MANPAGER="less --pattern=''\b' . <q-args> . '\b'' --hilite-search --squeeze-blank-lines" MANPAGER= man ' . 'msmtp' |
    \ redraw!
elseif has('terminal')
  command! -buffer -nargs=1 MsmtpKeywordPrg
    \ silent exe 'term ' . 'env LESS= MANPAGER="less --pattern=''\\b' . <q-args> . '\\b'' --hilite-search --squeeze-blank-lines" MANPAGER= man ' . 'msmtp'
else
  finish
endif
setlocal iskeyword+=-
setlocal keywordprg=:MsmtpKeywordPrg

let b:undo_ftplugin .= 'iskeyword< keywordprg<'
