#!/bin/bash
# the --remote-debugging-port is important af
#
file ./chromium/chrome
set args --headless --disable-gpu --remote-debugging-port=1338 --user-data-dir=./sandbox_exp/ --enable-logging=stderr --js-flags=--allow-natives-syntax final.html
set cwd ./sandbox_exp
set  follow-fork-mode parent
