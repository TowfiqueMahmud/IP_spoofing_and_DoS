#!/bin/sh
gcc /syn_flood.c -o /syn_flood -pthread
echo "[+] Running SYN Flood Attack..."
/syn_flood
