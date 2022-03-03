#!/usr/bin/env python3

import argparse
import base64
from pathlib import Path
import plistlib
import re
import subprocess
import sys


parser = argparse.ArgumentParser()
parser.add_argument("file", help="OTAUpdate.ips log file to read")
args = parser.parse_args()

tss_request = None

lines = Path(args.file).read_text().splitlines()

for line in lines:
    if "Failed to load update brain trust cache" in line:
        sys.exit("ERROR: Failed to load update brain trust cache. You are probably in a jailbroken state, reboot.")

for line in lines:
    if "Enabling managed request" in line:
        break
else:
    print("WARNING: Managed request line not found in log file. Are you supervised?")

for line in lines:
    if "failed tss request:<<<<<<<<<<" in line:
        tss_request = plistlib.loads(base64.b64decode(lines[lines.index(line) + 1]))
        break

if not tss_request:
    sys.exit("ERROR: Unable to find TSS request in log file")

if "@BCert" not in tss_request:
    sys.exit("ERROR: No BCert found in TSS request")

p = subprocess.run(["openssl", "asn1parse", "-inform", "DER", "-in", "-"], input=tss_request["@BCert"], capture_output=True)
match = False
for line in p.stdout.splitlines():
    if b"1.2.840.113635.100.8.7" in line:
        match = True
        continue
    if match:
        data = bytes.fromhex(line.split(b":")[-1].decode())
        sep_version = re.search(br"[\d.]+$", data)
        if sep_version:
            print("SEP version:", sep_version.group().decode())
            break
else:
    sys.exit("ERROR: Unable to find SEP version in BCert")

for line in lines:
    if "STATUS=" in line:
        print(line)
        break
else:
    sys.exit("ERROR: Unable to find TSS response line in log file")
