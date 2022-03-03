#!/usr/bin/env python3

import argparse
import base64
import plistlib
import re
import sys
from pathlib import Path

from pyasn1.codec.der.decoder import decode


parser = argparse.ArgumentParser()
parser.add_argument("file", help="OTAUpdate.ips log file to read")
parser.add_argument("--print-bcert", action="store_true", help="print BCert")
parser.add_argument("--print-tss-request", action="store_true", help="print TSS request")
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
        tss_request = base64.b64decode(lines[lines.index(line) + 1])
        if args.print_tss_request:
            print(tss_request.decode())
        tss_request = plistlib.loads(tss_request)
        break

if not tss_request:
    sys.exit("ERROR: Unable to find TSS request in log file")

if "@BCert" not in tss_request:
    sys.exit("ERROR: No BCert found in TSS request")

if args.print_bcert:
    print(base64.b64encode(tss_request["@BCert"]).decode())

asn1, _ = decode(tss_request["@BCert"])
try:
    data = str(asn1[0][-1][-1][-1])
except LookupError:
    sys.exit("ERROR: Unable to find SEP version in BCert")
sep_version = re.search(r"[\d.]+$", data)
if sep_version:
    print("SEP version:", sep_version.group())
else:
    sys.exit("ERROR: Field does not contain SEP version?!")

for line in lines:
    if "STATUS=" in line:
        print(line)
        break
else:
    sys.exit("ERROR: Unable to find TSS response line in log file")
