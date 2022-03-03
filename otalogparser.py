#!/usr/bin/env python3

import argparse
import base64
import plistlib
import re
import subprocess
import sys


parser = argparse.ArgumentParser()
parser.add_argument('file', help='OTAUpdate.ips log file to read')
args = parser.parse_args()

tss_request = None

with open(args.file, 'r') as fd:
    for line in fd.readlines():
        if line.startswith('PD94'):
            tss_request = plistlib.loads(base64.b64decode(line))
            break

if not tss_request:
    sys.exit('ERROR: Unable to find TSS request in log file')

if '@BCert' not in tss_request:
    sys.exit('ERROR: No BCert found in TSS request')

p = subprocess.run(
    ['openssl', 'asn1parse', '-inform', 'DER', '-in', '-'], input=tss_request['@BCert'], capture_output=True
)
match = False
for line in p.stdout.splitlines():
    if b'1.2.840.113635.100.8.7' in line:
        match = True
        continue
    if match:
        data = bytes.fromhex(line.split(b':')[-1].decode())
        sep_version = re.search(br'[\d.]+$', data)
        if sep_version:
            print('SEP version:', sep_version.group().decode())
            sys.exit(0)

sys.exit('ERROR: Unable to find SEP version in BCert')
