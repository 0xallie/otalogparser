#!/usr/bin/env python3

import argparse
import base64
import plistlib
import re
import sys
from datetime import datetime
from pathlib import Path

from packaging import version
from pyasn1.codec.der.decoder import decode
from rich import print


def info(msg):
    print(f"[bold white]ℹ️ {msg}[/bold white]")


def success(msg):
    print(f"[bold green]✅ {msg}[/bold green]")


def warning(msg):
    print(f"[bold yellow]⚠️ {msg}[/bold yellow]")


def error(msg):
    print(f"[bold red]❌ {msg}[/bold red]")


def fatal(msg):
    error(msg)
    sys.exit(1)


parser = argparse.ArgumentParser()
parser.add_argument("file", help="OTAUpdate.ips log file to read")
parser.add_argument("--print-bcert", action="store_true", help="print BCert")
parser.add_argument("--print-tss-request", action="store_true", help="print TSS request")
args = parser.parse_args()

tss_request = None

lines = Path(args.file).read_text().splitlines()

for line in lines:
    if "Failed to load update brain trust cache" in line:
        fatal("Failed to load update brain trust cache. You are probably in a jailbroken state, reboot.")

for line in lines:
    if "Enabling managed request" in line:
        break
else:
    warning("Managed request line not found in log file. Are you supervised?")

for line in lines:
    if m := re.search(r"Still short (\d+) free space bytes", line):
        size = int(m.group(1))
        if size >= 1024**3:
            size = f"{size / 1000**3:.2f} GB"
        else:
            size = f"{size / 1000**2:.2f} MB"
        warning(f"Update needs {size} more free space")

for line in lines:
    if m := re.search(r"preallocation of (\d+) bytes failed", line):
        size = int(m.group(1))
        if size >= 1024**3:
            size = f"{size / 1000**3:.2f} GB"
        else:
            size = f"{size / 1000**2:.2f} MB"
        error(f"Insufficient available storage. Update requires at least {size}.")
        break

for line in lines:
    if "tss request:<<<<<<<<<<" in line:
        tss_request = base64.b64decode(lines[lines.index(line) + 1])
        if args.print_tss_request:
            print(tss_request.decode())
        tss_request = plistlib.loads(tss_request)

if not tss_request:
    fatal("Unable to find TSS request in log file")

if "@BCert" not in tss_request:
    fatal("No BCert found in TSS request. Are you supervised?")

if args.print_bcert:
    print(base64.b64encode(tss_request["@BCert"]).decode())

asn1, _ = decode(tss_request["@BCert"])
root = asn1[0]

try:
    validity = root[4]
    valid_from, valid_to = validity
except LookupError:
    warning("Unable to find expiry date in BCert")
else:
    expiry = datetime.strptime(str(valid_to), "%y%m%d%H%M%S%z")
    if expiry > datetime.now().astimezone():
        success(f"BCert is valid (expires: {expiry})")
    else:
        error(f"BCert is expired (expires: {expiry})")

try:
    sep_version_raw = next(x[1] for x in root[7] if str(x[0]) == "1.2.840.113635.100.8.7")
    sep_version_obj, _ = decode(sep_version_raw)
    sep_version = str(sep_version_obj[0])
except LookupError:
    warning("Unable to find SEP version in BCert")
else:
    info(f"SEP version: [cyan]{sep_version}[/cyan]")

if target_version := tss_request.get("ProductMarketingVersion"):
    info(f"Target version: [cyan]{target_version}[/cyan]")
    if sep_version:
        if version.parse(target_version) >= version.parse(sep_version):
            success("Target version is higher or equal to SEP version")
        else:
            fatal("Target version is lower than SEP version. Updating is not possible.")

for line in lines:
    if "STATUS=" in line:
        info(f"TSS status: [cyan]{line[line.index('STATUS='):]}")
        break
else:
    warning("Unable to find TSS response line in log file")
