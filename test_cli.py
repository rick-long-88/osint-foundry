#!/usr/bin/env python3
"""Test the CLI import."""
import sys
sys.path.insert(0, "src")

from osint_foundry.cli import osint

print("CLI import OK")
print("Help output:")
osint(["--help"])
