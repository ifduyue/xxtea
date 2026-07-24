#!/usr/bin/env python3
"""Extract release notes from CHANGELOG.rst for a given tag."""
import os
import re

tag = os.environ['TAG']
repo = os.environ['REPO']

with open('CHANGELOG.rst') as f:
    text = f.read()

# Find all version headings
versions = re.findall(r'^(v[\d.]+) [\d/]+$', text, re.MULTILINE)

# Find current version's section
escaped = re.escape(tag)
pattern = r'^' + escaped + r'.*?(?=^v[\d.]+ [\d/]+|\Z)'
m = re.search(pattern, text, re.MULTILINE | re.DOTALL)
if m:
    notes = m.group(0).strip()
    # Convert RST-style heading (line + underline) to Markdown heading.
    # e.g. "v5.3.2 2026/07/24\n~~~~~~~~~~~~~~~~~~~" -> "## v5.3.2 2026/07/24"
    lines = notes.splitlines()
    if len(lines) >= 2 and set(lines[1]) <= set('~=-^'):
        notes = '## ' + lines[0] + '\n' + '\n'.join(lines[2:])
else:
    notes = '## Release ' + tag

# Find previous version in the same major.minor series for changelog link
prefix = tag.rsplit('.', 1)[0]
prev = ''
found = False
for v in versions:
    if v == tag:
        found = True
        continue
    if found and v.startswith(prefix):
        prev = v
        break
if prev:
    notes += '\n\n**Full Changelog**: https://github.com/' + repo + '/compare/' + prev + '...' + tag

with open('release_notes.md', 'w') as f:
    f.write(notes + '\n')
