#!/usr/bin/env python3
"""Extract real Python identifiers from pinned, openly licensed source archives."""
import ast
import hashlib
import io
import json
from pathlib import Path
import tarfile
import urllib.request

DATA = Path(__file__).resolve().parents[1] / 'data/entropy/code'
DATA.mkdir(parents=True, exist_ok=True)
PROJECTS = [
    ('django', 'django/django', '5.2', 'train'),
    ('requests', 'psf/requests', 'v2.32.3', 'train'),
    ('urllib3', 'urllib3/urllib3', '2.3.0', 'calibration'),
    ('flask', 'pallets/flask', '3.1.0', 'test'),
]
manifest = []
for name, repo, tag, split in PROJECTS:
    url = f'https://codeload.github.com/{repo}/tar.gz/refs/tags/{tag}'
    cache = DATA / f'{name}-{tag}.tar.gz'
    if not cache.exists():
        with urllib.request.urlopen(url, timeout=60) as response:
            payload = response.read()
        cache.write_bytes(payload)
    payload = cache.read_bytes()
    identifiers, parsed, skipped = set(), 0, 0
    with tarfile.open(fileobj=io.BytesIO(payload), mode='r:gz') as archive:
        for member in archive:
            if not member.isfile():
                continue
            path = Path(member.name)
            if len(path.parts) == 2 and path.name.lower() in ('license', 'license.txt', 'license.rst', 'license.md'):
                (DATA / f'{name}-LICENSE').write_bytes(archive.extractfile(member).read())
            if path.suffix != '.py' or any(p in ('tests', 'test', 'migrations', 'vendor', '_vendor') for p in path.parts):
                continue
            try:
                tree = ast.parse(archive.extractfile(member).read())
            except (SyntaxError, UnicodeError):
                skipped += 1
                continue
            parsed += 1
            for node in ast.walk(tree):
                if isinstance(node, ast.Name):
                    identifiers.add(node.id)
                elif isinstance(node, ast.arg):
                    identifiers.add(node.arg)
                elif isinstance(node, ast.Attribute):
                    identifiers.add(node.attr)
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    identifiers.add(node.name)
    path = DATA / f'{name}.json'
    path.write_text(json.dumps(sorted(identifiers), ensure_ascii=False, indent=2) + '\n')
    manifest.append(dict(name=name, repo=repo, tag=tag, split=split, url=url,
                         archive_sha256=hashlib.sha256(payload).hexdigest(),
                         identifiers_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                         identifiers=len(identifiers), parsed_files=parsed, skipped_files=skipped))
(DATA / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps(manifest, indent=2))
