#!/usr/bin/env python3
"""Download public dictionaries, train bigrams, calibrate, and evaluate deterministically."""
import argparse
import collections
import hashlib
import json
import math
from pathlib import Path
import random
import re
import urllib.request
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'data/entropy'
SOURCES = {
    'english-words': 'https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt',
}
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--download', action='store_true', help='refresh cached source files')
args = parser.parse_args()
DATA.mkdir(parents=True, exist_ok=True)
manifest = []
words = set()
for name, url in SOURCES.items():
    path = DATA / (name + '.txt')
    if args.download or not path.exists():
        with urllib.request.urlopen(url, timeout=60) as response:
            payload = response.read()
        if len(payload) < 50000:
            raise ValueError('Unexpectedly small dictionary: ' + url)
        path.write_bytes(payload)
    payload = path.read_bytes()
    entries = {w.lower() for w in payload.decode().splitlines() if re.fullmatch('[A-Za-z]+', w)}
    words.update(entries)
    manifest.append(dict(name=name, url=url, sha256=hashlib.sha256(payload).hexdigest(), words=len(entries)))

# Word-based hash split prevents the same word leaking across partitions/sources.
parts = [[], [], []]
for word in sorted(words):
    bucket = int(hashlib.sha256(word.encode()).hexdigest()[:8], 16) % 10
    parts[0 if bucket < 8 else 1 if bucket == 8 else 2].append(word)
train, calibration, test = parts
# Match the runtime tokenizer exactly; camelCase and digits stay together.
if not (DATA / 'code/manifest.json').exists():
    subprocess.run([sys.executable, str(ROOT / 'scripts/collect-code-identifiers.py')], check=True)
code_manifest = json.loads((DATA / 'code/manifest.json').read_text())
code_parts = {k: set() for k in ('train', 'calibration', 'test')}
for project in code_manifest:
    names = json.loads((DATA / 'code' / (project['name'] + '.json')).read_text())
    for name in names:
        code_parts[project['split']].update(b.lower() for b in re.findall('[A-Za-z0-9]+', name) if not b.isdigit())
# Reserve held-out blocks globally, including words shared with the dictionary.
code_test = code_parts['test']
code_cal = code_parts['calibration'] - code_test - set(test)
code_train = code_parts['train'] - code_test - code_cal - set(test) - set(calibration)
reserved = code_test | code_cal
train = [w for w in train if w not in reserved]
calibration = [w for w in calibration if w not in code_test]
# Deduplicate training sources; modest upweighting balances code with the large dictionary.
training_samples = train + sorted(code_train) * 10
worker = ROOT / 'worker.js'
source = worker.read_text()
def extract(name):
    return json.loads(re.search(r'const ' + name + r' = (.*);', source)[1])
baseline_path = DATA / 'baseline.json'
if not baseline_path.exists():
    baseline_path.write_text(json.dumps(dict(cost=extract('BIGRAM_COST'), thresholds=extract('ENTROPY_THRESHOLDS'))))
baseline = json.loads(baseline_path.read_text())
code_baseline_path = DATA / 'before-code.json'
if not code_baseline_path.exists():
    code_baseline_path.write_text(json.dumps(dict(cost=extract('BIGRAM_COST'), thresholds=extract('ENTROPY_THRESHOLDS'))))
code_baseline = json.loads(code_baseline_path.read_text())
letters = 'abcdefghijklmnopqrstuvwxyz0123456789'
following = letters + '$'
counts = {c: collections.Counter() for c in '^' + letters}
for word in training_samples:
    for a, b in zip('^' + word, word + '$'):
        counts[a][b] += 1
cost = {}
for a, row in counts.items():
    total = sum(row.values()) + 0.5 * len(following)
    cost[a] = {b: round(-math.log2((row[b] + 0.5) / total), 6) for b in following}

def score(word, model):
    s = word.lower()
    return sum(model[a][b] for a, b in zip('^' + s, s + '$')) / (len(s) + 1)
def diverse(word):
    s = word.lower()
    h = -sum((n / len(s)) * math.log2(n / len(s)) for n in collections.Counter(s).values())
    return h >= min(2.5, math.log2(len(s)) * 0.72)
def threshold(n, table):
    if n <= 8:
        return math.inf
    for (a, x), (b, y) in zip(table, table[1:]):
        if a <= n <= b:
            return x + (y-x) * (n-a) / (b-a)
    return table[-1][1]

# Retain the original length curve, calibrating one offset on an independent split.
# Target <=0.03% false positives among eligible dictionary words.
cal = [w for w in calibration if len(w) > 8 and diverse(w)]
margins = sorted(score(w, cost) - threshold(len(w), baseline['thresholds']) for w in cal)
offset = margins[min(len(margins)-1, math.ceil(0.9997 * len(margins))-1)]
code_margins = sorted(score(w, cost) - threshold(len(w), baseline['thresholds']) for w in code_cal if len(w) > 8 and diverse(w))
code_offset = code_margins[min(len(code_margins)-1, math.ceil(0.99 * len(code_margins))-1)]
offset = max(offset, code_offset)
thresholds = [[n, round(h + offset, 6)] for n, h in baseline['thresholds']]

def metrics(samples, model, table):
    eligible = [w for w in samples if len(w) > 8 and not w.isdigit()]
    hits = sum(diverse(w) and score(w, model) > threshold(len(w), table) for w in eligible)
    return dict(samples=len(eligible), detected=hits, rate=round(hits / len(eligible), 6) if eligible else None)
rng = random.Random(20261123)
synthetic = {}
for name, alphabet in [('letters', letters[:26]), ('alphanumeric', letters), ('hex', '0123456789abcdef')]:
    synthetic[name] = [''.join(rng.choice(alphabet) for _ in range(n)) for n in [9, 12, 16, 24, 32, 64, 128] for _ in range(1000)]
# Preserve the existing benchmark samples and add every missing length separately.
extra_rng = random.Random(20261124)
for name, alphabet in [('letters', letters[:26]), ('alphanumeric', letters), ('hex', ''.join('0123456789') + 'abcdef')]:
    synthetic[name].extend(''.join(extra_rng.choice(alphabet) for _ in range(n))
                           for n in range(9, 129) if n not in (9, 12, 16, 24, 32, 64, 128)
                           for _ in range(1000))
report = dict(code_sources=code_manifest, code_split={k:len(v) for k,v in [('train', code_train), ('calibration', code_cal), ('test', code_test)]}, code_training_weight=10, sources=manifest, split=dict(train=len(train), calibration=len(calibration), test=len(test)), smoothing=0.5,
              calibration_target=0.0003, threshold_offset=offset, thresholds=thresholds, evaluations={})
for name, model, table in [('before', baseline['cost'], baseline['thresholds']), ('before_code', code_baseline['cost'], code_baseline['thresholds']), ('after', cost, thresholds)]:
    report['evaluations'][name] = dict(dictionary=metrics(test, model, table), code=metrics(sorted(code_test), model, table), code_with_digits=metrics(sorted(w for w in code_test if any(c.isdigit() for c in w)), model, table), synthetic={k: metrics([w for w in v if len(w) in (9,12,16,24,32,64,128)], model, table) for k,v in synthetic.items()})
    report['evaluations'][name]['by_length'] = {
        str(n): dict(dictionary=metrics([w for w in test if len(w) == n], model, table),
                     code=metrics(sorted(w for w in code_test if len(w) == n), model, table),
                     synthetic={k:metrics([w for w in v if len(w) == n], model, table) for k,v in synthetic.items()})
        for n in range(9, max(128, max(map(len, test)), max(map(len, code_test))) + 1)
    }
if report['evaluations']['after']['dictionary']['rate'] > 0.001:
    raise ValueError('Held-out dictionary false positive regression; refusing update')
for name, value in [('BIGRAM_COST', cost), ('ENTROPY_THRESHOLDS', thresholds)]:
    source = re.sub(r'const ' + name + r' = .*;', lambda m: 'const ' + name + ' = ' + json.dumps(value, separators=(',', ':')) + ';', source, count=1)
worker.write_text(source)
(DATA / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
