"""Re-run research feature extraction and the fixed OCSVM on the included benign capture."""
from pathlib import Path
import csv
import gzip
import hashlib
import json
import math
import struct
from extract_host_minutes import extract, label_flows, aggregate, FEATURES

base = Path(__file__).resolve().parent
sample = base / 'sample'


def require(cond, error):
    if not cond:
        raise ValueError(error)


def as_f32(x):
    return struct.unpack('f', struct.pack('f', x))[0]


def raw_anomaly_score(vector, model):
    """Return the archived OCSVM score without deserializing executable model objects."""
    low, high = model['clip']
    transformed = []
    for x, median, mean, scale in zip(vector, model['median'], model['mean'], model['scale']):
        clean = x if math.isfinite(x) else median
        z = (math.log1p(max(clean, 0.0)) - mean) / scale
        transformed.append(as_f32(max(low, min(high, z))))
    return -sum(
        alpha * math.exp(-model['gamma'] * sum((a-b)**2 for a,b in zip(transformed, support)))
        for alpha, support in zip(model['dual_coef'], model['support_vectors'])
    )


def main():
    meta = json.loads((sample/'metadata.json').read_text())
    path = sample/'benign_get200.pcap'
    require(hashlib.sha256(path.read_bytes()).hexdigest() == meta['pcap_sha256'], 'Unexpected PCAP')
    flows, _ = extract(path, meta['roles'])
    require(len(flows)==meta['flows'] and sum(r['packets'] for r in flows)==meta['packets'], 'PCAP count mismatch')
    label_flows(flows, meta['roles'], {}, [], 'normal')
    extracted = aggregate(flows, meta['roles'], 'normal', *meta['fixed_interval'])
    actual = {tuple(r['key']):r['x'] for r in extracted if r['role']=='normal_client' and r['label']==0 and not r['invalid']}
    with gzip.open(sample/'host_minutes.jsonl.gz','rt') as fh:
        expected = {tuple(r['key']):r['x'] for r in map(json.loads,fh)}
    model = json.loads((sample/'ocsvm_numeric.json').read_text())
    require(FEATURES == model['feature_order'] == json.loads((sample/'feature_order.json').read_text()), 'Feature order mismatch')
    require(len(expected) == len(actual) == meta['normal_client_minutes'] and actual == expected, 'Feature parity failed')
    require(model['kernel']=='rbf' and model['float32_after_transform'], 'Unexpected model scoring convention')
    err = 0.0
    count = {k:0 for k in ('IDS','AI','OR')}
    seen = set()
    with (sample/'saved_predictions.csv').open(newline='') as fh:
        for row in csv.DictReader(fh):
            key = tuple(json.loads(row['key']))
            require(key in actual and key not in seen, 'Prediction key mismatch')
            seen.add(key)
            score = raw_anomaly_score(actual[key], model)
            err = max(err, abs(score-float(row['score'])))
            require(math.isclose(score,float(row['score']),rel_tol=1e-6,abs_tol=1e-7), 'Fixed score parity failed')
            ids = row['IDS']=='True'   # Precomputed IDS result, not an engine run.
            ai = score > model['AI_threshold']
            ai_for_or = score > model['selected_combined_threshold']
            both = ids or ai_for_or
            require((ai,ai_for_or,both)==tuple(row[k]=='True' for k in ('AI','selected_AI_component','selected_OR')), 'Alarm parity failed')
            for name, flag in zip(count,(ids,ai,both)):
                count[name] += int(flag)
    require(seen==set(actual), 'Saved decisions do not cover the fixture')
    print(f"PCAP: {meta['packets']} packets / {len(flows)} flows / {len(actual)} exact 32-feature windows")
    print(f"Fixed OCSVM score error <= {err:.3g}; IDS(saved), AI(new), OR(new): {count}")


if __name__ == '__main__':
    main()
