"""Prepare two offline URL assignments. Never starts a browser or collection."""
import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'phishing-study'))
from study.phiusiil_intake import _inputs, _clean, _membership, sha256_file
from study.urls import digest

ALGORITHM = 'phiusiil-two-laptop-domain-balanced-v1'
OPERATORS = ('Lawrken', 'AR-AR-prog')
PARTITIONS = ('train', 'validation', 'test')
LABELS = ('legitimate', 'phishing')
FIELDS = ('assignment_id', 'assigned_operator', 'assignment_index', 'source_row', 'row_id',
          'url', 'url_hash', 'domain_group_hash', 'original_partition', 'source_label',
          'published_label', 'confidence', 'mixed_label_domain_group')


def assign_groups(records, seed):
    """Largest groups first; balance published class and original partition."""
    groups = defaultdict(list)
    totals = Counter()
    for record in records:
        groups[record['domain_group_hash']].append(record)
        totals[(record['split'], record['label'])] += 1
    cells = [(partition, label) for partition in PARTITIONS for label in LABELS]
    targets = [{cell: (totals[cell]+1)//2 for cell in cells},
               {cell: totals[cell]//2 for cell in cells}]
    counts = [Counter(), Counter()]
    assignments = [[], []]
    mixed = 0
    ordered = sorted(groups, key=lambda g: (-len(groups[g]), digest(str(seed)+':assign:'+g)))
    for group in ordered:
        members = groups[group]
        mix = len({r['label'] for r in members}) > 1
        mixed += mix
        size = Counter((r['split'], r['label']) for r in members)
        def cost(slot):
            delta = sum((counts[slot][cell]+size[cell]-targets[slot][cell])**2
                        -(counts[slot][cell]-targets[slot][cell])**2 for cell in cells)
            overflow = sum(max(0, counts[slot][cell]+size[cell]-targets[slot][cell]) for cell in cells)
            return (overflow, delta, len(assignments[slot]), slot)
        slot = min(range(2), key=cost)
        counts[slot].update(size)
        assignments[slot].extend({**r, 'mixed_label_domain_group': mix} for r in members)
    return assignments, {'domain_groups': len(groups), 'mixed_label_domain_groups': mixed,
        'group_rule': 'All endpoints in a domain/private-PSL tenant group stay on one laptop.',
        'target_cell_counts': [{p:{l:t[(p,l)] for l in LABELS} for p in PARTITIONS} for t in targets]}


def ordered_records(records, seed):
    by_label = {label: sorted((r for r in records if r['label']==label),
        key=lambda r: (digest(str(seed)+':visit:'+r['url_hash']), r['source_row'])) for label in LABELS}
    # Balanced prefixes, then the remaining majority-class endpoints. No
    # reachability, page features or predictions are used to set this order.
    for index in range(max(map(len, by_label.values()), default=0)):
        for label in LABELS:
            if index < len(by_label[label]):
                yield by_label[label][index]


def check_assignments(assignments, records):
    ids = [{r['row_id'] for r in shard} for shard in assignments]
    urls = [{r['url_hash'] for r in shard} for shard in assignments]
    domains = [{r['domain_group_hash'] for r in shard} for shard in assignments]
    if ids[0]&ids[1] or urls[0]&urls[1] or domains[0]&domains[1]:
        raise ValueError('Assignment overlap detected.')
    if ids[0]|ids[1] != {r['row_id'] for r in records}:
        raise ValueError('Assignments do not cover the exact cleaned population.')
    for shard in assignments:
        if len(shard)!=len({r['row_id'] for r in shard}) or len(shard)!=len({r['url_hash'] for r in shard}):
            raise ValueError('Duplicate identity inside an assignment.')
    return {'row_id_overlap':0, 'url_hash_overlap':0, 'domain_group_hash_overlap':0,
        'cleaned_population_covered_exactly':True, 'duplicate_urls_within_assignments':0}


def build(source, membership, audit, output, seed=20261010):
    if importlib.metadata.version('tldextract')!='5.4.0':
        raise ValueError('Use tldextract==5.4.0 to reproduce the frozen domain groups.')
    source,membership,audit,old,source_hash,membership_hash,audit_hash = _inputs(source,membership,audit)
    records,census = _clean(source,source_hash)
    for key in ('rows','source_label_counts','retained_rows','retained_class_counts','exclusion_counts'):
        if census[key]!=old[key]:raise ValueError('Original cleaning changed: '+key)
    census['original_partition_rows'] = _membership(membership,records)
    rows=list(records.values())
    assignments, details=assign_groups(rows,seed)
    checks=check_assignments(assignments,rows)
    identity={'algorithm':ALGORITHM,'seed':seed,'operators':list(OPERATORS),
        'source_sha256':source_hash,'membership_sha256':membership_hash,'audit_sha256':audit_hash}
    assignment_id=digest(json.dumps(identity,sort_keys=True,separators=(',',':')))
    output=Path(output).resolve()
    output.mkdir(parents=True,exist_ok=False)
    files={};owners={}
    for operator,shard in zip(OPERATORS,assignments):
        name='assignment-'+operator.lower()+'.csv'
        with (output/name).open('x',encoding='utf-8',newline='') as stream:
            writer=csv.DictWriter(stream,fieldnames=FIELDS,lineterminator='\n');writer.writeheader()
            for index,r in enumerate(ordered_records(shard,seed),1):
                writer.writerow({'assignment_id':assignment_id,'assigned_operator':operator,'assignment_index':index,
                    'source_row':r['source_row'],'row_id':r['row_id'],'url':r['url'],'url_hash':r['url_hash'],
                    'domain_group_hash':r['domain_group_hash'],'original_partition':r['split'],
                    'source_label':r['source_label'],'published_label':r['label'],'confidence':'dataset',
                    'mixed_label_domain_group':str(r['mixed_label_domain_group']).lower()})
        files[name]={'sha256':sha256_file(output/name),'bytes':(output/name).stat().st_size}
        owners[operator]={'csv':name,'rows':len(shard),'published_class_counts':dict(sorted(Counter(r['label'] for r in shard).items())),
            'original_partitions':{p:dict(sorted(Counter(r['label'] for r in shard if r['split']==p).items())) for p in PARTITIONS},
            'domain_groups':len({r['domain_group_hash'] for r in shard}),
            'mixed_label_domain_groups':len({r['domain_group_hash'] for r in shard if r['mixed_label_domain_group']})}
    for path,expected in ((source,source_hash),(membership,membership_hash),(audit,audit_hash)):
        if sha256_file(path)!=expected:raise ValueError('Original input changed during preparation.')
    # Independently reread emitted CSVs to check exact labels/partitions and all
    # source identities, including the seeded order and per-owner row numbers.
    emitted=[]
    for operator in OPERATORS:
        items=[]
        with (output/owners[operator]['csv']).open(encoding='utf-8',newline='') as stream:
            for index,r in enumerate(csv.DictReader(stream),1):
                original=records[int(r['source_row'])]
                if (r['row_id']!=original['row_id'] or r['url_hash']!=digest(r['url'])
                        or r['url']!=original['url'] or r['domain_group_hash']!=original['domain_group_hash']
                        or r['source_label']!=str(original['source_label']) or r['published_label']!=original['label']
                        or r['original_partition']!=original['split'] or r['assigned_operator']!=operator
                        or r['assignment_id']!=assignment_id or int(r['assignment_index'])!=index):
                    raise ValueError('An emitted row differs from its original identity.')
                items.append(original)
        emitted.append(items)
    check_assignments(emitted,rows)
    manifest={'schema_version':1,'assignment_id':assignment_id,**identity,'census':census,
        'allocation':details,'operators':owners,'files':files,'validation':{**checks,
            'emitted_rows_replayed_against_originals':True,'original_inputs_unchanged':True},
        'ordering':'Within each published class: sha256(seed:visit:url_hash); alternate legitimate,phishing, then remaining majority.',
        'label_mapping':{'0':'phishing','1':'legitimate'},'label_confidence':'dataset',
        'mixed_label_domains':'Preserved on one laptop; no extra exclusions beyond the original cleaned population.',
        'purpose':'Offline workload assignments for a future two-laptop campaign; not activation evidence.',
        'collection_activation':False,'endpoint_visits_during_split':0,
        'current_operator_compatible':False,'current_operator_limit':400,
        'heldout_partitions':'Preserved metadata; not moved into training or used for model selection.',
        'splitter_sha256':sha256_file(Path(__file__)),
        'grouping_code_sha256':sha256_file(ROOT/'phishing-study/study/urls.py'),
        'cleaning_code_sha256':sha256_file(ROOT/'phishing-study/study/phiusiil_intake.py'),
        'tldextract':'5.4.0','generated_utc':datetime.now(timezone.utc).isoformat()}
    (output/'split-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    (output/'SHA256SUMS.txt').write_text(''.join(f"{entry['sha256']}  {name}\n" for name,entry in files.items())
        +sha256_file(output/'split-manifest.json')+'  split-manifest.json\n',encoding='utf-8')
    print(json.dumps({'output':str(output),'assignment_id':assignment_id,'operators':owners,'validation':manifest['validation']},indent=2))
    return manifest


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source','membership','audit','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--seed',type=int,default=20261010)
    a=parser.parse_args();build(a.source,a.membership,a.audit,a.output,a.seed)


if __name__=='__main__':main()
