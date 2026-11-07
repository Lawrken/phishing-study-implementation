"""Read-only verification of one supplied laptop package. No website requests."""
import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
from pathlib import Path


def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def verify(directory):
    root=Path(directory).resolve()
    contract=json.loads((root/'THIS_LAPTOP.json').read_text(encoding='utf-8'))
    manifest_path=root/'split-manifest.json'
    if sha(manifest_path)!=contract['manifest_sha256']:
        raise ValueError('Split manifest changed.')
    manifest=json.loads(manifest_path.read_text(encoding='utf-8'))
    owner=contract['operator'];expected=manifest['operators'][owner]
    name=expected['csv']
    if Path(name).name!=name or name!=contract['csv']:
        raise ValueError('Invalid assignment filename.')
    path=root/name
    if path.is_symlink() or sha(path)!=manifest['files'][name]['sha256'] or sha(path)!=contract['csv_sha256']:
        raise ValueError('Assignment CSV changed.')
    labels=Counter();partitions=defaultdict(Counter);ids=set();urls=set();groups=set();mixed=set()
    with path.open(encoding='utf-8',newline='') as stream:
        for index,row in enumerate(csv.DictReader(stream),1):
            if (row['assignment_id']!=manifest['assignment_id'] or row['assigned_operator']!=owner
                    or row['assignment_id']!=contract['assignment_id'] or int(row['assignment_index'])!=index
                    or row['confidence']!='dataset' or row['original_partition'] not in {'train','validation','test'}
                    or {'0':'phishing','1':'legitimate'}.get(row['source_label'])!=row['published_label']
                    or hashlib.sha256(row['url'].encode()).hexdigest()!=row['url_hash']
                    or row['row_id'] in ids or row['url_hash'] in urls):
                raise ValueError('Invalid assignment record at index '+str(index))
            ids.add(row['row_id']);urls.add(row['url_hash']);groups.add(row['domain_group_hash'])
            labels[row['published_label']]+=1;partitions[row['original_partition']][row['published_label']]+=1
            if row['mixed_label_domain_group']=='true':mixed.add(row['domain_group_hash'])
    if (len(ids)!=expected['rows'] or dict(labels)!=expected['published_class_counts']
            or {p:dict(v) for p,v in partitions.items()}!=expected['original_partitions']
            or len(groups)!=expected['domain_groups'] or len(mixed)!=expected['mixed_label_domain_groups']):
        raise ValueError('Assignment counts differ from the frozen manifest.')
    return {'status':'passed','operator':owner,'assignment_id':manifest['assignment_id'],
        'rows':len(ids),'published_class_counts':dict(labels),'original_partitions':dict(partitions),
        'domain_groups':len(groups),'csv_sha256':contract['csv_sha256'],
        'endpoint_visits':0,'collection_activation':False,
        'scope':'Package identity and integrity only; not reachability or deployment approval.'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory',type=Path,default=Path('.'))
    a=parser.parse_args();print(json.dumps(verify(a.directory),indent=2))


if __name__=='__main__':main()
