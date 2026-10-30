"""Create a release manifest from a verified installation-inputs directory.

Compatibility and data epoch are explicit publisher decisions, never inferred.
This command does not publish or sign anything.
"""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from uterctl import validate
from scripts import source_provenance


def make_manifest(inputs, version, data_epoch, upgrade_from, *, session_identity_gate=False):
    inputs = Path(inputs)
    images = json.loads((inputs / 'images.json').read_text(encoding='utf-8'))
    publication = json.loads((inputs / 'publication.json').read_text(encoding='utf-8'))
    records = publication['images']
    if set(images) != {'guardrail', 'agent', 'redis'} or set(records) != set(images):
        raise ValueError('Publication must describe exactly the three installation images')
    sha = records['guardrail']['source_commit']
    if records['agent']['source_commit'] != sha:
        raise ValueError('Guardrail and Agent source commits differ')
    redis_source = records['redis'].get('application_commit')
    if redis_source is not None and redis_source != sha:
        raise ValueError('Redis publication application commit differs')
    ids = {service: records[service]['image_id'] for service in images}
    manifest = {'schema': 1, 'config_schema': 1, 'tooling_schema': 1, 'status': 'released',
                'version': version, 'source_commit': sha, 'data_epoch': data_epoch,
                'upgrade_from': upgrade_from, 'images': images, 'image_config_ids': ids}
    if session_identity_gate:
        if data_epoch != 2 or not upgrade_from:
            raise ValueError('Session identity gate requires epoch 2 and an explicit upgrade source')
        manifest['session_identity_gate'] = {'schema': 1, 'from_epoch': 1, 'to_epoch': 2,
                                             'policy': 'block_unverified_sessions'}
    states = [records[service].get('source_state') for service in ('guardrail', 'agent', 'redis')]
    if any(state is not None for state in states):
        if any(state is None for state in states):
            raise ValueError('Source snapshot provenance missing from an image')
        validated = [source_provenance.validate(state, sha) for state in states]
        if any(state != validated[0] for state in validated):
            raise ValueError('Source snapshot provenance differs across images')
        # source_commit is explicitly the committed BASELINE for this variant;
        # source_state identifies the additional working-tree patch.
        manifest['source_state'] = validated[0]
    return validate(manifest)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inputs', type=Path, required=True)
    p.add_argument('--version', required=True)
    p.add_argument('--data-epoch', type=int, required=True)
    p.add_argument('--upgrade-from', action='append', default=[])
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    manifest = make_manifest(a.inputs, a.version, a.data_epoch, a.upgrade_from)
    with a.output.open('x', encoding='utf-8') as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write('\n')
    print('Manifest created; publisher must independently confirm metadata and compatibility before signing.')


if __name__ == '__main__':
    main()
