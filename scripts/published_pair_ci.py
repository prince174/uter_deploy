"""Select and validate immutable published release pair before disposable CI."""
import json
import os
from pathlib import Path

from scripts.verify_release_pair import verify_pair

FINGERPRINT = '65be6fd9613fa7e879735fe5b453bfcb8c0e38911cd7429c9aac9c9afba676a2'
OLD_VERSION, NEW_VERSION = '0.1.2', '0.1.3'


def select_mode(environ, work):
    mode = environ.get('UTER_CI_RELEASE_MODE', 'synthetic')
    if mode == 'synthetic':
        if any(environ.get(name) for name in ('OLD_SIGNED_BUNDLE_PATH', 'NEW_SIGNED_BUNDLE_PATH', 'PUBLISHER_KEY_PATH')):
            raise ValueError('Published bundle paths require explicit published mode')
        return {'mode': mode}
    if mode != 'published':
        raise ValueError('Unsupported release test mode')
    required = ('OLD_SIGNED_BUNDLE_PATH', 'NEW_SIGNED_BUNDLE_PATH', 'PUBLISHER_KEY_PATH')
    if any(not environ.get(name) for name in required):
        raise ValueError('Published mode requires both bundles and publisher key')
    old, new, public = (Path(environ[name]).resolve(strict=True) for name in required)
    previous, current = verify_pair(old, new, public, FINGERPRINT, OLD_VERSION, NEW_VERSION)
    work = Path(work)
    for manifest, release in ((previous, 'published-old'), (current, 'published-new')):
        inputs = work / 'input' / release
        images = json.loads((inputs / 'images.json').read_text())
        publication = json.loads((inputs / 'publication.json').read_text())
        if images != manifest['images']:
            raise ValueError('Installation images do not match signed release')
        ids = manifest.get('image_config_ids')
        if ids and any(publication['images'][name]['image_id'] != image_id for name, image_id in ids.items()):
            raise ValueError('Installation image identities do not match signed release')
    return {'mode': mode, 'old': old, 'new': new, 'public': public,
            'old_manifest': previous, 'new_manifest': current, 'installer': old/'scripts/install.py'}


def parse_update_output(output):
    # The signed command emits pretty-printed JSON followed by a human warning.
    text = output.decode('utf-8').lstrip()
    value, _ = json.JSONDecoder().raw_decode(text)
    if not isinstance(value, dict) or not isinstance(value.get('backup'), str) or not value['backup']:
        raise ValueError('Signed update output is missing backup path')
    return value
