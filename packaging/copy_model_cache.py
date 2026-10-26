"""Export only the selected toxicity snapshot, resolving shared HF blobs safely."""
import argparse
import re
import shutil
from pathlib import Path

MODEL = 'models--cointegrated--rubert-tiny-toxicity'
REQUIRED = ('config.json', 'model.safetensors', 'tokenizer_config.json', 'vocab.txt')
OPTIONAL = ('tokenizer.json', 'special_tokens_map.json', 'added_tokens.json', 'LICENSE', 'README.md')


def export(hub, output):
    hub, output = Path(hub).resolve(), Path(output)
    (output / 'hub').mkdir(parents=True, exist_ok=True)
    model = hub / MODEL
    if not model.exists():
        return 0  # Agent has no preloaded toxicity model; Guardrail offline test requires it.
    ref = model / 'refs/main'
    revision = ref.read_text().strip()
    if not re.fullmatch('[0-9a-f]{40}', revision):
        raise ValueError('Invalid model revision')
    copied = 0
    for name in REQUIRED + OPTIONAL:
        source = model / 'snapshots' / revision / name
        if not source.exists() and name in OPTIONAL:
            continue
        resolved = source.resolve(strict=True)
        if not resolved.is_relative_to(hub) or not resolved.is_file():
            raise ValueError('Model resource escapes trusted cache')
        target = output / 'hub' / MODEL / 'snapshots' / revision / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(resolved, target)
        copied += 1
    target_ref = output / 'hub' / MODEL / 'refs/main'
    target_ref.parent.mkdir(parents=True, exist_ok=True)
    target_ref.write_text(revision)
    return copied


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('hub', type=Path); p.add_argument('output', type=Path)
    a = p.parse_args()
    print('Allowlisted model files:', export(a.hub, a.output))
