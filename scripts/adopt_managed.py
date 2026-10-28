"""Safely adopt an install.py installation using its matching signed bundle."""
import argparse
import contextlib
import io
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import uterctl
from scripts import adopt_installation, managed_smoke


def adopt(home,bundle,publisher_key):
    home=Path(home).resolve(strict=True);bundle=Path(bundle).resolve(strict=True)
    if (home/'state.json').exists():raise ValueError('Installation already has controller state')
    manifest=uterctl.verify(bundle,publisher_key)
    cfg=uterctl.read(home/'install.json')
    if cfg.get('images')!=manifest['images']:raise ValueError('Current bundle does not match installed images')
    runtime=home/'runtime'
    if runtime.is_symlink() or not runtime.is_dir():raise ValueError('Installation runtime must be a regular directory')
    smoke,created=managed_smoke.prepare(home)
    try:
        with contextlib.redirect_stdout(io.StringIO()):adopt_installation.adopt(home,bundle,publisher_key,smoke)
    except BaseException:
        for path in created:path.unlink(missing_ok=True)
        raise
    return manifest


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--home',type=Path,required=True);p.add_argument('--bundle',type=Path,required=True)
    p.add_argument('--publisher-key',type=Path,required=True)
    a=p.parse_args();manifest=adopt(a.home,a.bundle,a.publisher_key)
    print('Adopted installation at signed version '+manifest['version']+'; workloads unchanged.')


if __name__=='__main__':
    try:main()
    except Exception as exc:
        print(f'adoption: {type(exc).__name__}: {exc}',file=sys.stderr);sys.exit(1)
