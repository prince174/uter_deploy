#!/usr/bin/env python3
"""Choose the Uter installation or update assistant from a trusted copy."""
import argparse
from pathlib import Path
import subprocess
import sys


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    # Let the selected assistant handle its own flags, including --help.
    if argv and argv[0] in ('install', 'update'):
        action, rest = argv[0], argv[1:]
        script = Path(__file__).resolve().parent / (action + '_wizard.py')
        return subprocess.call([sys.executable, '-I', '-B', str(script), *rest])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', choices=('install', 'update'),
                        help='Choose an operation; omit for an interactive menu')
    args, rest = parser.parse_known_args(argv)
    action = args.action
    if action is None:
        if rest:
            parser.error('Choose install or update before passing options')
        if not sys.stdin.isatty():
            parser.error('Interactive selection requires a terminal; specify install or update')
        print('Uter: 1 — установка, 2 — обновление')
        choice = input('Выберите действие [1/2]: ').strip()
        action = {'1': 'install', '2': 'update'}.get(choice)
        if not action:
            print('Действие не выбрано; изменения не выполнены.', file=sys.stderr)
            return 2
    script = Path(__file__).resolve().parent / (action + '_wizard.py')
    return subprocess.call([sys.executable, '-I', '-B', str(script), *rest])


if __name__ == '__main__':
    sys.exit(main())
