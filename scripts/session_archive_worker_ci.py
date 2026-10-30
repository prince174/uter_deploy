"""Synthetic-only worker feasibility check on a disposable GitHub runner.

Does not implement or validate encrypted archive orchestration or recovery.
"""
import struct
import subprocess
import sys

from scripts import experimental_rdb_probe as probe

PRODUCT_REDIS = 'ghcr.io/prince174/uter-redis@sha256:b4a3dd93f2f7e276b98131e947d2c30e4b237d964c87a948cf808f160eef2fcc'


def verify_worker(binary, snapshot, expiry, execute=subprocess.run):
    key = b'sess:synthetic'
    frame = (b'UTSA1\0K' + struct.pack('>QQQ', 2, expiry, len(key)) + key +
             b'V' + struct.pack('>Q', 5) + b'alpha' +
             b'V' + struct.pack('>Q', 6) + b'beta\0x' + b'EZ' + struct.pack('>Q', 1))
    corrupt = snapshot[:-1] + bytes([snapshot[-1] ^ 1])
    zero_checksum = snapshot[:-8] + bytes(8)
    for payload, expected in ((snapshot, frame), (corrupt, None),
                              (snapshot[:-8], None), (zero_checksum, None),
                              (snapshot + b'extra', None)):
        result = execute([binary], input=payload, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, check=False, timeout=probe.TIMEOUT_SECONDS)
        if result.stderr or (expected is not None and (result.returncode or result.stdout != expected)) or \
                (expected is None and result.returncode == 0):
            raise RuntimeError('synthetic worker verification failed')


def main(probe_binary, worker_binary):
    original = probe.verify_probe

    def verify_both(binary, snapshot, expiry):
        original(binary, snapshot, expiry)
        verify_worker(worker_binary, snapshot, expiry)

    probe.IMAGE = PRODUCT_REDIS
    probe.verify_probe = verify_both
    probe.main(probe_binary)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('Expected probe and worker executable paths')
    try:
        main(sys.argv[1], sys.argv[2])
    except RuntimeError as exc:
        raise SystemExit('Synthetic worker test failed: ' + str(exc))
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        raise SystemExit('Synthetic worker test failed: ' + type(exc).__name__)
