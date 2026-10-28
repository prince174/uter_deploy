"""Convert an isolated Redis loaded from RDB into a checked AOF baseline.

Caller must start Redis with appendonly disabled, verify the restored dataset and
keep all application writers disconnected. This module does not start/stop Redis.
"""
import time


def enable_checked(redis_cli, *, timeout=180):
    """Enable AOF and wait for a successful completed rewrite before cutover."""
    response=redis_cli(['CONFIG','SET','appendonly','yes']).strip()
    if response != b'OK': raise ValueError('Redis did not enable AOF')
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        info=redis_cli(['INFO','persistence']).decode('utf-8',errors='strict')
        values={}
        for line in info.splitlines():
            if ':' in line and not line.startswith('#'):
                key,value=line.split(':',1);values[key]=value.strip()
        if values.get('aof_last_bgrewrite_status') == 'err' or values.get('aof_last_write_status') == 'err':
            raise ValueError('Redis AOF creation or write failed')
        if (values.get('aof_enabled') == '1' and values.get('aof_rewrite_in_progress') == '0'
                and values.get('aof_rewrite_scheduled') == '0'
                and values.get('aof_last_bgrewrite_status') == 'ok'
                and values.get('aof_last_write_status') == 'ok'
                and int(values.get('aof_base_size','0')) > 0):
            return
        time.sleep(1)
    raise TimeoutError('Redis AOF baseline did not complete; do not start the recovered workload')
