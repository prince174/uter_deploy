"""Experimental authenticated Compose recovery plan: storage only, never rollback.

The plan describes a limited observed topology. It is NOT evidence that Docker
can recreate an endpoint, that a fence is held, or that Redis data can be safely
restored. This module does not connect to Docker or touch workloads.
"""
import datetime
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat

from scripts import backup_crypto

NAME='compose-fence-plan.json'
MAX_BYTES=8192
FIELDS=frozenset(('schema','operation','site','container_id','started_at','restart_count','image_ref',
                  'image_config_id','restart_policy','volume_name','volume_driver','network_id',
                  'network_name','network_driver','network_scope','network_internal','network_subnet',
                  'network_gateway','endpoint_id','endpoint_ipv4','endpoint_static_ipv4','endpoint_aliases',
                  'endpoint_mac','ipv6_enabled','network_options','endpoint_driver_options'))


class ComposePlanError(ValueError):
    pass


def new_operation():
    """Generate an operation identifier before writing plan and journal."""
    return secrets.token_hex(16)


def _valid_text(value, pattern):
    return isinstance(value,str) and re.fullmatch(pattern,value) is not None


def validate(value):
    """Reject unsupported/incomplete profiles, without returning supplied data in errors."""
    try:
        if not isinstance(value,dict) or set(value)!=FIELDS or type(value['schema']) is not int or value['schema']!=1:
            raise ValueError
        site=value['site']
        if (not _valid_text(value['operation'],r'[0-9a-f]{32}') or
            not _valid_text(site,r'[a-z][a-z0-9-]{0,40}') or
            not _valid_text(value['container_id'],r'[0-9a-f]{64}') or
            not _valid_text(value['started_at'],r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z') or
            type(value['restart_count']) is not int or value['restart_count']<0 or
            not _valid_text(value['image_ref'],r'[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}') or
            not _valid_text(value['image_config_id'],r'sha256:[0-9a-f]{64}') or
            value['restart_policy']!='unless-stopped' or
            value['volume_name']!=site+'_redis-data' or value['volume_driver']!='local' or
            not _valid_text(value['network_id'],r'[0-9a-f]{64}') or value['network_name']!=site+'_backend' or
            value['network_driver']!='bridge' or value['network_scope']!='local' or value['network_internal'] is not True or
            not _valid_text(value['endpoint_id'],r'[0-9a-f]{64}') or value['ipv6_enabled'] is not False or
            value['network_options']!={} or value['endpoint_driver_options']!={} or
            not _valid_text(value['endpoint_mac'],r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}')):
            raise ValueError
        datetime.datetime.fromisoformat(value['started_at'].replace('Z','+00:00'))
        if not all(isinstance(value[field],str) for field in ('network_subnet','endpoint_ipv4','network_gateway')):
            raise ValueError
        subnet=ipaddress.IPv4Network(value['network_subnet'],strict=True)
        ip=ipaddress.IPv4Address(value['endpoint_ipv4'])
        gateway=ipaddress.IPv4Address(value['network_gateway'])
        static=value['endpoint_static_ipv4']
        if (not 1<=subnet.prefixlen<=30 or ip not in subnet or gateway not in subnet or ip==gateway
            or ip in (subnet.network_address,subnet.broadcast_address)
            or gateway in (subnet.network_address,subnet.broadcast_address)
            or (static is not None and (not isinstance(static,str) or ipaddress.IPv4Address(static)!=ip))):
            raise ValueError
        aliases=value['endpoint_aliases']
        if (not isinstance(aliases,list) or not 1<=len(aliases)<=16 or 'redis' not in aliases
            or any(not _valid_text(item,r'[a-z0-9][a-z0-9._-]{0,252}') for item in aliases)
            or len(set(aliases))!=len(aliases)):
            raise ValueError
        return value
    except (ValueError,TypeError,KeyError,AttributeError):
        raise ComposePlanError('COMPOSE_PLAN_INVALID') from None


def _json(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()


def _key(key):
    if not isinstance(key,bytes) or len(key)!=32: raise ComposePlanError('COMPOSE_PLAN_KEY_INVALID')
    return backup_crypto.derive_key(key,b'compose-fence-plan')


def _directory(path):
    if os.name!='posix' or not hasattr(os,'O_NOFOLLOW') or not hasattr(os,'O_DIRECTORY'):
        raise ComposePlanError('COMPOSE_PLAN_PLATFORM_UNSUPPORTED')
    try:
        fd=os.open(Path(path),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        info=os.fstat(fd)
        if info.st_uid!=os.geteuid() or info.st_mode & 0o077:
            os.close(fd)
            raise ComposePlanError('COMPOSE_PLAN_DIRECTORY_UNSAFE')
        return fd
    except ComposePlanError: raise
    except OSError: raise ComposePlanError('COMPOSE_PLAN_DIRECTORY_UNSAFE') from None


def create(directory, plan, key):
    """Durably create once; return hash for journal, never store or print key."""
    validate(plan)
    mac=hmac.new(_key(key),_json(plan),hashlib.sha256).hexdigest()
    raw=_json({'schema':1,'plan':plan,'mac':mac})+b'\n'
    if len(raw)>MAX_BYTES: raise ComposePlanError('COMPOSE_PLAN_INVALID')
    dirfd=_directory(directory);temporary='.compose-plan-'+secrets.token_hex(16)+'.tmp';fd=None
    try:
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=dirfd)
        with os.fdopen(fd,'wb') as output:
            fd=None
            os.fchmod(output.fileno(),0o600)
            output.write(raw);output.flush();os.fsync(output.fileno())
        os.link(temporary,NAME,src_dir_fd=dirfd,dst_dir_fd=dirfd,follow_symlinks=False)
        os.unlink(temporary,dir_fd=dirfd)
        os.fsync(dirfd)
        return hashlib.sha256(raw).hexdigest()
    except OSError:
        raise ComposePlanError('COMPOSE_PLAN_WRITE_FAILED') from None
    finally:
        if fd is not None: os.close(fd)
        try: os.unlink(temporary,dir_fd=dirfd)
        except FileNotFoundError: pass
        finally: os.close(dirfd)


def read(directory,key,expected_sha256,*,operation,site,resource):
    """Authenticate plan and bind exact bytes, site and resource to journal."""
    derived=_key(key)
    if not _valid_text(expected_sha256,r'[0-9a-f]{64}'):
        raise ComposePlanError('COMPOSE_PLAN_INVALID')
    dirfd=_directory(directory)
    try:
        fd=os.open(NAME,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=dirfd)
        with os.fdopen(fd,'rb') as source:
            info=os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1
                    or info.st_mode & 0o077 or info.st_size>MAX_BYTES):
                raise ComposePlanError('COMPOSE_PLAN_FILE_UNSAFE')
            raw=source.read(MAX_BYTES+1)
        if len(raw)>MAX_BYTES or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(),expected_sha256):
            raise ComposePlanError('COMPOSE_PLAN_HASH_MISMATCH')
        envelope=json.loads(raw)
        if not isinstance(envelope,dict) or set(envelope)!={'schema','plan','mac'} or type(envelope['schema']) is not int or envelope['schema']!=1:
            raise ComposePlanError('COMPOSE_PLAN_INVALID')
        plan=validate(envelope['plan']);mac=envelope['mac']
        expected=hmac.new(derived,_json(plan),hashlib.sha256).hexdigest()
        if not isinstance(mac,str) or not hmac.compare_digest(mac,expected):
            raise ComposePlanError('COMPOSE_PLAN_AUTH_FAILED')
        if plan['operation']!=operation or plan['site']!=site or plan['container_id']!=resource:
            raise ComposePlanError('COMPOSE_PLAN_IDENTITY_MISMATCH')
        return plan
    except ComposePlanError: raise
    except (OSError,ValueError,TypeError,UnicodeError,KeyError):
        raise ComposePlanError('COMPOSE_PLAN_UNREADABLE') from None
    finally:
        os.close(dirfd)
