"""Authenticate exact Kubernetes configuration objects for encrypted backup.

Objects are never logged. A pinned UID and exact pre-recorded resourceVersion
must match before and after capture; only the declared installation resources
are read. This component alone cannot authorize a backup or update.
"""
import io
import json
import re

import uterctl
from scripts import (backup_installation, backup_snapshot, kubernetes_audit_writer_guard as writer_guard,
                     kubernetes_fence_finalizer as finalizer, kubernetes_writer_quiesce as storage)

NAME='kubernetes-config-snapshot-plan.json'


class ConfigSnapshotError(ValueError):pass


def _objects(session):
    site=uterctl.site_config(session.home)
    if (site.get('backend')!='helm' or site.get('name')!=session.site or site.get('namespace')!=session.site
            or site.get('context')!=session.api.context):raise ValueError
    names=backup_snapshot.kube_objects(session.home,site,manifest=session.manifest)
    if len(set(names))!=len(names):raise ValueError
    expected=set(session._record['object_uids'])|{'pvc/'+session.site+'-redis','pvc/'+session.site+'-guardrail'}
    if set(names)!=expected:raise ValueError
    return sorted(names)


def _read(session,name):
    kind,item=name.split('/',1)
    if kind in ('secret','configmap'):
        value=session._get_configured_object(kind,item)
        if kind=='secret' and item==session.site+'-maintenance':
            backup_snapshot.validate_maintenance_secret(value,item,session.site,home=session.home)
        return value
    if kind!='pvc' or item not in (session.site+'-redis',session.site+'-guardrail'):raise ValueError
    value=session._query(['get','pvc',item]);meta=value['metadata']
    uid=session.profile['redis_pvc_uid'] if item.endswith('-redis') else session._record['audit_pvc_uid']
    if (value.get('kind')!='PersistentVolumeClaim' or meta.get('name')!=item or meta.get('namespace')!=session.site
            or meta.get('uid')!=uid or meta.get('deletionTimestamp') or value.get('status',{}).get('phase')!='Bound'
            or not isinstance(meta.get('resourceVersion'),str) or not re.fullmatch(r'[0-9]{1,32}',meta['resourceVersion'])):
        raise ValueError
    return value


def prepare(session,operation,key):
    try:
        if session._executor is None or session._record['schema']!=2:raise ValueError
        if backup_installation.safe_file(session._key_path,private=True,limit=32)!=key:raise ValueError
        pod=finalizer.read_plan(session.home);finalizer._check_journal(session.home,pod,operation,'prepared')
        session.reverify();names=_objects(session)
        versions={}
        for name in names:
            value=_read(session,name);versions[name]={'uid':value['metadata']['uid'],'rv':value['metadata']['resourceVersion']}
        record={'schema':1,'operation':operation,'profile_sha256':session._profile_digest,'objects':versions}
        storage._write(session.home,NAME,record,key)
        session._scope()
        return {'configuration_plan_saved':True,'safe_to_backup':False}
    except Exception:raise ConfigSnapshotError('KUBE_CONFIG_PLAN_UNVERIFIED') from None


def capture(session,operation,key,writer):
    accepted=False
    try:
        if session._executor is None or session._record['schema']!=2:raise ValueError
        if backup_installation.safe_file(session._key_path,private=True,limit=32)!=key:raise ValueError
        writer_guard.verify(session,operation,key)
        plan=storage._read(session.home,NAME,key);names=_objects(session)
        if (set(plan)!={'schema','operation','profile_sha256','objects'} or type(plan['schema']) is not int or plan['schema']!=1
                or plan['operation']!=operation or plan['profile_sha256']!=session._profile_digest
                or not isinstance(plan['objects'],dict) or set(plan['objects'])!=set(names)):raise ValueError
        def read_all():
            objects=[]
            for name in names:
                value=_read(session,name);meta=value['metadata']
                if plan['objects'][name]!={'uid':meta['uid'],'rv':meta['resourceVersion']}:raise ValueError
                objects.append(value)
            return objects
        objects=read_all();raw=json.dumps({'apiVersion':'v1','kind':'List','items':objects},
                                          sort_keys=True,separators=(',',':')).encode()
        if len(raw)>32*1024*1024:raise ValueError
        writer.put('kubernetes',io.BytesIO(raw))
        read_all()
        if _objects(session)!=names:raise ValueError
        writer_guard.verify(session,operation,key)
        accepted=True
        return {'kubernetes_component_captured':True,'complete_backup':False,'safe_to_update':False}
    except Exception:raise ConfigSnapshotError('KUBE_CONFIG_CAPTURE_UNVERIFIED') from None
    finally:
        if not accepted:
            manifest=getattr(writer,'manifest',None)
            if isinstance(manifest,dict) and isinstance(manifest.get('files'),dict):manifest['files'].pop('kubernetes',None)


def reverify(session,operation,key):
    """Recheck all pinned UID/resourceVersions without exposing data."""
    try:
        if session._executor is None or session._record['schema']!=2:raise ValueError
        if backup_installation.safe_file(session._key_path,private=True,limit=32)!=key:raise ValueError
        writer_guard.verify(session,operation,key)
        plan=storage._read(session.home,NAME,key);names=_objects(session)
        if (set(plan)!={'schema','operation','profile_sha256','objects'} or type(plan['schema']) is not int or plan['schema']!=1
                or plan['operation']!=operation or plan['profile_sha256']!=session._profile_digest
                or not isinstance(plan['objects'],dict) or set(plan['objects'])!=set(names)):raise ValueError
        for name in names:
            item=_read(session,name);meta=item['metadata']
            if plan['objects'][name]!={'uid':meta['uid'],'rv':meta['resourceVersion']}:raise ValueError
        writer_guard.verify(session,operation,key)
        return {'configuration_unchanged_observed':True,'safe_to_update':False}
    except Exception:raise ConfigSnapshotError('KUBE_CONFIG_REVERIFY_UNCERTAIN') from None
