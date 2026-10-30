"""Pinned kubeconfig exercise for a signed install on disposable hosted CI.

The test synthesizes pins from its own freshly created cluster; this is not
independent cluster authentication or authorization for an actual update.
Credential-bearing bytes stay in memory and never appear in diagnostics.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time

from scripts import (adopt_backup_ci, install_recovery, kubernetes_pinned_preflight as preflight,
                     kubernetes_trusted_kubectl as trusted_kubectl,
                     kubernetes_fence_pin as pin,
                     kubernetes_fence_coordinator as coordinator,
                     kubernetes_fence_profile_store as profile_store,
                     kubernetes_writer_finalizer as writer_finalizer,
                     kubernetes_writer_quiesce as quiesce,
                     kubernetes_redis_identity_ci as snapshot)

ROOT=Path(__file__).resolve().parents[1]


class PinnedCITestError(ValueError):
    def __init__(self,code,stage=None):super().__init__(code);self.stage=stage


def _query(args):return snapshot._query(args)


def _material(home,bundle,key):
    """Internal disposable-CI inputs; the generated pin is not independent."""
    try:
        adopt_backup_ci.runner_guard(os.environ,ROOT)
        if (os.environ.get('UTER_CI_STRICT_RUNNER')!='true'
                or os.environ.get('UTER_CI_VERIFY_KUBE_LOOPBACK')!='true'
                or os.environ.get('BACKEND')!='kubernetes'):
            raise ValueError
        for path in (home,bundle,key):
            if not Path(path).resolve(strict=True).is_relative_to(ROOT/'work'):raise ValueError
        # CI owns this newly created kind cluster and test namespace. The
        # generated pin is not external trust and is never published as one.
        raw=install_recovery.run_readonly(['kubectl','--context='+snapshot.CONTEXT,
            'config','view','--raw','--minify','-o','json'],timeout=30).encode('utf-8')
        value=json.loads(raw)
        if len(value['clusters'])!=1 or len(value['contexts'])!=1:raise ValueError
        cluster=value['clusters'][0]['cluster'];server=cluster['server']
        ca=base64.b64decode(cluster['certificate-authority-data'],validate=True)
        namespace=_query(['get','namespace',snapshot.SITE])
        system=_query(['get','namespace','kube-system'])
        pvc=_query(['-n',snapshot.SITE,'get','pvc',snapshot.SITE+'-redis'])
        deployment=_query(['-n',snapshot.SITE,'get','deployment',snapshot.SITE+'-redis'])
        profile={'schema':1,'context':snapshot.CONTEXT,'server_sha256':hashlib.sha256(server.encode()).hexdigest(),
                 'ca_sha256':hashlib.sha256(ca).hexdigest(),'kube_system_uid':system['metadata']['uid'],
                 'namespace_uid':namespace['metadata']['uid'],'redis_pvc_uid':pvc['metadata']['uid'],
                 'redis_deployment_uid':deployment['metadata']['uid']}
        return raw,profile
    except Exception:raise PinnedCITestError('KUBE_PINNED_CI_UNVERIFIED') from None


def verify(home,bundle,key,manifest):
    stage='PIN_MATERIAL'
    try:
        raw,profile=_material(home,bundle,key)
        # A different pinned CA is rejected before any API object is created.
        wrong=dict(profile,ca_sha256='0'*64)
        refused=False
        try:
            with preflight.checked_session(home,bundle,key,raw,wrong):pass
        except pin.PinError:refused=True
        if not refused:raise ValueError
        stage='PIN_BASELINE'
        with preflight.checked_session(home,bundle,key,raw,profile) as session:
            if session.manifest!=manifest or session.reverify()['safe_to_update'] is not False:raise ValueError
        # Disposable CI-only binary pin, not independently trusted evidence.
        stage='PIN_BINARY_OPEN'
        binary_path=Path('/usr/local/bin/uter-ci-kubectl')
        binary_digest=hashlib.sha256(binary_path.read_bytes()).hexdigest()
        fd=trusted_kubectl.open_binary(binary_path,binary_digest)
        try:
            old={name:os.environ.get(name) for name in ('PATH','HTTPS_PROXY','HTTP_PROXY','KUBECTL_EXTERNAL_DIFF')}
            try:
                os.environ.update(PATH='/nonexistent',HTTPS_PROXY='http://127.0.0.1:1',
                                  HTTP_PROXY='http://127.0.0.1:1',KUBECTL_EXTERNAL_DIFF='/nonexistent')
                stage='PIN_BINARY_SESSION'
                with preflight.checked_session(home,bundle,key,raw,profile,binary_fd=fd,binary_sha256=binary_digest) as pinned:
                    stage='PIN_BINARY_REVERIFY'
                    if pinned.reverify()['safe_to_update'] is not False:raise ValueError
            finally:
                for name,value in old.items():
                    if value is None:os.environ.pop(name,None)
                    else:os.environ[name]=value
        finally:os.close(fd)
        # Exercise operator-profile checks with an independent file and exact
        # kubeconfig bytes on the single disposable kind runner only. These
        # synthetic pins are observed on this same test cluster and do not
        # constitute independent trust for a real installation.
        stage='PIN_OPERATOR_PROFILE'
        config_path=Path(os.environ.get('KUBECONFIG') or Path.home()/'.kube'/'config')
        with tempfile.TemporaryDirectory(prefix='kube-pin-ci-',dir=ROOT/'work') as folder:
            private=Path(folder);backup_key=private/'key';backup_key.write_bytes(os.urandom(32));backup_key.chmod(0o600)
            writer_uids={service:_query(['-n',snapshot.SITE,'get','deployment',snapshot.SITE+'-'+service])['metadata']['uid']
                         for service in ('guardrail','agent')}
            operator={'schema':1,'site':snapshot.SITE,'api':profile,'writer_uids':writer_uids,
                      'release_version':manifest['version'],
                      'inventory_sha256':hashlib.sha256((Path(bundle)/'checksums.json').read_bytes()).hexdigest(),
                      'publisher_sha256':hashlib.sha256(Path(key).read_bytes()).hexdigest()}
            profile_path=private/'profile';profile_store.create(profile_path,backup_key.read_bytes(),operator)
            with coordinator.checked_session(home,bundle,key,config_path,profile_path,backup_key) as bound:
                if bound.reverify().get('safe_to_update') is not False:raise ValueError
                obj=json.loads(bound.api._call(['--request-timeout=20s','get','namespace','kube-system','-o','json']))
                if obj.get('metadata',{}).get('uid')!=profile['kube_system_uid']:raise ValueError
    except Exception:raise PinnedCITestError('KUBE_PINNED_CI_UNVERIFIED',stage) from None
    return {'result':'sealed_pinned_queries_exercised','cluster_authenticated':False,'safe_to_update':False}


def quiesce_writers(home,bundle,key,manifest,operation):
    """Run the exact two writer CAS mutations on this disposable fixture."""
    stage='WRITER_QUIESCE_MATERIAL'
    try:
        raw,profile=_material(home,bundle,key)
        qkey=os.urandom(32)
        stage='WRITER_QUIESCE_SESSION'
        with preflight.checked_session(home,bundle,key,raw,profile) as session:
            if session.manifest!=manifest:raise ValueError
            # CI synthesized these UIDs from its newly created fixture. A real
            # operation requires separate administrator-provisioned writer pins.
            stage='WRITER_QUIESCE_UID'
            uids={service:session._query(['get','deployment',session.site+'-'+service])['metadata']['uid']
                  for service in quiesce.SERVICES}
            stage='WRITER_QUIESCE_PREPARE'
            quiesce.prepare(home,session,operation,uids,qkey)
            for service in quiesce.SERVICES:
                stage='WRITER_POD_PREPARE'
                writer_finalizer.prepare(home,session,operation,service,qkey)
                stage='WRITER_FINALIZER_HOLD'
                writer_finalizer.hold(home,session,operation,service,qkey)
            real_call=session.api._call;counts={'attempted':0,'succeeded':0}
            def timeout_after_guardrail_patch(args):
                if len(args)>2 and args[1]=='patch' and args[2]=='deployment/'+session.site+'-guardrail':
                    counts['attempted']+=1;result=real_call(args);counts['succeeded']+=1
                    raise TimeoutError('synthetic after-success fault')
                return real_call(args)
            session.api._call=timeout_after_guardrail_patch
            try:
                stage='WRITER_GUARDRAIL_STOP'
                try:quiesce.stop(home,session,operation,'guardrail',qkey)
                except quiesce.QuiesceError:pass
                else:raise ValueError
                if counts!={'attempted':1,'succeeded':1}:raise ValueError
                stage='WRITER_GUARDRAIL_CLASSIFY'
                if quiesce.classify(home,session,operation,'guardrail',qkey)['state']!='stopped_spec_observed':raise ValueError
                stage='WRITER_GUARDRAIL_RETRY'
                try:quiesce.stop(home,session,operation,'guardrail',qkey)
                except quiesce.QuiesceError:pass
                else:raise ValueError
                if counts!={'attempted':1,'succeeded':1}:raise ValueError
            finally:session.api._call=real_call
            stage='WRITER_AGENT_STOP'
            quiesce.stop(home,session,operation,'agent',qkey)
            for service in quiesce.SERVICES:
                stage='WRITER_TERMINATION_UNVERIFIED'
                deadline=time.monotonic()+180;termination_stage='UNVERIFIED'
                while time.monotonic()<deadline:
                    try:
                        observed=writer_finalizer.observe(home,session,operation,service,qkey)
                        if observed.get('result')=='writer_termination_observed':break
                    except writer_finalizer.WriterFinalizerError as error:
                        termination_stage=error.stage;time.sleep(.5)
                else:
                    allowed={'POD_FETCH','IDENTITY','CONTAINER','TERMINATED_STATE','EXIT_CODE','SIGNAL','REASON','POD_STATUS'}
                    raise PinnedCITestError('KUBE_WRITER_CI_UNVERIFIED',
                                            'WRITER_TERMINATION_'+(termination_stage if termination_stage in allowed else 'UNVERIFIED'))
                if observed.get('audit_durability_verified') is not False or observed.get('safe_to_backup') is not False:
                    raise ValueError
                stage='WRITER_FINALIZER_RELEASE'
                released=writer_finalizer.release(home,session,operation,service,qkey)
                if released!={'result':'writer_finalizer_release_requested','termination_verified':True,
                              'audit_durability_verified':False,'safe_to_backup':False}:raise ValueError
            stage='WRITER_STOPPED_OBSERVE'
            deadline=time.monotonic()+180
            while time.monotonic()<deadline:
                try:
                    result=quiesce.observe_stopped(home,session,operation,qkey)
                    if result.get('writers_stopped_observed') is True:break
                except quiesce.QuiesceError:time.sleep(.5)
            else:raise ValueError
            if result!={'writers_stopped_observed':True,'continuous_exclusion':False,
                        'old_writer_termination_observed':True,'unforced_deletion_verified':False,'audit_durability_verified':False,
                        'redis_isolated':False,'safe_to_backup':False,'safe_to_update':False}:raise ValueError
        return qkey
    except PinnedCITestError as error:
        raise PinnedCITestError('KUBE_WRITER_CI_UNVERIFIED',error.stage or stage) from None
    except Exception:raise PinnedCITestError('KUBE_WRITER_CI_UNVERIFIED',stage) from None
