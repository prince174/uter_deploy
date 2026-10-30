"""Strict Kubernetes API identity checks for a future fenced operation.

Pins must come from a separately trusted administrator, not from the same
request being checked. This module neither opens a cluster connection nor proves
CNI/CSI behaviour, admission/RBAC/GitOps exclusion, data durability or a Redis
fence. All privileged control-plane and node actors remain trusted. The caller
must use the *exact checked kubeconfig bytes* for every request, maintain an
exclusive operation lock, and recheck live resources before side effects.
"""
import base64
import hashlib
import re
import urllib.parse

from cryptography import x509
import yaml

from scripts import kubernetes_redis_identity as identity

MAX_CONFIG=262144
FIELDS=frozenset(('schema','context','server_sha256','ca_sha256','kube_system_uid',
                  'namespace_uid','redis_pvc_uid','redis_deployment_uid'))


class PinError(ValueError): pass


class UniqueLoader(yaml.SafeLoader):
    pass


def _mapping(loader,node,deep=False):
    loader.flatten_mapping(node);result={}
    for key_node,value_node in node.value:
        key=loader.construct_object(key_node,deep=deep)
        if not isinstance(key,str) or key in result:raise ValueError
        result[key]=loader.construct_object(value_node,deep=deep)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,_mapping)


def _sha(value):return hashlib.sha256(value).hexdigest()


def _profile(profile):
    try:
        if (not isinstance(profile,dict) or set(profile)!=FIELDS or type(profile['schema']) is not int
                or profile['schema']!=1 or not isinstance(profile['context'],str)
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,252}',profile['context'])
                or any(not isinstance(profile[k],str) or not re.fullmatch(r'[0-9a-f]{64}',profile[k])
                       for k in ('server_sha256','ca_sha256'))
                or any(not isinstance(profile[k],str) or not identity.UUID.fullmatch(profile[k])
                       for k in ('kube_system_uid','namespace_uid','redis_pvc_uid','redis_deployment_uid'))):
            raise ValueError
        if len({profile[k] for k in ('kube_system_uid','namespace_uid','redis_pvc_uid','redis_deployment_uid')})!=4:
            raise ValueError
        return profile
    except (ValueError,KeyError,TypeError):raise PinError('KUBE_PIN_PROFILE_INVALID') from None


def _select(items,name,content_key):
    if not isinstance(items,list) or len(items)>128:raise ValueError
    matched=[];names=set()
    for item in items:
        if not isinstance(item,dict) or set(item)!={'name',content_key} or not isinstance(item['name'],str):raise ValueError
        if item['name'] in names:raise ValueError
        names.add(item['name'])
        if item['name']==name:matched.append(item[content_key])
    if len(matched)!=1 or not isinstance(matched[0],dict):raise ValueError
    return matched[0]


def _decode(value):
    if not isinstance(value,str) or not value or len(value)>131072:raise ValueError
    return base64.b64decode(value,validate=True)


def verify_config(raw,profile):
    """Validate one static kubeconfig against an independently held pin.

    Only one embedded CA and one static token or embedded client key pair are
    supported. External file paths, auth plugins and dynamic credentials fail
    closed. No credential or endpoint value is returned or logged.
    """
    profile=_profile(profile)
    try:
        if not isinstance(raw,bytes) or not 1<=len(raw)<=MAX_CONFIG:raise ValueError
        value=yaml.load(raw,Loader=UniqueLoader)
        if not isinstance(value,dict) or value.get('apiVersion')!='v1' or value.get('kind')!='Config':raise ValueError
        selected=_select(value.get('contexts'),profile['context'],'context')
        if set(selected)-{'cluster','user','namespace'} or not isinstance(selected.get('cluster'),str) or not isinstance(selected.get('user'),str):raise ValueError
        cluster=_select(value.get('clusters'),selected['cluster'],'cluster')
        if set(cluster)-{'server','certificate-authority-data'}:raise ValueError
        server=cluster['server']
        if not isinstance(server,str) or len(server)>2048:raise ValueError
        parsed=urllib.parse.urlsplit(server)
        if (parsed.scheme!='https' or not parsed.hostname or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment or parsed.path not in ('','/') or parsed.port is None):raise ValueError
        ca=_decode(cluster['certificate-authority-data'])
        # Strict profile requires exactly one PEM certificate, not a bundle.
        if not re.fullmatch(rb'\s*-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*',ca):raise ValueError
        x509.load_pem_x509_certificate(ca)
        user=_select(value.get('users'),selected['user'],'user')
        if set(user)=={'token'}:
            if not isinstance(user['token'],str) or not 1<=len(user['token'])<=16384:raise ValueError
        elif set(user)=={'client-certificate-data','client-key-data'}:
            if not _decode(user['client-certificate-data']) or not _decode(user['client-key-data']):raise ValueError
        else:raise ValueError
        if _sha(server.encode())!=profile['server_sha256'] or _sha(ca)!=profile['ca_sha256']:raise ValueError
        return {'result':'pinned_kubeconfig_match','cluster_authenticated':False,'redis_isolated':False,'safe_to_update':False}
    except (ValueError,KeyError,TypeError,yaml.YAMLError,UnicodeError):
        raise PinError('KUBE_PIN_CONFIG_UNVERIFIED') from None


def verify_resources(profile,*,kube_system,namespace,pvc,deployment):
    """Compare independently provisioned UIDs with observed objects only."""
    profile=_profile(profile)
    try:
        for obj,kind,key in ((kube_system,'Namespace','kube_system_uid'),(namespace,'Namespace','namespace_uid'),
                             (pvc,'PersistentVolumeClaim','redis_pvc_uid'),(deployment,'Deployment','redis_deployment_uid')):
            if not isinstance(obj,dict) or obj.get('kind')!=kind or obj.get('metadata',{}).get('uid')!=profile[key]:raise ValueError
            if obj['metadata'].get('deletionTimestamp'):raise ValueError
        if kube_system['metadata'].get('name')!='kube-system':raise ValueError
        name=namespace['metadata'].get('name')
        if (not isinstance(name,str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,40}',name)
                or pvc['metadata'].get('name')!=name+'-redis' or pvc['metadata'].get('namespace')!=name
                or deployment['metadata'].get('name')!=name+'-redis' or deployment['metadata'].get('namespace')!=name):
            raise ValueError
        return {'result':'pinned_resource_uids_match','cluster_authenticated':False,'redis_isolated':False,'safe_to_update':False}
    except (ValueError,KeyError,TypeError):raise PinError('KUBE_PIN_RESOURCES_UNVERIFIED') from None
