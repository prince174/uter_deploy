import copy
import tempfile
from pathlib import Path
import unittest
from unittest import mock

from scripts import compose_redis_diagnostic as diag


class ComposeDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.home=Path(self.tmp.name)
        self.redis='a'*64;self.net='b'*64;self.image='registry.test/redis@sha256:'+'c'*64;self.image_id='sha256:'+'d'*64
        self.signed={'version':'0.1.6','images':{'redis':self.image,'agent':'agent','guardrail':'guard'},'image_config_ids':{'redis':self.image_id}}
        self.cfg={'backend':'compose','name':'uter-test','context':'default','images':self.signed['images']}
        self.state={'current':self.signed,'pending':None,'adopted_installer':True}
        self.site={'backend':'compose','name':'uter-test','namespace':'uter-test','context':'default'}
        (self.home/'bundle').mkdir()
        (self.home/'bundle/checksums.json').write_text('synthetic')
        (self.home/'releases/0.1.6').mkdir(parents=True)
        (self.home/'releases/0.1.6/checksums.json').write_text('synthetic')
        self.resource={'id':self.redis,'running':True,'pid':12,'started':'2026-10-30T00:00:00Z','restart_count':0,
                       'image':self.image,'image_id':self.image_id,'restart':'unless-stopped',
                       'network_mode':'uter-test_backend','ports':None,'publish_all':False,'runtime_ports':{'6379/tcp':None},
                       'privileged':False,'pid_mode':'',
                       'cap_add':None,'networks':{'uter-test_backend':{'NetworkID':self.net}},
                       'mounts':[{'Destination':'/data','Type':'volume','Name':'uter-test_redis-data','RW':True}]}
        self.network={'id':self.net,'driver':'bridge','internal':True,'project':'uter-test','network':'backend','scope':'local'}
        self.volume={'name':'uter-test_redis-data','driver':'local','project':'uter-test','volume':'redis-data','options':None}

    def run_diagnostic(self, *, resource=None, second=None, network=None, volume=None, local_image=None):
        first=resource if resource is not None else self.resource
        responses=['unix:///var/run/docker.sock', self.redis, local_image if local_image is not None else self.image_id,
                   network if network is not None else self.network, volume if volume is not None else self.volume]
        with mock.patch.dict(diag.os.environ,{},clear=True), \
             mock.patch.object(diag.uterctl,'verify',return_value=self.signed), \
             mock.patch.object(diag.uterctl,'read',side_effect=[self.state,self.cfg]), \
             mock.patch.object(diag.uterctl,'site_config',return_value=self.site), \
             mock.patch.object(diag.adopt_installation,'verify_live') as live, \
             mock.patch.object(diag.install,'commands',return_value=(['docker','-f','old'],{})), \
             mock.patch.object(diag,'_json',side_effect=responses), \
             mock.patch.object(diag,'_read',return_value=self.redis[:12]), \
             mock.patch.object(diag,'_redis_inspect',side_effect=[first,second if second is not None else first]):
            result=diag.inspect_installation(self.home,self.home/'bundle',self.home/'publisher')
            live.assert_called_once()
            return result

    def test_success_remains_read_only_and_does_not_establish_fence(self):
        result=self.run_diagnostic()
        self.assertEqual(result,{'result':'supported_shape_observed','backend':'compose','isolation_established':False,
                                 'writers_stopped':False,'safe_to_upgrade':False})

    def test_rejects_runtime_shapes_that_could_bypass_isolation(self):
        for change in ({'running':False},{'pid':0},{'restart':'always'},{'ports':{'6379/tcp':[{}]}},
                       {'privileged':True},{'pid_mode':'host'},{'cap_add':['NET_ADMIN']},{'network_mode':'host'},
                       {'publish_all':True},{'runtime_ports':{'6379/tcp':[{'HostPort':'6379'}]}},
                       {'networks':{}},{'networks':{'uter-test_backend':{'NetworkID':self.net},'other':{}}},
                       {'image':'untrusted'},{'image_id':None},{'restart_count':-1},
                       {'mounts':[{'Destination':'/data','Type':'bind','RW':True}]}):
            bad=copy.deepcopy(self.resource);bad.update(change)
            with self.subTest(change=change),self.assertRaises(diag.ComposeDiagnosticError):self.run_diagnostic(resource=bad)

    def test_rejects_wrong_or_untrusted_network_and_volume(self):
        for field, bad in [('driver','overlay'),('internal',False),('scope','swarm'),('project','different'),('id','z'*64)]:
            value=dict(self.network,**{field:bad})
            with self.subTest(field=field),self.assertRaisesRegex(diag.ComposeDiagnosticError,'NETWORK_INVALID'):
                self.run_diagnostic(network=value)
        for field,bad in [('name','other'),('driver','other'),('project','other'),('options',{'type':'nfs'})]:
            value=dict(self.volume,**{field:bad})
            with self.subTest(field=field),self.assertRaisesRegex(diag.ComposeDiagnosticError,'VOLUME_INVALID'):
                self.run_diagnostic(volume=value)

    def test_rejects_image_change_and_live_race(self):
        with self.assertRaisesRegex(diag.ComposeDiagnosticError,'IMAGE_CHANGED'):
            self.run_diagnostic(local_image='sha256:'+'e'*64)
        with self.assertRaisesRegex(diag.ComposeDiagnosticError,'STATE_CHANGED'):
            self.run_diagnostic(second=dict(self.resource,pid=13))

    def test_installed_bundle_must_match_selected_signed_bundle(self):
        (self.home/'releases/0.1.6/checksums.json').write_text('different')
        with self.assertRaisesRegex(diag.ComposeDiagnosticError,'INSTALLED_BUNDLE_MISMATCH'):
            self.run_diagnostic()

    def test_rejects_remote_context_or_environment_before_any_runtime_query(self):
        for overrides in ({'DOCKER_HOST':'unix:///tmp/other.sock'},{'DOCKER_CONTEXT':'external'}):
            with self.subTest(overrides=overrides), mock.patch.dict(diag.os.environ, overrides,clear=True), \
                 mock.patch.object(diag.uterctl,'verify',return_value=self.signed), \
                 mock.patch.object(diag.uterctl,'read',side_effect=[self.state,self.cfg]), \
                 mock.patch.object(diag.uterctl,'site_config',return_value=self.site), \
                 mock.patch.object(diag,'_json') as runtime, \
                 mock.patch.object(diag.adopt_installation,'verify_live') as live:
                with self.assertRaisesRegex(diag.ComposeDiagnosticError,'IDENTITY_INVALID'):
                    diag.inspect_installation(self.home,self.home/'bundle',self.home/'publisher')
                runtime.assert_not_called();live.assert_not_called()

    def test_rejects_unadopted_pending_or_unmatched_state(self):
        for update in ({'adopted_installer':False},{'pending':{'version':'pending'}},{'current':{}}):
            with self.subTest(update=update), mock.patch.dict(diag.os.environ,{},clear=True), \
                 mock.patch.object(diag.uterctl,'verify',return_value=self.signed), \
                 mock.patch.object(diag.uterctl,'read',side_effect=[dict(self.state,**update),self.cfg]), \
                 mock.patch.object(diag.uterctl,'site_config',return_value=self.site), \
                 mock.patch.object(diag,'_json') as runtime:
                with self.assertRaisesRegex(diag.ComposeDiagnosticError,'IDENTITY_INVALID'):
                    diag.inspect_installation(self.home,self.home/'bundle',self.home/'publisher')
                runtime.assert_not_called()

    def test_runtime_error_is_sanitized(self):
        with mock.patch.object(diag.install_recovery,'run_readonly',side_effect=ValueError('secret content')):
            with self.assertRaisesRegex(diag.ComposeDiagnosticError,'^COMPOSE_DIAGNOSTIC_QUERY_FAILED$') as error:
                diag._read(['synthetic'])
            self.assertNotIn('secret',str(error.exception))

    def test_redis_inspection_difference_is_classified_without_weakening_equality(self):
        base=copy.deepcopy(self.resource)
        base['networks']['uter-test_backend'].update({'Aliases':['redis','uter-test-redis'],
                                                      'DNSNames':['redis','uter-test-redis'],
                                                      'EndpointID':'x'*64,'MacAddress':'02:42:00:00:00:01'})
        cases=(('PROCESS',lambda x:x.update(pid=13)),
               ('MOUNTS',lambda x:x['mounts'].append({'Name':'secret-volume'})),
               ('ENDPOINT_ID',lambda x:x['networks']['uter-test_backend'].update(EndpointID='z'*64)),
               ('ALIASES_ORDER',lambda x:x['networks']['uter-test_backend']['Aliases'].reverse()),
               ('ALIASES_CONTENT',lambda x:x['networks']['uter-test_backend']['Aliases'].append('other')),
               ('DNSNAMES_ORDER',lambda x:x['networks']['uter-test_backend']['DNSNames'].reverse()),
               ('NETWORK_FIELDS',lambda x:x['networks']['uter-test_backend'].update(Unexpected='secret')))
        for name,mutate in cases:
            with self.subTest(name=name):
                changed=copy.deepcopy(base);mutate(changed)
                with self.assertRaisesRegex(diag.ComposeDiagnosticError,'^COMPOSE_DIAGNOSTIC_STATE_CHANGED_'+name+'$') as error:
                    self.run_diagnostic(resource=base,second=changed)
                self.assertNotIn('secret',str(error.exception))

    def test_runtime_queries_are_readonly_and_do_not_inspect_config_or_environment(self):
        with mock.patch.object(diag,'_json',return_value={}) as read:
            diag._redis_inspect(self.redis)
        command=read.call_args.args[0]
        self.assertEqual(command[:4],['docker','--context','default','inspect'])
        self.assertNotIn('.Config.Env',command[-2]);self.assertNotIn('{{json .Config}}',command[-2])
        self.assertNotIn('secret',command[-2].lower())


if __name__=='__main__':unittest.main()
