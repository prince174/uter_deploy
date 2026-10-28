from pathlib import Path
import json
import unittest
from unittest.mock import patch
from scripts import real_llm_upgrade_ci as ci


class RuntimeImageVerificationTests(unittest.TestCase):
    def test_kubernetes_accepts_image_config_id_but_rejects_wrong_image(self):
        image='ghcr.io/owner/guardrail@sha256:'+'a'*64
        config='sha256:'+'b'*64
        images={'guardrail':image}
        publication={'images':{'guardrail':{'image_id':config}}}
        deployment={'spec':{'template':{'spec':{'containers':[{'image':image}]}}}}
        pod={'metadata':{'labels':{'app.kubernetes.io/name':'guardrail','app.kubernetes.io/instance':'uter-ci'}},
             'spec':{'containers':[{'image':image}]},
             'status':{'containerStatuses':[{'ready':True,'image':image,'imageID':config}]}}
        def run(args, **kwargs):
            return json.dumps({'items':[pod]} if 'pods' in args else deployment).encode()
        with patch.object(ci,'call',side_effect=run):
            ci.verify_active_images('kubernetes','uter-ci',Path('.'),{},['kubectl'],images,publication)
            pod['status']['containerStatuses'][0]['imageID']='sha256:'+'c'*64
            with self.assertRaises(AssertionError):
                ci.verify_active_images('kubernetes','uter-ci',Path('.'),{},['kubectl'],images,publication)
