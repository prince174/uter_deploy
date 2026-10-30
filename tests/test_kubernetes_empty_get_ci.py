import unittest
from scripts.kubernetes_empty_get_ci import classify


class EmptyGetClassificationTests(unittest.TestCase):
    def test_finite_output_only(self):
        self.assertEqual(classify(b'  \n'),'EMPTY')
        self.assertEqual(classify(b'{"apiVersion":"v1","kind":"List","items":[]}'),'EMPTY_LIST')
        self.assertEqual(classify(b'{"kind":"List","items":[{}]}'),'OTHER')
        self.assertEqual(classify(b'{'),'MALFORMED')
