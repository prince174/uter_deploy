from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as E

ROOT=Path(__file__).resolve().parents[1]


class DiagramTests(unittest.TestCase):
    def test_drawio_edges_and_pages(self):
        for name, pages in [('uter-deployment.drawio', 2), ('uter-request-protection.drawio', 1)]:
            tree=E.parse(ROOT/'docs/diagrams'/name)
            self.assertEqual(len(tree.findall('.//diagram')),pages)
            for page in tree.findall('.//diagram'):
                cells=page.findall('.//mxCell'); ids=[n.get('id') for n in cells]
                self.assertEqual(len(ids),len(set(ids)))
                for cell in cells:
                    if cell.get('edge')=='1':
                        self.assertIn(cell.get('source'),ids)
                        self.assertIn(cell.get('target'),ids)

    def test_offline_diagrams_have_no_repository_addresses(self):
        paths=list((ROOT/'docs/diagrams').glob('*.drawio'))+list((ROOT/'docs').glob('uter-*.html'))
        for path in paths:
            text=path.read_text(encoding='utf-8-sig')
            for forbidden in ('github.com','ghcr.io','G:\\code','fileHref(', 'customer', 'pilot'):
                self.assertNotIn(forbidden,text,path.name)
            if path.suffix=='.html':
                self.assertNotRegex(text,r'<script[^>]+src=')
                self.assertNotRegex(text,r'\b(fetch|XMLHttpRequest|WebSocket)\s*\(')
        deployment=(ROOT/'docs/uter-deployment.html').read_text(encoding='utf-8-sig')
        for service in ('guardrail','agent','redis'):
            self.assertIn('docker.io/prince174/uter-'+service,deployment)
