import clojure_action
import unittest
from unittest import TestCase, mock
import os
import json

all_opts = {
    'INPUT_NOMONITOR': 'true',
    'INPUT_SNYKPOLICY': '.snyk',
    'INPUT_SNYKORG': 'someorg',
    'INPUT_SNYKPROJECT': 'some-project'
}

class Testing(TestCase):
    
    def test_get_args_noopts(self):
        args = clojure_action._getArgs()
        self.assertIn('snyk', args)
        self.assertIn('monitor', args)
        self.assertIn('--file=pom.xml', args)
        self.assertIn('--json', args)

    @mock.patch.dict(os.environ, all_opts)
    def test_get_args_allOpts(self):
        args = clojure_action._getArgs()
        self.assertIn('snyk', args)
        self.assertIn('test', args)
        self.assertIn('--file=pom.xml', args)
        self.assertIn('--json', args)
        self.assertIn('--policy-path=.snyk', args)
        self.assertIn('--org=someorg', args)
        self.assertIn('--project=some-project', args)

    def test_parse_results_w_vulns(self):
        path = os.path.join('unit_test_files', 'test_res_vuln.json')
        with open(path, 'r') as f:
            contents = f.read()
        test_res = json.loads(contents)
        vulns = clojure_action._parseResults(test_res)
        self.assertTrue(len(vulns) != 0)

    def test_parse_no_vuln(self):
        path = os.path.join('unit_test_files', 'test_res_novuln.json')
        with open(path, 'r') as f:
            contents = f.read()
        test_res = json.loads(contents)
        vulns = clojure_action._parseResults(test_res)
        self.assertTrue(len(vulns) == 0)

if __name__ == '__main__':
    unittest.main()