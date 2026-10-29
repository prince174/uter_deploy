import unittest
from unittest.mock import patch

from scripts import uter_wizard


class WizardEntryTests(unittest.TestCase):
    def test_dispatches_without_shell_and_propagates_exit(self):
        with patch.object(uter_wizard.subprocess, 'call', return_value=7) as call:
            self.assertEqual(uter_wizard.main(['update', '--home', '/safe/path']), 7)
        command = call.call_args.args[0]
        self.assertEqual(command[1:3], ['-I', '-B'])
        self.assertTrue(command[3].endswith('update_wizard.py'))
        self.assertEqual(command[4:], ['--home', '/safe/path'])

    def test_unknown_interactive_choice_does_not_execute(self):
        with patch.object(uter_wizard.sys.stdin, 'isatty', return_value=True), \
             patch('builtins.input', return_value='invalid'), \
             patch.object(uter_wizard.subprocess, 'call') as call:
            self.assertEqual(uter_wizard.main([]), 2)
        call.assert_not_called()

    def test_operation_help_is_forwarded_to_selected_assistant(self):
        with patch.object(uter_wizard.subprocess, 'call', return_value=0) as call:
            self.assertEqual(uter_wizard.main(['install', '--help']), 0)
        self.assertTrue(call.call_args.args[0][3].endswith('install_wizard.py'))
        self.assertEqual(call.call_args.args[0][4:], ['--help'])

    def test_noninteractive_missing_action_fails(self):
        with patch.object(uter_wizard.sys.stdin, 'isatty', return_value=False), \
             patch.object(uter_wizard.subprocess, 'call') as call:
            with self.assertRaises(SystemExit):
                uter_wizard.main([])
        call.assert_not_called()
