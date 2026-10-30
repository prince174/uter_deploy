import unittest
from unittest import mock
from scripts import session_identity_upgrade_ci as session


def entry(length, digest='a', ttl=1799, own=0, other=0):
    return {'length':length, 'digest':digest*64, 'ttl':ttl, 'own':own, 'other':other}


def before():
    return dict(zip(session.KEYS, [entry(2),entry(2,'b'),entry(4,'c'),entry(2,'d'),entry(0,'e',-2),entry(0,'f',-2)]))


def after():
    return dict(zip(session.KEYS, [entry(2),entry(2,'b'),entry(4,'c'),entry(4,'0'),
                                  entry(4,'1',own=2),entry(4,'2',other=2)]))


class SessionIdentityUpgradeTests(unittest.TestCase):
    def test_two_principals_canonical_and_legacy_alias_semantics(self):
        old = before()
        with mock.patch.object(session, 'snapshot', side_effect=[old, after()]), \
             mock.patch.object(session, 'send_turns') as send:
            result = session.verify_after_update([], None, 'secret-canary', old)
        send.assert_called_once()
        self.assertEqual(result['canonical_history_continues'], 'pass')
        self.assertEqual(result['new_principals_isolated'], 'pass')
        self.assertEqual(result['legacy_alias_history_automatically_accessible'], 'no')
        self.assertNotIn('secret-canary', str(result))

    def test_cross_user_history_or_lost_old_values_fails(self):
        old = before(); wrong = after(); wrong[session.KEYS[4]]['other'] = 1
        with mock.patch.object(session, 'snapshot', side_effect=[old, wrong]), mock.patch.object(session, 'send_turns'):
            with self.assertRaisesRegex(session.SessionCheckFailure, '^SESSION_PRINCIPALS_NOT_ISOLATED$'):
                session.verify_after_update([], None, '', old)
        old2 = before(); damaged = before(); damaged[session.KEYS[0]]['digest'] = 'f'*64
        with mock.patch.object(session, 'snapshot', return_value=damaged):
            with self.assertRaisesRegex(session.SessionCheckFailure, '^SESSION_DATA_NOT_PRESERVED$'):
                session.verify_after_update([], None, '', old2)

    def test_canonical_history_must_continue(self):
        old = before(); wrong = after(); wrong[session.KEYS[3]]['length'] = old[session.KEYS[3]]['length']
        with mock.patch.object(session, 'snapshot', side_effect=[old, wrong]), mock.patch.object(session, 'send_turns'):
            with self.assertRaisesRegex(session.SessionCheckFailure, '^CANONICAL_SESSION_NOT_CONTINUED$'):
                session.verify_after_update([], None, '', old)

    def test_old_paths_need_real_shared_openai_key_and_separate_chat_keys(self):
        empty = {key:entry(0,ttl=-2) for key in session.KEYS}
        with mock.patch.object(session, 'snapshot', side_effect=[empty, before()]), mock.patch.object(session, 'send_turns'):
            self.assertEqual(session.prepare_baseline([], None, ''), before())
        wrong = before(); wrong[session.KEYS[2]]['length'] = 2
        with mock.patch.object(session, 'snapshot', side_effect=[empty, wrong]), mock.patch.object(session, 'send_turns'):
            with self.assertRaisesRegex(session.SessionCheckFailure, '^SESSION_OLD_BEHAVIOR_UNEXPECTED$'):
                session.prepare_baseline([], None, '')

    def test_uses_five_authenticated_calls_and_same_untrusted_alias(self):
        creds = dict(zip(session.SUBJECTS, ('fake-a','fake-b','fake-c')))
        with mock.patch.object(session, 'tokens', return_value=creds), mock.patch.object(session, 'post') as post:
            session.send_turns([], None, 'secret-canary')
        self.assertEqual(post.call_count, 5)
        calls = post.call_args_list
        self.assertEqual(calls[0].args[2]['user_id'], calls[1].args[2]['user_id'])
        self.assertEqual(calls[3].args[2]['user'], calls[4].args[2]['user'])
        self.assertNotEqual(calls[0].args[1], calls[1].args[1])

    def test_restoration_checks_each_session_without_logging_content(self):
        expected = after()
        with mock.patch.object(session, 'snapshot', return_value=expected):
            session.verify_restored([], None, expected)
        corrupted = after(); corrupted[session.KEYS[1]]['digest'] = 'f'*64
        with mock.patch.object(session, 'snapshot', return_value=corrupted):
            with self.assertRaisesRegex(session.SessionCheckFailure, '^SESSION_RESTORE_NOT_PRESERVED$'):
                session.verify_restored([], None, expected)


if __name__ == '__main__':
    unittest.main()
