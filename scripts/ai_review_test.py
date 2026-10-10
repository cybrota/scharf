import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import ai_review as r

PR = {'state': 'open', 'changed_files': 1, 'base': {'sha': 'a'*40, 'repo': {'full_name': 'cybrota/scharf'}}, 'head': {'sha': 'b'*40}}
FILES = [{'filename': 'main.go', 'status': 'modified', 'patch': '@@ -1 +1 @@\n-old\n+new', 'additions': 1, 'deletions': 1}]
ENV = {'GITHUB_REPOSITORY': 'cybrota/scharf', 'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REF': 'refs/heads/main',
       'APPROVE_SEND': 'true', 'PR_NUMBER': '64', 'PROVIDER': 'openai', 'MODEL': 'explicit-model', 'PROVIDER_API_KEY': 'test-key', 'GH_TOKEN': 'gh-test', 'GITHUB_SHA': 'c'*40, 'EXPECTED_HEAD_SHA': 'b'*40, 'EXPECTED_BASE_SHA': 'a'*40}

class ReviewTests(unittest.TestCase):
    def test_fingerprint(self):
        self.assertEqual(r.fingerprint(PR), ('a'*40, 'b'*40))
        for change in [{'state': 'closed'}, {'head': {'sha': 'main'}}, {'base': {'sha': 'a'*40, 'repo': {'full_name': 'evil/repo'}}}]:
            with self.subTest(change=change), self.assertRaises(r.ReviewError):
                r.fingerprint({**PR, **change})

    def test_input_is_json_data(self):
        files = copy.deepcopy(FILES)
        files[0]['filename'] = '$(curl evil);\n::error::owned'
        value = json.loads(r.make_input(PR, files, []))
        self.assertEqual(value['changes'][0]['filename'], files[0]['filename'])

    def test_rejects_missing_and_truncated_patches(self):
        for updates in [{'patch': None}, {'patch': ''}, {'additions': 2}, {'deletions': 2}]:
            with self.subTest(updates=updates), self.assertRaises(r.ReviewError):
                r.make_input(PR, [{**FILES[0], **updates}], [])

    def test_rejects_file_budget_and_incomplete_listing(self):
        for count in [0, 61, True, 2]:
            with self.subTest(count=count), self.assertRaises(r.ReviewError):
                r.make_input({**PR, 'changed_files': count}, FILES, [])

    def test_rejects_large_input(self):
        with self.assertRaises(r.ReviewError):
            r.make_input(PR, FILES, [{'content': 'a' * r.MAX_INPUT}])

    def test_sensitive_paths(self):
        for name in ['.env', 'foo/.env.production', 'foo/id_rsa', 'cert.key', 'cert.pem']:
            with self.subTest(name=name), self.assertRaises(r.ReviewError):
                r.make_input(PR, [{**FILES[0], 'filename': name}], [])

    def test_sensitive_renamed_path(self):
        with self.assertRaises(r.ReviewError):
            r.make_input(PR, [{**FILES[0], 'previous_filename': '.env.production'}], [])

    def test_dispatch_revision_mismatch(self):
        changed = {**PR, 'head': {'sha': 'd'*40}}
        calls, report = self._run_fixture([changed])
        self.assertEqual(calls, 0)
        self.assertIsNone(report)

    def test_sensitive_content(self):
        for value in ['-----BEGIN RSA PRIVATE KEY-----', 'ghp_'+'a'*25, 'sk-ant-'+'x'*25]:
            with self.subTest(value=value), self.assertRaises(r.ReviewError):
                r.make_input(PR, FILES, [{'content': value}])

    def test_skill_hash_and_origin(self):
        data = b'---\nname: test\n---\n'
        entry = {'path': 'skills/security/example/SKILL.md', 'sha256': hashlib.sha256(data).hexdigest()}
        config = {'schema_version': 1, 'repository': 'narenaryan/agent-skills', 'commit': 'a'*40, 'skills': [entry]}
        with patch.object(r, 'request', return_value=data) as req:
            result = r.load_skills(config)
            self.assertEqual(result[0]['content'], data.decode())
            self.assertTrue(req.call_args.args[0].startswith('https://raw.githubusercontent.com/narenaryan/agent-skills/'+'a'*40+'/'))
            for bad in [{**config, 'commit': 'main'}, {**config, 'repository': 'evil/repo'}, {**config, 'skills': [{**entry, 'path': '../x'}]}, {**config, 'skills': [{**entry, 'sha256': '0'*64}]}]:
                with self.assertRaises(r.ReviewError):
                    r.load_skills(bad)

    def test_openai_contract_and_redaction(self):
        response = {'status': 'completed', 'output': [{'type': 'message', 'content': [{'type': 'output_text', 'text': 'test-key gh-test'}]}]}
        with patch.dict(os.environ, ENV), patch.object(r, 'request', return_value=json.dumps(response).encode()) as req:
            text = r.call_model('openai', 'model-v1', 'diff', 'test-key')
            url, headers, body = req.call_args.args
            self.assertEqual(url, 'https://api.openai.com/v1/responses')
            self.assertEqual(body['max_output_tokens'], 4096)
            self.assertFalse(body['store'])
            self.assertEqual(body['tools'], [])
            self.assertNotIn('test-key', text)
            self.assertNotIn('gh-test', text)

    def test_anthropic_contract(self):
        response = {'stop_reason': 'end_turn', 'content': [{'type': 'text', 'text': 'review'}]}
        with patch.object(r, 'request', return_value=json.dumps(response).encode()) as req:
            self.assertEqual(r.call_model('anthropic', 'model-v1', 'diff', 'key'), 'review')
            url, headers, body = req.call_args.args
            self.assertEqual(url, 'https://api.anthropic.com/v1/messages')
            self.assertEqual(headers['anthropic-version'], '2023-06-01')
            self.assertEqual(body['max_tokens'], 4096)
            self.assertNotIn('tools', body)

    def test_provider_failure_no_retry(self):
        for provider, response in [('openai', {'status': 'incomplete'}), ('anthropic', {'stop_reason': 'max_tokens'})]:
            with patch.object(r, 'request', return_value=json.dumps(response).encode()) as req, self.assertRaises(r.ReviewError):
                r.call_model(provider, 'model', 'diff', 'key')
            self.assertEqual(req.call_count, 1)

    def test_missing_key_or_invalid_provider_model_no_request(self):
        for provider, model, key in [('openai', 'm', ''), ('openai', '$(x)', 'key'), ('other', 'm', 'key'), ('openai', 'm', 'a\nb')]:
            with patch.object(r, 'request') as req, self.assertRaises(r.ReviewError):
                r.call_model(provider, model, 'diff', key)
            req.assert_not_called()

    def test_redirect_refused(self):
        with self.assertRaises(r.ReviewError):
            r.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://evil.example')

    def test_invalid_json(self):
        with self.assertRaises(r.ReviewError):
            r.parse_json(b'no')

    def test_bad_provider_container(self):
        for provider in ('openai', 'anthropic'):
            with patch.object(r, 'request', return_value=b'[]'), self.assertRaises(r.ReviewError):
                r.call_model(provider, 'model', 'diff', 'key')

    def test_malformed_http_is_sanitized(self):
        with patch.object(r.urllib.request, 'build_opener') as opener:
            opener.return_value.open.side_effect = r.http.client.BadStatusLine('secret-remote-text')
            with self.assertRaises(r.ReviewError) as error:
                r.request('https://api.openai.com/v1/responses')
            self.assertNotIn('secret-remote-text', str(error.exception))

    def test_response_byte_limit(self):
        with patch.object(r.urllib.request, 'build_opener') as opener:
            opener.return_value.open.return_value.__enter__.return_value.read.return_value = b'x'*11
            with self.assertRaises(r.ReviewError):
                r.request('https://api.openai.com/v1/responses', limit=10)

    def test_run_guards_no_network(self):
        for update in [{'GITHUB_REF': 'refs/heads/evil'}, {'APPROVE_SEND': 'false'}, {'PR_NUMBER': '1;echo bad'}, {'GITHUB_EVENT_NAME': 'pull_request_target'}, {'GITHUB_REPOSITORY': 'fork/scharf'}]:
            with patch.dict(os.environ, {**ENV, **update}, clear=True), patch.object(r, 'github') as gh, self.assertRaises(r.ReviewError):
                r.run()
            gh.assert_not_called()

    def _run_fixture(self, responses):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, ENV, clear=True), patch.object(r, 'github', side_effect=responses), patch.object(r, 'load_skills', return_value=[]), patch.object(r, 'call_model', return_value='<script>untrusted</script>') as model:
            old = os.getcwd()
            os.chdir(tmp)
            try:
                Path('.github/ai-review').mkdir(parents=True)
                Path('.github/ai-review/skills.json').write_text(json.dumps({'commit':'a'*40, 'skills':[]}))
                try:
                    r.run()
                except r.ReviewError:
                    pass
                report = Path('ai-review-report.json')
                return model.call_count, json.loads(report.read_text()) if report.exists() else None
            finally:
                os.chdir(old)

    def test_stale_before_model_no_paid_call(self):
        changed = {**PR, 'head': {'sha': 'd'*40}}
        calls, report = self._run_fixture([PR, FILES, changed])
        self.assertEqual(calls, 0)
        self.assertIsNone(report)

    def test_stale_after_model_marked(self):
        changed = {**PR, 'head': {'sha': 'd'*40}}
        calls, report = self._run_fixture([PR, FILES, PR, changed])
        self.assertEqual(calls, 1)
        self.assertTrue(report['stale_at_completion'])
        self.assertEqual(report['head_sha'], 'b'*40)

    def test_final_freshness_failure_preserves_paid_result(self):
        calls, report = self._run_fixture([PR, FILES, PR, r.ReviewError('unavailable')])
        self.assertEqual(calls, 1)
        self.assertTrue(report['stale_at_completion'])
        self.assertEqual(report['freshness'], 'unknown')

    def test_success_report(self):
        calls, report = self._run_fixture([PR, FILES, PR, PR])
        self.assertEqual(calls, 1)
        self.assertFalse(report['stale_at_completion'])
        self.assertEqual(report['review_text'], '<script>untrusted</script>')
        self.assertNotIn('changes', report)

if __name__ == '__main__':
    unittest.main()
