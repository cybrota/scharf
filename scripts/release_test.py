#!/usr/bin/env python3
"""Offline regression tests for the production release gate and state machine."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('release', Path(__file__).with_name('release.py'))
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)
SHA = 'a' * 40
BEFORE = 'b' * 40
VERSION = 'v1.4.2'
ENV = {'GITHUB_REPOSITORY': 'cybrota/scharf', 'GITHUB_REF': 'refs/heads/main',
       'GITHUB_EVENT_NAME': 'push', 'GITHUB_SHA': SHA}
EVENT = {'before': BEFORE, 'after': SHA, 'deleted': False}


class VersionTests(unittest.TestCase):
    def test_strict_versions(self):
        for value in ('v0.0.0', 'v1.4.2', 'v10.20.300\n'):
            with self.subTest(value=value):
                self.assertEqual(release.version(value)[0], value.rstrip('\n'))
        for value in ('1.4.2', 'v01.4.2', 'v1.04.2', 'v1.4.02', 'v1.4',
                      ' v1.4.2', 'v1.4.2 ', 'v1.4.2\n\n', 'v1.4.2\r\n',
                      'v1.4.2-rc.1', 'v1.4.2+build', 'v-1.4.2', '', 'v١.4.2'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                release.version(value)

    def test_compares_maximum_semver_not_last_or_lexical_tag(self):
        for tags in (['v1.4.1', 'v0.5.1'], ['v0.5.1', 'v1.4.1']):
            with self.subTest(tags=tags), self.assertRaises(ValueError):
                release.check_versions('v0.5.2', tags, None, SHA)
        release.check_versions('v1.10.0', ['v1.9.9', 'v0.5.1', 'junk'], None, SHA)
        with self.assertRaises(ValueError):
            release.check_versions('v1.9.9', ['v1.10.0'], None, SHA)

    def test_equal_version_only_resumes_same_commit(self):
        release.check_versions(VERSION, [VERSION, 'v1.4.1'], SHA, SHA)
        with self.assertRaisesRegex(ValueError, 'never move'):
            release.check_versions(VERSION, [VERSION], BEFORE, SHA)
        with self.assertRaises(ValueError):
            release.check_versions(VERSION, ['v2.0.0'], SHA, SHA)


class ContextTests(unittest.TestCase):
    def test_main_push(self):
        self.assertEqual(release.context(ENV, EVENT), (SHA, BEFORE))

    def test_rejects_wrong_origin_event_ref_and_sha(self):
        for key, values in {
            'GITHUB_REPOSITORY': ('fork/scharf', '', 'cybrota/other'),
            'GITHUB_REF': ('refs/heads/feature', 'refs/tags/v1.4.2', ''),
            'GITHUB_EVENT_NAME': ('pull_request', 'pull_request_target', 'workflow_dispatch', ''),
            'GITHUB_SHA': ('', 'a' * 39, 'g' * 40, 'A' * 40),
        }.items():
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    release.context(dict(ENV, **{key: value}), EVENT)
        for event in ({}, dict(EVENT, deleted=True), dict(EVENT, after=BEFORE),
                      dict(EVENT, before='0' * 40), dict(EVENT, before='bad'),
                      dict(EVENT, before=''), dict(EVENT, after='')):
            with self.subTest(event=event), self.assertRaises(ValueError):
                release.context(ENV, event)


class ArtifactFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.dist = self.root / 'dist'
        self.dist.mkdir()
        self.data = {name: ('fixture:' + name).encode() for name in release.ARCHIVES}
        manifest = ''.join(f'{hashlib.sha256(self.data[name]).hexdigest()}  {name}\n'
                           for name in sorted(self.data))
        self.manifest = f'scharf_{VERSION[1:]}_checksums.txt'
        self.data[self.manifest] = manifest.encode()
        for name, data in self.data.items():
            (self.dist / name).write_bytes(data)


class ArtifactTests(ArtifactFixture):
    def test_exact_set_and_hashes(self):
        self.assertEqual(release.assets(self.dist, VERSION),
                         {name: hashlib.sha256(data).hexdigest() for name, data in self.data.items()})

    def test_missing_archive(self):
        (self.dist / sorted(release.ARCHIVES)[0]).unlink()
        with self.assertRaises(ValueError):
            release.assets(self.dist, VERSION)

    def test_unexpected_archive(self):
        (self.dist / 'unreviewed.zip').write_bytes(b'extra')
        with self.assertRaises(ValueError):
            release.assets(self.dist, VERSION)

    def test_unexpected_manifest(self):
        (self.dist / 'wrong_checksums.txt').write_bytes(b'extra')
        with self.assertRaises(ValueError):
            release.assets(self.dist, VERSION)

    def test_corrupt_archive(self):
        (self.dist / sorted(release.ARCHIVES)[0]).write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError, 'Checksum'):
            release.assets(self.dist, VERSION)

    def test_duplicate_manifest_entry(self):
        path = self.dist / self.manifest
        lines = path.read_text().splitlines()
        lines[-1] = lines[0]
        path.write_text('\n'.join(lines) + '\n')
        with self.assertRaisesRegex(ValueError, 'Checksum'):
            release.assets(self.dist, VERSION)

    def test_empty_and_symlink_artifacts(self):
        name = sorted(release.ARCHIVES)[0]
        path = self.dist / name
        path.write_bytes(b'')
        with self.assertRaises(ValueError):
            release.assets(self.dist, VERSION)
        path.unlink()
        target = self.root / 'outside.zip'
        target.write_bytes(self.data[name])
        path.symlink_to(target)
        with self.assertRaises(ValueError):
            release.assets(self.dist, VERSION)


class ApiTests(unittest.TestCase):
    def test_only_404_can_mean_absent(self):
        for status in (401, 403, 422, 429, 500, 503):
            with self.subTest(status=status), mock.patch.object(release.subprocess, 'run',
                    return_value=subprocess.CompletedProcess([], 1, '', f'gh: failed (HTTP {status})')):
                with self.assertRaises(RuntimeError):
                    release.api('example', missing_ok=True)
        with mock.patch.object(release.subprocess, 'run', return_value=
                subprocess.CompletedProcess([], 1, '', 'gh: Not Found (HTTP 404)')):
            self.assertIsNone(release.api('example', missing_ok=True))
            with self.assertRaises(RuntimeError):
                release.api('example')

    def test_transport_failure_does_not_mean_absent(self):
        with mock.patch.object(release.subprocess, 'run', return_value=
                subprocess.CompletedProcess([], 2, '', 'network connection failed')):
            with self.assertRaises(RuntimeError):
                release.api('example', missing_ok=True)

    def test_tag_absent_and_lightweight(self):
        with mock.patch.object(release, 'api', return_value=None):
            self.assertIsNone(release.tag_commit(VERSION))
        with mock.patch.object(release, 'api', return_value={'object': {'type': 'commit', 'sha': SHA}}):
            self.assertEqual(release.tag_commit(VERSION), SHA)

    def test_annotated_tag_peels_to_commit(self):
        with mock.patch.object(release, 'api', side_effect=[
                {'object': {'type': 'tag', 'sha': 'tag1'}},
                {'object': {'type': 'tag', 'sha': 'tag2'}},
                {'object': {'type': 'commit', 'sha': SHA}}]) as api:
            self.assertEqual(release.tag_commit(VERSION), SHA)
            self.assertEqual(api.call_args_list[-1].args[0], 'repos/cybrota/scharf/git/tags/tag2')

    def test_tag_noncommit_and_cycle_fail_closed(self):
        for kind in ('tree', 'blob', 'tag'):
            with self.subTest(kind=kind), mock.patch.object(release, 'api', return_value=
                    {'object': {'type': kind, 'sha': 'cycle'}}) as api:
                with self.assertRaises(ValueError):
                    release.tag_commit(VERSION)
                self.assertLessEqual(api.call_count, 9)


class PublishTests(ArtifactFixture):
    """Run publish itself against in-memory remote state and actual local files."""
    def setUp(self):
        super().setUp()
        old_cwd = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, old_cwd)
        (self.root / 'release').mkdir()
        (self.root / 'release/version.txt').write_text(VERSION + '\n')
        (self.root / 'release/notes.md').write_text(f'# Scharf {VERSION}\n\nReviewed production release notes.\n')
        event_path = self.root / 'event.json'
        event_path.write_text(json.dumps(EVENT))
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.dict(os.environ, dict(ENV, GITHUB_EVENT_PATH=str(event_path))))
        self.remote_tag = SHA
        self.remote_release = {'id': 7, 'tag_name': VERSION, 'draft': True, 'prerelease': False}
        self.remote_assets = {}
        self.calls = []
        self.uploads = []
        self.fail_upload_number = None
        self.final_asset_override = None
        self.stack.enter_context(mock.patch.object(release, 'run', side_effect=self.git))
        self.stack.enter_context(mock.patch.object(release, 'api', side_effect=self.api))
        self.stack.enter_context(mock.patch.object(release.subprocess, 'check_call', side_effect=self.command))
        self.stack.enter_context(mock.patch.object(release.subprocess, 'check_output', side_effect=self.download))
        # A stray subprocess call must never reach a real repository or network.
        self.stack.enter_context(mock.patch.object(release.subprocess, 'run', side_effect=AssertionError('Unexpected subprocess')))
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))

    def git(self, *args):
        if args == ('git', 'rev-parse', 'HEAD'):
            return SHA
        if args == ('git', 'tag', '--list'):
            return 'v1.4.1\n' + (VERSION if self.remote_tag else '')
        raise AssertionError(f'Unexpected git command: {args}')

    def asset_rows(self):
        return [{'id': index, 'name': name, 'state': 'uploaded'}
                for index, name in enumerate(self.remote_assets, 1)]

    def api(self, endpoint, method='GET', payload=None, missing_ok=False):
        self.calls.append((endpoint, method, payload))
        prefix = 'repos/cybrota/scharf/'
        if endpoint == prefix + f'git/ref/tags/{VERSION}' and method == 'GET':
            return {'object': {'type': 'commit', 'sha': self.remote_tag}} if self.remote_tag else None
        if endpoint == prefix + 'git/refs' and method == 'POST':
            self.assertIsNone(self.remote_tag, 'Never overwrite a tag')
            self.assertEqual(payload, {'ref': f'refs/tags/{VERSION}', 'sha': SHA})
            self.remote_tag = SHA
            return {}
        if endpoint == prefix + f'releases/tags/{VERSION}' and method == 'GET':
            return self.remote_release
        if endpoint == prefix + 'releases' and method == 'POST':
            self.assertTrue(payload['draft'])
            self.assertEqual(payload['target_commitish'], SHA)
            self.remote_release = dict(payload, id=7)
            return self.remote_release
        if endpoint.startswith(prefix + 'releases/7/assets?') and method == 'GET':
            if endpoint.endswith('per_page=100') and self.final_asset_override is not None:
                return self.final_asset_override
            return self.asset_rows()
        if endpoint == prefix + 'releases/7' and method == 'PATCH':
            self.assertEqual(set(self.remote_assets), set(self.data))
            self.remote_release.update(payload)
            return self.remote_release
        raise AssertionError(f'Unexpected API mutation or read: {method} {endpoint}')

    def download(self, args):
        self.assertEqual(args[:2], ['gh', 'api'])
        self.assertIn('Accept: application/octet-stream', args)
        asset_id = int(args[2].rsplit('/', 1)[1])
        name = list(self.remote_assets)[asset_id - 1]
        return self.remote_assets[name]

    def command(self, args):
        if args == ['git', 'fetch', '--tags', 'origin']:
            return 0
        if args[:3] == ['gh', 'release', 'upload']:
            self.assertNotIn('--clobber', args)
            name = Path(args[4]).name
            self.assertNotIn(name, self.remote_assets, 'Never overwrite an existing asset')
            self.uploads.append(name)
            if len(self.uploads) == self.fail_upload_number:
                raise subprocess.CalledProcessError(1, args)
            self.remote_assets[name] = Path(args[4]).read_bytes()
            return 0
        raise AssertionError(f'Unexpected subprocess: {args}')

    def mutations(self):
        return [call for call in self.calls if call[1] != 'GET']

    def test_new_tag_and_release_created_as_draft_then_published(self):
        self.remote_tag = None
        self.remote_release = None
        release.publish()
        self.assertEqual(self.remote_tag, SHA)
        self.assertFalse(self.remote_release['draft'])
        self.assertEqual([call[1] for call in self.mutations()], ['POST', 'POST', 'PATCH'])
        self.assertEqual(set(self.uploads), set(self.data))

    def test_interrupted_upload_resumes_without_overwrite(self):
        self.fail_upload_number = 3
        with self.assertRaises(subprocess.CalledProcessError):
            release.publish()
        self.assertTrue(self.remote_release['draft'])
        self.assertEqual(len(self.remote_assets), 2)
        already_uploaded = set(self.remote_assets)
        self.uploads.clear()
        self.fail_upload_number = None
        release.publish()
        self.assertFalse(self.remote_release['draft'])
        self.assertEqual(set(self.uploads), set(self.data) - already_uploaded)

    def test_final_patch_lost_response_replay_is_noop(self):
        original = self.api

        def lost_response(endpoint, method='GET', payload=None, missing_ok=False):
            result = original(endpoint, method, payload, missing_ok)
            if method == 'PATCH':
                raise RuntimeError('Response lost after server accepted publication')
            return result

        with mock.patch.object(release, 'api', side_effect=lost_response):
            with self.assertRaises(RuntimeError):
                release.publish()
        self.assertFalse(self.remote_release['draft'])
        self.calls.clear()
        self.uploads.clear()
        release.publish()
        self.assertEqual(self.mutations(), [])
        self.assertEqual(self.uploads, [])

    def test_atomic_tag_creation_conflict_does_not_retry_or_force(self):
        self.remote_tag = None
        original = self.api

        def conflict(endpoint, method='GET', payload=None, missing_ok=False):
            if method == 'POST' and endpoint.endswith('/git/refs'):
                self.remote_tag = BEFORE
                raise RuntimeError('HTTP 422: reference already exists')
            return original(endpoint, method, payload, missing_ok)

        with mock.patch.object(release, 'api', side_effect=conflict):
            with self.assertRaises(RuntimeError):
                release.publish()
        self.assertEqual(self.remote_tag, BEFORE)
        self.assertEqual(self.uploads, [])
        self.assertTrue(self.remote_release['draft'])

    def test_remote_read_failure_never_creates_release(self):
        original = self.api

        def unavailable(endpoint, method='GET', payload=None, missing_ok=False):
            if endpoint.endswith('/releases/tags/' + VERSION):
                raise RuntimeError('HTTP 503')
            return original(endpoint, method, payload, missing_ok)

        with mock.patch.object(release, 'api', side_effect=unavailable):
            with self.assertRaises(RuntimeError):
                release.publish()
        self.assertEqual(self.mutations(), [])
        self.assertEqual(self.uploads, [])

    def test_existing_complete_draft_only_publishes(self):
        self.remote_assets = dict(self.data)
        release.publish()
        self.assertEqual(self.uploads, [])
        self.assertEqual([call[1] for call in self.mutations()], ['PATCH'])

    def test_identical_published_release_is_noop(self):
        self.remote_assets = dict(self.data)
        self.remote_release['draft'] = False
        release.publish()
        self.assertEqual(self.mutations(), [])
        self.assertEqual(self.uploads, [])

    def test_incomplete_published_release_fails_without_mutation(self):
        self.remote_release['draft'] = False
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            release.publish()
        self.assertEqual(self.mutations(), [])
        self.assertEqual(self.uploads, [])

    def test_remote_mismatch_is_never_overwritten(self):
        for draft in (True, False):
            self.remote_release['draft'] = draft
            self.remote_assets = {sorted(self.data)[0]: b'wrong bytes'}
            with self.subTest(draft=draft), self.assertRaisesRegex(ValueError, 'mismatch'):
                release.publish()
        self.assertEqual(self.mutations(), [])
        self.assertEqual(self.uploads, [])

    def test_mismatched_tag_never_moves(self):
        self.remote_tag = BEFORE
        with self.assertRaisesRegex(ValueError, 'never move'):
            release.publish()
        self.assertEqual(self.mutations(), [])
        self.assertEqual(self.uploads, [])

    def test_tag_race_before_publish_aborts(self):
        with mock.patch.object(release, 'tag_commit', side_effect=[SHA, SHA, BEFORE]):
            with self.assertRaisesRegex(ValueError, 'changed before publish'):
                release.publish()
        self.assertTrue(self.remote_release['draft'])
        self.assertEqual(self.mutations(), [])

    def test_release_wrong_tag_or_prerelease_rejected(self):
        for update in ({'tag_name': 'v9.0.0'}, {'prerelease': True}):
            original = dict(self.remote_release)
            self.remote_release.update(update)
            with self.subTest(update=update), self.assertRaises(ValueError):
                release.publish()
            self.remote_release = original
        self.assertEqual(self.mutations(), [])
        self.assertEqual(self.uploads, [])

    def test_duplicate_unexpected_or_incomplete_remote_assets_rejected(self):
        name = sorted(self.data)[0]
        self.remote_assets[name] = self.data[name]
        valid = {'id': 1, 'name': name, 'state': 'uploaded'}
        for rows in ([valid, valid], [dict(valid, name='extra.zip')], [dict(valid, state='new')]):
            with self.subTest(rows=rows), mock.patch.object(self, 'asset_rows', return_value=rows):
                with self.assertRaises(ValueError):
                    release.publish()
        self.assertEqual(self.mutations(), [])
        self.assertEqual(self.uploads, [])

    def test_final_corrupt_bytes_cannot_publish(self):
        self.remote_assets = dict(self.data)
        original = self.download
        count = 0

        def corrupt_final(args):
            nonlocal count
            count += 1
            return original(args) if count <= len(self.data) else b'corrupt'

        with mock.patch.object(release.subprocess, 'check_output', side_effect=corrupt_final):
            with self.assertRaisesRegex(ValueError, 'Final remote asset bytes'):
                release.publish()
        self.assertTrue(self.remote_release['draft'])
        self.assertEqual(self.mutations(), [])

    def test_tag_race_during_final_verification_aborts(self):
        self.remote_assets = dict(self.data)
        with mock.patch.object(release, 'tag_commit', side_effect=[SHA, SHA, SHA, BEFORE]):
            with self.assertRaisesRegex(ValueError, 'changed during verification'):
                release.publish()
        self.assertTrue(self.remote_release['draft'])
        self.assertEqual(self.mutations(), [])

    def test_final_missing_or_duplicate_assets_cannot_publish(self):
        self.remote_assets = dict(self.data)
        rows = self.asset_rows()
        for invalid in (rows[:-1], rows[:-1] + [rows[0]], [dict(row, state='new') for row in rows]):
            self.final_asset_override = invalid
            with self.subTest(rows=invalid), self.assertRaisesRegex(ValueError, 'incomplete'):
                release.publish()
        self.assertTrue(self.remote_release['draft'])
        self.assertEqual(self.mutations(), [])


class PrepareTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        old_cwd = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, old_cwd)
        (self.root / 'release').mkdir()
        (self.root / 'release/version.txt').write_text(VERSION + '\n')
        (self.root / 'release/notes.md').write_text(f'# Scharf {VERSION}\n\nReviewed production release notes.\n')
        (self.root / 'event.json').write_text(json.dumps(EVENT))
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.dict(os.environ, dict(
            ENV, GITHUB_EVENT_PATH=str(self.root / 'event.json'),
            GITHUB_OUTPUT=str(self.root / 'outputs'))))
        self.run = self.stack.enter_context(mock.patch.object(release, 'run', side_effect=[
            SHA, release.VERSION_FILE, 'v1.4.1']))
        self.command = self.stack.enter_context(mock.patch.object(release.subprocess, 'check_call'))
        self.local_tag = self.stack.enter_context(mock.patch.object(release.subprocess, 'run',
            return_value=subprocess.CompletedProcess([], 1, '', 'missing local tag')))
        self.stack.enter_context(mock.patch.object(release, 'tag_commit', return_value=None))

    def test_valid_gate_creates_local_tag_and_output(self):
        release.prepare()
        self.assertEqual((self.root / 'outputs').read_text(), 'version=' + VERSION + '\n')
        self.command.assert_any_call(['git', 'merge-base', '--is-ancestor', BEFORE, SHA])
        self.command.assert_any_call(['git', 'tag', VERSION, SHA])

    def test_wrong_checkout_cannot_output_version(self):
        self.run.side_effect = [BEFORE]
        with self.assertRaisesRegex(ValueError, 'exact event commit'):
            release.prepare()
        self.assertFalse((self.root / 'outputs').exists())
        self.command.assert_not_called()

    def test_unchanged_version_cannot_output_version(self):
        self.run.side_effect = [SHA, '']
        with self.assertRaisesRegex(ValueError, 'did not change'):
            release.prepare()
        self.assertFalse((self.root / 'outputs').exists())

    def test_nonancestor_push_cannot_output_version(self):
        self.command.side_effect = subprocess.CalledProcessError(1, ['git', 'merge-base'])
        with self.assertRaises(subprocess.CalledProcessError):
            release.prepare()
        self.assertFalse((self.root / 'outputs').exists())

    def test_wrong_release_notes_cannot_output_version(self):
        (self.root / 'release/notes.md').write_text('# Scharf v9.0.0\n\nRelease notes for wrong version.\n')
        with self.assertRaisesRegex(ValueError, 'notes must match'):
            release.prepare()
        self.assertFalse((self.root / 'outputs').exists())

    def test_conflicting_local_tag_cannot_move_or_output_version(self):
        self.local_tag.return_value = subprocess.CompletedProcess([], 0, BEFORE + '\n', '')
        with self.assertRaisesRegex(ValueError, 'Local tag mismatch'):
            release.prepare()
        self.assertFalse((self.root / 'outputs').exists())
        self.assertNotIn(mock.call(['git', 'tag', VERSION, SHA]), self.command.call_args_list)


if __name__ == '__main__':
    unittest.main()
