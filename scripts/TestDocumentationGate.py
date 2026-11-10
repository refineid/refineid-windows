#!/usr/bin/env python3
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
"""Usage: python3 -B Scripts/TestDocumentationGate.py."""

import os
from pathlib import Path
import subprocess
import stat
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('DocumentationGate.py').resolve()


class DocumentationGateTests(unittest.TestCase):
    def setUp(self):
        self.env = os.environ.copy()
        # Hooks export repository-local Git variables; fixture repos must not
        # inherit their parent's index or object directory.
        for key in subprocess.check_output(['git', 'rev-parse', '--local-env-vars'], text=True).split():
            self.env.pop(key, None)
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.git('init', '-q', '-b', 'main')
        self.git('config', 'user.name', 'Synthetic Author')
        self.git('config', 'user.email', 'author@example.com')
        self.write('README.md', 'Read me\n')
        self.write('source.swift', 'let value = 1\n')
        self.commit()
        self.base = self.git('rev-parse', 'HEAD').strip()
        self.git('update-ref', 'refs/remotes/origin/main', self.base)

    def tearDown(self):
        self.directory.cleanup()

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.root, text=True, stderr=subprocess.PIPE, env=self.env)

    def write(self, path, content):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)

    def commit(self):
        self.git('add', '.')
        self.git('-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'Synthetic change')

    def gate(self, mode='commit', old=None):
        data = ''
        if mode == 'push':
            data = f'refs/heads/topic {self.git("rev-parse", "HEAD").strip()} refs/heads/topic {old or "0" * 40}\n'
        return subprocess.run(['python3', '-B', str(SCRIPT), mode, 'origin'], cwd=self.root, input=data, text=True, capture_output=True, env=self.env)

    def test_prose_uses_index_not_worktree(self):
        self.write('README.md', 'Updated\n')
        self.git('add', '.')
        self.write('README.md', '[broken](missing.md)\n')
        self.assertEqual(self.gate().returncode, 0)

    def test_mixed_unknown_and_executable_are_strict(self):
        for path in ['source.swift', 'unknown.md', 'Documentation/protocol/spec.md', 'Scripts/check.sh']:
            with self.subTest(path=path):
                self.git('reset', '--hard', self.base)
                self.git('clean', '-fdq')
                self.write('README.md', 'Updated\n')
                self.write(path, 'Changed\n')
                self.git('add', '.')
                self.assertEqual(self.gate().returncode, 1)
        self.git('reset', '--hard', self.base)
        os.chmod(self.root / 'README.md', (self.root / 'README.md').stat().st_mode | stat.S_IXUSR)
        self.git('add', '.')
        self.assertEqual(self.gate().returncode, 1)

    def test_executable_document_is_strict(self):
        self.write('README.md', '#!/bin/sh\necho executable\n')
        self.git('add', '.')
        self.assertEqual(self.gate().returncode, 1)

    def test_links_and_whitespace(self):
        for content in ['Trailing space \n', '[missing](absent.md)\n']:
            self.write('README.md', content)
            self.git('add', '.')
            self.assertEqual(self.gate().returncode, 2)
        self.write('README.md', '[source](source.swift)\n')
        self.git('add', '.')
        self.assertEqual(self.gate().returncode, 0)

    def test_rename_from_code_is_strict(self):
        self.git('mv', 'source.swift', 'AGENTS.md')
        self.assertEqual(self.gate().returncode, 1)

    def test_document_deletion_is_docs(self):
        self.git('rm', 'README.md')
        self.assertEqual(self.gate().returncode, 0)

    def test_symlink_is_strict(self):
        (self.root / 'README.md').unlink()
        (self.root / 'README.md').symlink_to('source.swift')
        self.git('add', '.')
        self.assertEqual(self.gate().returncode, 1)

    def test_push_new_and_existing_branch(self):
        self.write('README.md', 'Updated\n')
        self.commit()
        self.assertEqual(self.gate('push').returncode, 0)
        self.assertEqual(self.gate('push', self.base).returncode, 0)

    def test_push_reverted_code_is_strict(self):
        self.write('source.swift', 'Changed\n')
        self.commit()
        self.write('source.swift', 'let value = 1\n')
        self.write('README.md', 'Updated\n')
        self.commit()
        self.assertEqual(self.gate('push').returncode, 1)

    def test_push_without_base_is_strict(self):
        self.write('README.md', 'Updated\n')
        self.commit()
        self.git('update-ref', '-d', 'refs/remotes/origin/main')
        self.assertEqual(self.gate('push').returncode, 1)


if __name__ == '__main__':
    unittest.main()
