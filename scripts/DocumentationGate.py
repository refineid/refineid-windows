#!/usr/bin/env python3
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
"""Usage: DocumentationGate.py commit|push [remote-name].

Exit 0: documentation validated; 1: engineering gate required; 2: invalid docs.
Push consumes Git's pre-push update records on stdin.
"""

import posixpath
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit


class InvalidDocumentation(Exception):
    pass


def git(*args):
    return subprocess.check_output(['git', *args], stderr=subprocess.PIPE)


def is_prose(path):
    return path in {'AGENTS.md', 'README.md'} or (
        path.startswith(('Documentation/process/', 'Documentation/design/', 'doc/process/', 'doc/design/', 'doc/architecture/', 'doc/security/'))
        and path.endswith('.md') and '\n' not in path and '\r' not in path
    )


def changes(base, target):
    args = ['diff', '--raw', '--no-renames', '--no-abbrev', '-z']
    args += ['--cached', base] if target is None else [base, target]
    fields = git(*args).split(bytes([0]))
    result = []
    for index in range(0, len(fields) - 1, 2):
        metadata = fields[index].decode().split()
        path = fields[index + 1].decode('utf-8')
        old_mode, new_mode = metadata[0][1:], metadata[1]
        if new_mode == '000000':
            return None  # Deletions can invalidate links in unchanged documents.
        if not is_prose(path) or any(mode not in {'000000', '100644'} for mode in (old_mode, new_mode)):
            return None
        for blob, mode in ((metadata[2], old_mode), (metadata[3], new_mode)):
            if mode != '000000':
                content = git('cat-file', 'blob', blob)
                if content.startswith(b'#!') or b'<!-- executable-documentation -->' in content:
                    return None
        result.append((path, metadata[3], new_mode))
    return result


def validate(base, target, records):
    args = ['diff', '--check'] + (['--cached', base] if target is None else [base, target])
    result = subprocess.run(['git', *args], capture_output=True, text=True)
    if result.returncode:
        raise InvalidDocumentation(result.stdout + result.stderr)
    # Inspect the committed/index snapshot, never unstaged edits.
    tree = git('write-tree').decode().strip() if target is None else target
    for path, blob, mode in records:
        if mode == '000000':
            continue
        content = git('cat-file', 'blob', blob).decode('utf-8')
        content = re.sub(r'```.*?```|~~~.*?~~~', '', content, flags=re.S)
        links = re.findall(r'\]\(<?([^\s)>]+)>?(?:\s+"[^"]*")?\)', content)
        links += re.findall(r'^\s*\[[^\]]+\]:\s*<?([^\s>]+)>?', content, re.M)
        previous = subprocess.run(['git', 'show', f'{base}:{path}'], capture_output=True, text=True)
        old_links = set(re.findall(r'\]\(<?([^\s)>]+)>?(?:\s+"[^"]*")?\)', previous.stdout))
        old_links.update(re.findall(r'^\s*\[[^\]]+\]:\s*<?([^\s>]+)>?', previous.stdout, re.M))
        links = [link for link in links if link not in old_links]
        for link in links:
            parsed = urlsplit(link)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            destination = posixpath.normpath(posixpath.join(posixpath.dirname(path), unquote(parsed.path)))
            if destination == '..' or destination.startswith('../') or destination.startswith('/'):
                raise InvalidDocumentation(f'{path}: local link leaves repository: {link}')
            if subprocess.run(['git', 'cat-file', '-e', f'{tree}:{destination}'], capture_output=True).returncode:
                raise InvalidDocumentation(f'{path}: missing local link: {link}')


def ranges(mode, remote, updates):
    if mode == 'commit':
        return [(git('rev-parse', 'HEAD').decode().strip(), None)]
    result = []
    for line in updates.splitlines():
        fields = line.split()
        if len(fields) != 4:
            return None
        local_ref, local, remote_ref, old = fields
        if not all(re.fullmatch('[0-9a-f]{40}', value) for value in (local, old)):
            return None
        if set(local) == {'0'}:  # A deleted ref introduces no tree.
            continue
        if not local_ref.startswith('refs/heads/') or not remote_ref.startswith('refs/heads/'):
            return None
        if set(old) == {'0'}:
            old = git('merge-base', local, f'refs/remotes/{remote}/main').decode().strip()
        elif subprocess.run(['git', 'merge-base', '--is-ancestor', old, local], capture_output=True).returncode:
            return None
        # Check every introduced commit, including changes later reverted.
        commits = git('rev-list', '--reverse', f'{old}..{local}').decode().splitlines()
        for commit in commits:
            parents = git('rev-list', '--parents', '-n', '1', commit).decode().split()[1:]
            if len(parents) != 1:
                return None
            result.append((parents[0], commit))
    return result or None


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in {'commit', 'push'}:
        return 1
    try:
        selected = ranges(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else 'origin', sys.stdin.read() if sys.argv[1] == 'push' else '')
        if not selected:
            return 1
        checked = []
        for base, target in selected:
            records = changes(base, target)
            if records is None:
                return 1
            checked.append((base, target, records))
        if not any(records for _, _, records in checked):
            return 1
        for base, target, records in checked:
            validate(base, target, records)
        print('Documentation gate passed: whitespace and local links; no build required.')
        return 0
    except InvalidDocumentation as error:
        print(error, file=sys.stderr)
        return 2
    except (subprocess.CalledProcessError, UnicodeError, ValueError, IndexError):
        return 1  # Unknown scope always takes the strict lane.


if __name__ == '__main__':
    sys.exit(main())
