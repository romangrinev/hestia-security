#!/usr/bin/env python3
"""Read-only, bounded-memory checks for PHP hidden under other extensions.

Emit JSON Lines containing paths, hashes and reasons, never file contents.
Findings are heuristics for review, not proof that a file has been executed.
Exit 2 means the scan was incomplete; exit 0 can still include findings.
"""

import argparse
import hashlib
import json
import os
import re
import stat
import sys


CHUNK_SIZE = 1024 * 1024
OVERLAP = 4096
# Case-sensitive: .pHp/.PHP and other uncommon suffixes need this extra check.
PHP_SOURCE_SUFFIXES = {'.php', '.php5', '.php7', '.phtml', '.phar', '.inc', '.stub', '.tpl'}
MEDIA_SUFFIXES = {
    '.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.ico', '.avif', '.heic',
    '.heif', '.svg', '.pdf', '.ogv', '.ogg', '.flv', '.mp4', '.mkv', '.mov',
    '.avi', '.webm', '.mp3', '.wav', '.woff', '.woff2', '.zip', '.gz', '.dat',
}
# Require the tag separator: a chunk boundary is not the end of the file.
PHP_TAG = re.compile(rb'<\?php(?=\s)', re.I)
PHP_HEADER = re.compile(rb'\A(?:\xef\xbb\xbf)?\s*<\?(?:php(?=\s)|=)', re.I)
SHORT_EXPRESSION = re.compile(rb'<\?=\s{0,64}(?:\$[a-zA-Z_]|(?:eval|system|shell_exec)\s{0,64}\()')
GOTO = re.compile(rb'\bgoto\s{1,64}[a-zA-Z_][a-zA-Z0-9_]{0,128}\s{0,64};', re.I)
EVAL = re.compile(rb'\beval\s{0,64}\(', re.I)
REQUEST_EXECUTION = re.compile(
    rb'\b(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open)'
    rb'\s{0,64}\(\s{0,64}\$_(?:GET|POST|REQUEST|COOKIE)\b', re.I
)


def inspect_file(stream, suffix):
    """Stream the entire file; overlap preserves tokens across chunk boundaries."""
    digest = hashlib.sha256()
    size = goto_count = 0
    php = header = short_expression = evaluation = request_execution = False
    carry = b''
    while True:
        chunk = stream.read(CHUNK_SIZE)
        if not chunk:
            break
        digest.update(chunk)
        block = carry + chunk
        if size == 0:
            header = bool(PHP_HEADER.search(block))
        size += len(chunk)
        php = php or bool(PHP_TAG.search(block))
        short_expression = short_expression or bool(SHORT_EXPRESSION.search(block))
        evaluation = evaluation or bool(EVAL.search(block))
        request_execution = request_execution or bool(REQUEST_EXECUTION.search(block))
        # Count statements, not lines, and don't double-count the overlap.
        goto_count += sum(match.end() > len(carry) for match in GOTO.finditer(block))
        carry = block[-OVERLAP:]

    reasons = []
    if header:
        reasons.append('php_header_under_unexpected_extension')
    if (php or short_expression) and suffix.lower() in MEDIA_SUFFIXES:
        reasons.append('php_code_in_media')
    if (php or short_expression) and request_execution:
        reasons.append('php_request_execution')
    if php and goto_count > 20 and evaluation:
        reasons.append('goto_obfuscated_php_with_eval')
    return size, reasons, digest.hexdigest(), goto_count


def scan(root, emit):
    counts = {'files_scanned': 0, 'bytes_scanned': 0, 'findings': 0, 'errors': 0}

    def error(path, exc):
        counts['errors'] += 1
        emit({'type': 'error', 'path': path, 'errno': exc.errno})

    if os.path.islink(root) or not os.path.isdir(root):
        error(root, OSError(22, 'Root must be a real directory'))
    else:
        try:
            for directory, dirs, files, directory_fd in os.fwalk(
                root, follow_symlinks=False,
                onerror=lambda exc: error(exc.filename, exc),
            ):
                dirs[:] = [name for name in dirs if name not in ('.git', 'node_modules')]
                # Old evidence is already isolated; only trust root-owned,
                # non-writable quarantine directories as scan exclusions.
                for name in dirs[:]:
                    if name.startswith(('.malware-quarantine-', 'security-quarantine-')):
                        try:
                            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                            if info.st_uid == 0 and not info.st_mode & 0o022:
                                dirs.remove(name)
                        except OSError as exc:
                            error(os.path.join(directory, name), exc)
                for name in files:
                    suffix = os.path.splitext(name)[1]
                    if suffix in PHP_SOURCE_SUFFIXES:
                        continue
                    path = os.path.join(directory, name)
                    try:
                        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                        if not stat.S_ISREG(info.st_mode):
                            continue
                        if name.endswith(('.QUARANTINED', '.malware-bak')) and info.st_uid == 0 and not info.st_mode & 0o022:
                            continue
                        # Don't follow replaced symlinks or block on a replaced FIFO.
                        descriptor = os.open(
                            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                            dir_fd=directory_fd,
                        )
                        with os.fdopen(descriptor, 'rb') as stream:
                            opened = os.fstat(stream.fileno())
                            if not stat.S_ISREG(opened.st_mode):
                                continue
                            size, reasons, sha256, goto_count = inspect_file(stream, suffix)
                        counts['files_scanned'] += 1
                        counts['bytes_scanned'] += size
                        if reasons:
                            counts['findings'] += 1
                            emit({'type': 'finding', 'path': path, 'reasons': reasons,
                                  'size': size, 'sha256': sha256, 'goto_count': goto_count})
                    except OSError as exc:
                        error(path, exc)
        except OSError as exc:
            error(root, exc)
    emit({'type': 'summary', **counts, 'complete': counts['errors'] == 0})
    return 2 if counts['errors'] else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', help='Directory to inspect without changing any files')
    args = parser.parse_args()
    return scan(os.path.abspath(args.root), lambda record: print(json.dumps(record), flush=True))


if __name__ == '__main__':
    sys.exit(main())
