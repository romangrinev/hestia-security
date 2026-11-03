import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SCANNER = Path(__file__).resolve().parents[1] / 'lib' / 'scan_disguised_php.py'
spec = importlib.util.spec_from_file_location('scanner', SCANNER)
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


class DisguisedPhpTests(unittest.TestCase):
    def inspect(self, content, suffix):
        return scanner.inspect_file(io.BytesIO(content), suffix)[1]

    def test_media_headers_and_mixed_case_php_are_detected(self):
        for suffix in ('.png', '.ogv', '.flv', '.pHp', '.PHP', '.txt', '.unknown', ''):
            with self.subTest(suffix=suffix):
                self.assertIn('php_header_under_unexpected_extension',
                              self.inspect(b'<?php echo "fixture"; ?>', suffix))

    def test_embedded_php_in_real_image_is_detected(self):
        content = b'\x89PNG\r\n\x1a\nimage bytes\x00<?php echo "fixture"; ?>'
        self.assertIn('php_code_in_media', self.inspect(content, '.png'))

    def test_short_echo_code_is_detected_without_binary_noise(self):
        self.assertIn('php_header_under_unexpected_extension', self.inspect(b'<?= "fixture" ?>', '.txt'))
        self.assertIn('php_code_in_media', self.inspect(b'GIF89a\x00<?= $fixture ?>', '.gif'))
        self.assertEqual([], self.inspect(b'\xff\xd8\x00<?=\xff\x88random bytes', '.jpg'))

    def test_obfuscation_counts_statements_on_one_line(self):
        content = b'prefix <?php ' + b'goto label; ' * 21 + b'eval($fixture); ?>'
        self.assertIn('goto_obfuscated_php_with_eval', self.inspect(content, '.unknown'))

    def test_chunk_boundary_tokens_are_not_missed_or_double_counted(self):
        with patch.object(scanner, 'CHUNK_SIZE', 64):
            content = b'x' * 62 + b'<?php ' + b'goto label; ' * 21 + b'eval($fixture);'
            size, reasons, digest, count = scanner.inspect_file(io.BytesIO(content), '.dat')
        self.assertEqual(len(content), size)
        self.assertEqual(21, count)
        self.assertIn('goto_obfuscated_php_with_eval', reasons)
        self.assertEqual(64, len(digest))

    def test_late_payload_is_not_hidden_by_a_size_limit(self):
        content = b'\x00' * (4 * scanner.CHUNK_SIZE + 15) + b'<?php echo "fixture"; ?>'
        self.assertIn('php_code_in_media', self.inspect(content, '.mp4'))

    def test_chunk_boundary_is_not_mistaken_for_end_of_php_tag(self):
        with patch.object(scanner, 'CHUNK_SIZE', 64):
            self.assertEqual([], self.inspect(b'x' * 59 + b'<?phpsomething', '.png'))

    def test_regular_assets_and_js_documentation_are_not_reported(self):
        for content, suffix in [
            (b'\x89PNG\x00ordinary image bytes', '.png'),
            (b'// Example: <?php echo "value"; ?>\nfunction load() {}', '.js'),
            (b'<?xml version="1.0"?><svg></svg>', '.svg'),
            (b'<?phpsomething is not a PHP open tag', '.txt'),
            (b'#!/usr/bin/env php\n<?php require "bootstrap.php";', ''),
        ]:
            with self.subTest(suffix=suffix):
                self.assertEqual([], self.inspect(content, suffix))

    def test_read_only_walk_skips_links_pipes_and_expected_php_sources(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
            base = Path(root)
            (base / 'fixture.pHp').write_bytes(b'<?php echo "fixture"; ?>')
            (base / 'regular.php').write_bytes(b'<?php echo "fixture"; ?>')
            (Path(outside) / 'external.png').write_bytes(b'<?php echo "fixture"; ?>')
            (base / 'link.png').symlink_to(Path(outside) / 'external.png')
            (base / 'linked-directory').symlink_to(outside, target_is_directory=True)
            os.mkfifo(str(base / 'pipe.png'))
            (base / '.git').mkdir()
            (base / '.git' / 'ignored.png').write_bytes(b'<?php echo "fixture"; ?>')
            before = (base / 'fixture.pHp').read_bytes()
            records = []
            self.assertEqual(0, scanner.scan(root, records.append))
            findings = [r for r in records if r['type'] == 'finding']
            self.assertEqual([str(base / 'fixture.pHp')], [r['path'] for r in findings])
            self.assertEqual(before, (base / 'fixture.pHp').read_bytes())
            self.assertTrue(records[-1]['complete'])

    def test_vendor_media_is_scanned(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'vendor' / 'package' / 'image.png'
            path.parent.mkdir(parents=True)
            path.write_bytes(b'<?php echo "fixture"; ?>')
            records = []
            scanner.scan(root, records.append)
            self.assertEqual(1, records[-1]['findings'])

    def test_missing_root_is_incomplete_not_clean(self):
        records = []
        self.assertEqual(2, scanner.scan('/nonexistent-disguised-php-test-root', records.append))
        self.assertFalse(records[-1]['complete'])
        self.assertEqual(1, records[-1]['errors'])

    def test_read_failure_is_reported(self):
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / 'unreadable.png').write_bytes(b'fixture')
            original_open = scanner.os.open

            def fail_file_open(path, *args, **kwargs):
                if path == 'unreadable.png':
                    raise PermissionError(13, 'denied')
                return original_open(path, *args, **kwargs)

            records = []
            with patch.object(scanner.os, 'open', side_effect=fail_file_open):
                self.assertEqual(2, scanner.scan(root, records.append))
            self.assertFalse(records[-1]['complete'])

    def test_cli_emits_valid_json_without_payload_or_raw_control_characters(self):
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / 'fixture\nname.png').write_bytes(b'<?php echo "PRIVATE_FIXTURE_CONTENT"; ?>')
            result = subprocess.run([sys.executable, str(SCANNER), root], capture_output=True, text=True)
            self.assertEqual(0, result.returncode)
            records = [json.loads(line) for line in result.stdout.splitlines()]
            self.assertEqual('finding', records[0]['type'])
            self.assertNotIn('PRIVATE_FIXTURE_CONTENT', result.stdout)
            self.assertEqual('summary', records[-1]['type'])

    def test_daily_audit_collects_findings_and_reports_missing_helper(self):
        audit = (SCANNER.parents[1] / '01-security-audit.sh').read_text()
        block = audit.split('    # PHP can be hidden in media,', 1)[1]
        block = block.split('    # 2. Search by suspicious filenames', 1)[0]
        # Drop the remainder of the first comment line after splitting it.
        block = block.split('\n', 1)[1]
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as reports:
            (Path(root) / 'fixture.flv').write_bytes(b'<?php echo "fixture"; ?>')
            env = dict(os.environ, SCRIPT_DIR=str(SCANNER.parents[1]),
                       WEB_DIR=root, REPORT_DIR=reports, user='fixture',
                       FOUND_FILE=str(Path(reports) / 'webshells-fixture.txt'))
            script = 'queue_alert() { printf "ALERT: %s\\n" "$1"; }\n' + block
            result = subprocess.run(['bash', '-c', script], env=env, capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn('PHP UNDER UNEXPECTED EXTENSION', result.stdout)
            self.assertIn('fixture.flv', Path(env['FOUND_FILE']).read_text())
            env['SCRIPT_DIR'] = root  # Simulate updating the shell script alone.
            result = subprocess.run(['bash', '-c', script], env=env, capture_output=True, text=True)
            self.assertIn('DISGUISED PHP SCAN INCOMPLETE', result.stdout)


if __name__ == '__main__':
    unittest.main()
