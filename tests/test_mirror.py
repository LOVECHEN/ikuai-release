import hashlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
SPEC = importlib.util.spec_from_file_location("mirror", Path(__file__).resolve().parents[1] / "scripts/mirror.py")
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class Response(io.BytesIO):
    def __init__(self, body, content_type="application/octet-stream", length=None):
        super().__init__(body)
        self.headers = {"Content-Type": content_type, "Content-Length": str(len(body) if length is None else length)}


class MirrorTests(unittest.TestCase):
    def setUp(self):
        # 模拟的 workflow command 不能变成真实 Actions 告警。
        output = patch.object(sys, "stdout", new_callable=io.StringIO)
        output.start()
        self.addCleanup(output.stop)

    def complete_order_fixture(self):
        groups = {
            "free-4.0.315-beta-Build202610291837": ["iKuai8_x64_4.0.315_beta_Build202610291837.bin"],
            "free-3.7.26-Build202609111743": ["iKuai8_x64_3.7.26_Build202609111743.bin"],
            "enterprise-3.7.26-Enterprise-Build202609111742": ["iKuai8_x64_3.7.26_Enterprise_Build202609111742.bin"],
            "hardware-M360X": ["IK-M360X_sysupgrade_3.7.26_Build202609111742.bin", "IK-M360X_sysupgrade_4.0.222_beta_Build202605211754.bin"],
            "oem-3.7.14-Build202408071731": ["oem_x64_3.7.14_Build202408071731.bin"],
            "hardware-H11": ["IK-H11_sysupgrade_1.9.0.bin", "IK-H11_sysupgrade_1.10.0.bin"],
            "resources-legacy-0": ["iKuai-GX2600_x64_3.5.4_Enterprise_Build202105071917.bin"],
            "resources-tools-0": ["Manual.pdf", "Tool.zip"],
        }
        expanded = {}
        for tag, names in groups.items():
            for name in names:
                expanded.setdefault(m.group_for(name) if m.hardware_parts(name) else tag, []).append(name)
        releases = []
        for index, (tag, names) in enumerate(expanded.items()):
            release = {"id": index + 1, "tag_name": tag, "assets": [{"name": name, "size": 10} for name in names]}
            release["name"] = m.release_title(tag, release["assets"])
            release["body"] = m.release_body("o/r", tag, m.presentation_records(release), [])
            releases.append(release)
        for tag in (m.CATEGORY_TAG, m.INDEX_TAG):
            releases.append({"tag_name": tag, "name": m.release_title(tag), "assets": []})
        releases.sort(key=lambda r: m.release_order_key(r["tag_name"], r["assets"]), reverse=True)
        return releases

    def test_global_audit_covers_all_types_and_every_file(self):
        releases = self.complete_order_fixture()
        report = m.ordering_audit("o/r", releases, m.release_index_body("o/r", releases), m.category_body("o/r", releases))
        self.assertEqual(report["status"], "success")
        self.assertEqual(report["issues"], [])
        self.assertEqual(report["releases"], 12)
        self.assertEqual(report["firmware_releases"], 9)
        self.assertEqual(report["resource_releases"], 1)
        self.assertEqual(report["files"], 11)

    def test_hardware_versions_and_builds_are_separate_even_for_same_model(self):
        names = ["IK-MT7981V1-Q3S_sysupgrade_3.7.26_Build202609111742.bin",
                 "IK-MT7981V1-Q3S_sysupgrade_3.7.11_Build202403041402.bin",
                 "IK-MT7981V1-Q3S_sysupgrade_3.7.9_Build202401121852.bin",
                 "IK-MT7981V1-Q3S_sysupgrade_3.7.5_Build202308250956.bin"]
        self.assertEqual(len({m.group_for(name) for name in names}), 4)
        self.assertEqual(m.group_for(names[0]), "hardware-IK-MT7981V1-Q3S-3.7.26-Build202609111742")
        entries = [m.candidate(name, "https://example.com/" + name) for name in names]
        for entry in entries:
            entry["tag"] = "hardware-IK-MT7981V1-Q3S"
        self.assertEqual(len({e["tag"] for e in m.merge_candidates(entries)}), 4)
        self.assertEqual(m.group_for("iKuai-GX2600_x32_3.5.4_Enterprise_Build202105071917.bin"),
                         m.group_for("iKuai-GX2600_x64_3.5.4_Enterprise_Build202105071917.bin"))

    def test_sorted_multi_year_hardware_group_cannot_pass_audit(self):
        names = ["IK-Q3S_sysupgrade_3.7.26_Build202609111742.bin", "IK-Q3S_sysupgrade_3.7.5_Build202308250956.bin"]
        release = {"tag_name": "hardware-IK-Q3S", "assets": [{"name": name} for name in names]}
        release["name"] = m.release_title(release["tag_name"], release["assets"])
        release["body"] = m.release_body("o/r", release["tag_name"], m.presentation_records(release), [])
        report = m.ordering_audit("o/r", [release], m.release_index_body("o/r", [release]), m.category_body("o/r", [release]))
        self.assertIn("hardware_version_grouping", {i["kind"] for i in report["issues"]})
        self.assertNotIn("file_table_order", {i["kind"] for i in report["issues"]})

    def test_compatibility_archive_stays_last_without_double_counting(self):
        releases = self.complete_order_fixture()
        archive = {"tag_name": "hardware-old", "name": "旧链接兼容", "assets": [
            {"name": "IK-Q3S_sysupgrade_3.7.5_Build202308250956.bin"}, {"name": m.SPLIT_META}]}
        releases.append(archive)
        self.assertEqual(m.release_kind(archive["tag_name"], archive["assets"]), "archive")
        self.assertLess(m.release_order_key(archive["tag_name"], archive["assets"]), m.release_order_key(m.INDEX_TAG))
        report = m.ordering_audit("o/r", releases, m.release_index_body("o/r", releases), m.category_body("o/r", releases))
        self.assertEqual(report["status"], "success")
        self.assertEqual(report["files"], 11)
        self.assertEqual(report["legacy_compat_releases"], 1)

    def test_copy_rejects_changed_source_before_upload(self):
        part = {"name": "fw.bin", "size": 4, "sha256": hashlib.sha256(b"good").hexdigest()}
        client = Mock(repo="o/r")
        with tempfile.TemporaryDirectory() as temp, patch.object(m, "request", return_value=Response(b"evil")), \
                patch.object(m, "upload_split_asset") as upload:
            with self.assertRaisesRegex(m.PublicationError, "SHA256"):
                m.copy_hardware_part(client, "old", {"tag_name": "new"}, part, {}, Path(temp))
            upload.assert_not_called()
            self.assertEqual(list(Path(temp).iterdir()), [])

    def test_copy_never_overwrites_same_name_different_digest(self):
        part = {"name": "fw.bin", "size": 4, "sha256": hashlib.sha256(b"good").hexdigest()}
        with tempfile.TemporaryDirectory() as temp, patch.object(m, "request") as request:
            with self.assertRaisesRegex(m.PublicationError, "不同内容"):
                m.copy_hardware_part(Mock(), "old", {"tag_name": "new"}, part,
                                     {"fw.bin": {"size": 4, "digest": "sha256:wrong"}}, Path(temp))
            request.assert_not_called()

    def test_split_upload_streams_with_content_length_and_checks_digest(self):
        client = Mock(repo="o/r")
        data = b"firmware"
        remote = {"id": 1, "name": "fw.bin", "size": len(data), "digest": "sha256:" + hashlib.sha256(data).hexdigest()}
        def upload(req, **kwargs):
            self.assertEqual(req.data.read(), data)
            self.assertEqual(req.get_header("Content-length"), str(len(data)))
            self.assertTrue(req.get_header("Authorization").startswith("Bearer "))
            return Response(json.dumps(remote).encode(), "application/json")
        with tempfile.TemporaryDirectory() as temp, patch.dict(m.os.environ, {"GH_TOKEN": "test-token"}), \
                patch.object(m.urllib.request, "urlopen", side_effect=upload):
            path = Path(temp) / "fw.bin"
            path.write_bytes(data)
            assets = {}
            m.upload_split_asset(client, {"id": 2, "tag_name": "new"}, path, assets)
            self.assertEqual(assets["fw.bin"], remote)
        client.assets.assert_not_called()

    def test_upload_rate_limit_is_distinguished_from_permission_failure(self):
        limited = urllib.error.HTTPError("https://uploads.github.com/", 403, "Forbidden",
                                         {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "160"}, io.BytesIO())
        with patch.object(m.time, "time", return_value=100):
            self.assertEqual(m.upload_rate_delay(limited), 61)
        secondary = urllib.error.HTTPError("https://uploads.github.com/", 403, "Forbidden", {},
                                           io.BytesIO(b'{"message":"secondary rate limit"}'))
        denied = urllib.error.HTTPError("https://uploads.github.com/", 403, "Forbidden", {},
                                        io.BytesIO(b'{"message":"Resource not accessible by integration"}'))
        self.assertEqual(m.upload_rate_delay(secondary), 60)
        self.assertIsNone(m.upload_rate_delay(denied))

    def test_split_upload_retries_rate_limit_without_overwriting_firmware(self):
        client = Mock(repo="o/r")
        client.assets.return_value = {}
        data = b"firmware"
        remote = {"id": 1, "name": "fw.bin", "size": len(data), "digest": "sha256:" + hashlib.sha256(data).hexdigest()}
        limited = urllib.error.HTTPError("https://uploads.github.com/", 403, "Forbidden", {"Retry-After": "2"}, io.BytesIO())
        with tempfile.TemporaryDirectory() as temp, patch.dict(m.os.environ, {"GH_TOKEN": "test-token"}), \
                patch.object(m.urllib.request, "urlopen", side_effect=[limited, Response(json.dumps(remote).encode())]) as upload, \
                patch.object(m.time, "sleep") as sleep:
            path = Path(temp) / "fw.bin"
            path.write_bytes(data)
            assets = {}
            m.upload_split_asset(client, {"id": 2, "tag_name": "new"}, path, assets)
        sleep.assert_called_once_with(2)
        self.assertEqual(upload.call_count, 2)
        self.assertEqual(assets["fw.bin"], remote)
        client.api.assert_not_called()

    def test_failed_copy_never_marks_old_model_as_finished(self):
        name = "IK-Q3S_sysupgrade_3.7.5_Build202308250956.bin"
        record = {"filename": name, "assets": [{"name": name, "size": 4, "sha256": "a" * 64}], "sha256": "a" * 64, "size": 4}
        item = {"legacy_tag": "hardware-IK-Q3S", "legacy_release_id": 7, "records": [record], "model": "IK-Q3S"}
        client = Mock(repo="o/r")
        client.release.return_value = {"id": 7}
        client.api.return_value = {"id": 8, "tag_name": m.group_for(name), "assets": []}
        client.read_asset.return_value = {"files": []}
        with tempfile.TemporaryDirectory() as temp, patch.object(m, "copy_hardware_part", side_effect=m.PublicationError("download failed")):
            with self.assertRaises(m.PublicationError):
                m.migrate_legacy_hardware(client, item, Path(temp))
        client.upload.assert_not_called()
        self.assertFalse(any(call.args[0].endswith("/7") for call in client.api.call_args_list))

    def test_successful_split_preserves_original_source_and_verifies_before_compatibility(self):
        name = "IK-Q3S_sysupgrade_3.7.5_Build202308250956.bin"
        sha = hashlib.sha256(b"data").hexdigest()
        old = {"id": "old-id", "filename": name, "source": {"url": "https://official.example/fw.bin"},
               "archived_at": "2023-08-25T00:00:00Z", "assets": [{"name": name, "size": 4, "sha256": sha}], "sha256": sha, "size": 4}
        item = {"legacy_tag": "hardware-IK-Q3S", "legacy_release_id": 7, "records": [old], "model": "IK-Q3S"}
        client = Mock(repo="o/r")
        client.release.return_value = {"id": 7}
        client.api.side_effect = [{"id": 8, "tag_name": m.group_for(name), "assets": []}, None, None]
        client.read_asset.return_value = {"files": []}
        saved = {}
        def copied(client, legacy, release, part, assets, work):
            assets[part["name"]] = {"name": part["name"], "size": part["size"], "digest": "sha256:" + part["sha256"]}
        def metadata(client, release, path, assets, **kwargs):
            saved[path.name] = path.read_text()
        def marker(tag, path, **kwargs):
            saved[path.name] = path.read_text()
        client.upload.side_effect = marker
        with tempfile.TemporaryDirectory() as temp, patch.object(m, "copy_hardware_part", side_effect=copied), \
                patch.object(m, "upload_split_asset", side_effect=metadata):
            result = m.migrate_legacy_hardware(client, item, Path(temp))
        record = json.loads(saved["sources.json"])["files"][0]
        self.assertEqual(record["source"], old["source"])
        self.assertEqual(record["sha256"], old["sha256"])
        self.assertEqual(record["id"], m.digest(m.group_for(name) + "/" + name))
        self.assertEqual(json.loads(saved[m.SPLIT_META])["targets"], [m.group_for(name)])
        self.assertEqual(result["files"], 1)
        self.assertEqual(client.api.call_args.args[0], "repos/o/r/releases/7")

    def test_finish_refuses_missing_migration_shards(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(m, "split_inventory", return_value={
                "files": [{"legacy_tag": "old"}]}), patch.object(m, "GitHub") as client:
            with self.assertRaisesRegex(m.PublicationError, "分片报告不完整"):
                m.finish_hardware_split(SimpleNamespace(report_dir=temp))
            client.assert_not_called()

    def test_global_audit_rejects_any_wrong_group_not_only_latest_enterprise(self):
        releases = self.complete_order_fixture()
        releases[4], releases[6] = releases[6], releases[4]
        report = m.ordering_audit("o/r", releases, m.release_index_body("o/r", releases), m.category_body("o/r", releases))
        self.assertIn("release_order", {issue["kind"] for issue in report["issues"]})

    def test_global_audit_detects_missing_file_wrong_time_and_stale_indexes(self):
        releases = self.complete_order_fixture()
        names = ["IK-M360X_sysupgrade_3.7.26_Build202609111742.bin", "IK-M360X_sysupgrade_4.0.222_beta_Build202605211754.bin"]
        release = {"tag_name": "hardware-M360X", "assets": [{"name": name} for name in names]}
        release["body"] = m.release_body("o/r", release["tag_name"], m.presentation_records(release), [])
        releases.append(release)
        lines = release["body"].splitlines()
        release["body"] = "\n".join(line for line in lines if not line.startswith("| 2026-05-21"))
        release["body"] = release["body"].replace("| 2026-09-11 17:42 |", "| 2099-01-01 00:00 |")
        report = m.ordering_audit("o/r", releases, "old index", "old categories")
        kinds = {issue["kind"] for issue in report["issues"]}
        self.assertTrue({"file_table_coverage", "file_build_time", "index_order_or_coverage", "category_order_or_coverage"} <= kinds)

    def test_undated_hardware_is_sorted_by_numeric_version_without_fake_dates(self):
        releases = self.complete_order_fixture()
        names = ["IK-H11_sysupgrade_1.9.0.bin", "IK-H11_sysupgrade_1.10.0.bin"]
        release = {"tag_name": "hardware-H11", "assets": [{"name": name} for name in names]}
        release["body"] = m.release_body("o/r", release["tag_name"], m.presentation_records(release), [])
        releases.append(release)
        self.assertLess(release["body"].index("1.10.0"), release["body"].index("1.9.0"))
        self.assertNotIn("1971", release["body"])
        release["body"] = release["body"].replace("1.10.0", "SWAP").replace("1.9.0", "1.10.0").replace("SWAP", "1.9.0")
        report = m.ordering_audit("o/r", releases, m.release_index_body("o/r", releases), m.category_body("o/r", releases))
        self.assertIn("file_table_order", {issue["kind"] for issue in report["issues"]})

    def test_legacy_firmware_inside_resource_tag_is_not_hidden_with_documents(self):
        assets = [{"name": "iKuai-GX2600_x64_3.5.4_Enterprise_Build202105071917.bin"}]
        tag = "resources-legacy-0"
        self.assertEqual(m.release_kind(tag, assets), "hardware")
        self.assertEqual(m.release_sort_date(tag, assets), "2021-05-07T11:17:00+00:00")
        self.assertIn("GX2600", m.release_title(tag, assets))
        self.assertEqual(m.release_kind(tag, [*assets, {"name": "Manual.pdf"}]), "resources")

    def test_same_original_document_names_are_not_merged_as_one_file(self):
        release = {"assets": [{"name": "Manual--aaa.pdf"}, {"name": "Manual--bbb.pdf"}], "body":
                   "| 说明书.pdf | [Manual--aaa.pdf](https://github.com/o/r/a) |\n"
                   "| 说明书.pdf | [Manual--bbb.pdf](https://github.com/o/r/b) |"}
        self.assertEqual(len(m.presentation_records(release)), 2)

    def test_snapshot_fetches_all_assets_for_large_document_groups_too(self):
        assets = [{"name": f"doc-{i}.pdf"} for i in range(45)]
        client = Mock(repo="o/r")
        client.api.return_value = [{"tag_name": "resources-tools-0", "assets": assets[:30]}]
        client.assets.return_value = {a["name"]: a for a in assets}
        self.assertEqual(len(m.release_snapshot(client)[0]["assets"]), 45)
        client.assets.assert_called_once()

    def test_unknown_document_categories_are_not_omitted_from_directory(self):
        release = {"tag_name": "resources-unknown-0", "name": "Uncategorized manual", "assets": [{"name": "manual.pdf"}]}
        body = m.category_body("o/r", [release])
        self.assertIn("https://github.com/o/r/releases/tag/resources-unknown-0", body)
        self.assertIn("其他资料", body)

    def test_automatic_maintenance_cannot_skip_global_audit(self):
        manager = Mock()
        with patch.object(m, "compact_history", manager.compact), patch.object(m, "refresh_categories", manager.indexes), \
                patch.object(m, "audit_release_order", manager.audit), patch.object(m, "prune_runs", manager.prune):
            m.maintain(SimpleNamespace(repo="o/r"))
        self.assertEqual([call[0] for call in manager.mock_calls], ["compact", "indexes", "audit", "prune"])
        backfill = (m.ROOT / ".github/workflows/backfill.yml").read_text()
        self.assertIn("scripts/mirror.py refresh-categories", backfill)
        self.assertIn("scripts/mirror.py audit-order", backfill)

    def test_failed_global_audit_is_published_but_never_returns_success(self):
        releases = self.complete_order_fixture()
        bad_index = "stale index"
        index = next(r for r in releases if r["tag_name"] == m.INDEX_TAG)
        index["assets"] = [{"name": "INDEX.md", "url": "fake-url", "size": len(bad_index),
                            "digest": "sha256:" + hashlib.sha256(bad_index.encode()).hexdigest()}]
        category = next(r for r in releases if r["tag_name"] == m.CATEGORY_TAG)
        category["body"] = m.category_body("o/r", releases)
        uploaded = {}
        client = Mock(repo="o/r")
        client.upload.side_effect = lambda tag, path, **kw: uploaded.update({path.name: json.loads(path.read_text())})
        with tempfile.TemporaryDirectory() as temp, patch.object(m, "ROOT", Path(temp)), \
                patch.object(m, "GitHub", return_value=client), patch.object(m, "release_snapshot", return_value=releases), \
                patch.object(m, "gh", return_value=SimpleNamespace(stdout=bad_index)):
            with self.assertRaisesRegex(m.PublicationError, "全库排序校验失败"):
                m.audit_release_order(SimpleNamespace(repo="o/r"))
        self.assertEqual(uploaded["ordering-audit.json"]["status"], "error")

    def test_restore_inventory_reloads_assets_after_publish_race(self):
        client = Mock(repo="owner/repo")
        client.assets.side_effect = [{}, {"catalog.json": {"name": "catalog.json", "url": "new-url"}}]
        args = SimpleNamespace(repo="owner/repo", previous=".work/previous.json")
        with patch.object(m, "GitHub", return_value=client), patch.object(m, "transfer_download") as download, \
                patch.object(m.time, "sleep") as sleep:
            self.assertFalse(m.restore_inventory(args))
        self.assertEqual(client.assets.call_count, 2)
        self.assertEqual(download.call_args.args[1]["url"], "new-url")
        sleep.assert_called_once_with(5)

    def test_restore_inventory_never_silently_discards_existing_history(self):
        client = Mock(repo="owner/repo")
        client.assets.return_value = {}
        with patch.object(m, "GitHub", return_value=client), patch.object(m.time, "sleep"):
            with self.assertRaisesRegex(m.PublicationError, "丢失累积来源"):
                m.restore_inventory(SimpleNamespace(repo="owner/repo", previous="unused"))
        self.assertEqual(client.assets.call_count, 4)
        client.release.return_value = None
        with patch.object(m, "GitHub", return_value=client):
            self.assertFalse(m.restore_inventory(SimpleNamespace(repo="owner/repo", previous="unused")))

    def test_restore_inventory_retries_corrupt_or_replaced_asset(self):
        client = Mock(repo="owner/repo")
        client.assets.return_value = {"catalog.json": {"name": "catalog.json"}}
        with patch.object(m, "GitHub", return_value=client), patch.object(m.time, "sleep"), \
                patch.object(m, "transfer_download", side_effect=[m.PublicationError("bad digest"), None]) as download:
            self.assertFalse(m.restore_inventory(SimpleNamespace(repo="owner/repo", previous="unused")))
        self.assertEqual(download.call_count, 2)

    def test_transfer_tag_requires_run_and_attempt(self):
        with patch.dict(m.os.environ, {"GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2"}):
            self.assertEqual(m.transfer_tag(), "mirror-run-123-2")
        with patch.dict(m.os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                m.transfer_tag()

    def test_transfer_rejects_wrong_run_or_published_release(self):
        for release in ({"draft": True, "tag_name": "mirror-run-999-1"},
                        {"draft": False, "tag_name": "mirror-run-123-2"}, None):
            with self.subTest(release=release), patch.dict(m.os.environ, {
                    "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2", "TRANSFER_RELEASE_ID": "5"}):
                client = Mock(repo="owner/repo")
                client.api.return_value = release
                with self.assertRaises(ValueError):
                    m.transfer_release(client)

    def test_transfer_download_verifies_utf8_bytes_and_json(self):
        payload = '{"files": ["中文.bin"]}\n'.encode()
        asset = {"url": "asset-url", "name": "catalog.json", "state": "uploaded",
                 "size": len(payload), "digest": "sha256:" + hashlib.sha256(payload).hexdigest()}
        with tempfile.TemporaryDirectory() as temp, patch.object(m, "gh", return_value=SimpleNamespace(stdout=payload.decode())):
            target = Path(temp) / "subdir/catalog.json"
            m.transfer_download(Mock(), asset, target)
            self.assertEqual(target.read_bytes(), payload)
            asset["digest"] = "sha256:" + "0" * 64
            bad = Path(temp) / "bad.json"
            with self.assertRaises(m.PublicationError):
                m.transfer_download(Mock(), asset, bad)
            self.assertFalse(bad.exists())

    def test_transfer_upload_checks_remote_digest_and_retries_pending_state(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "catalog.json"
            path.write_text('{"files": []}\n')
            client = Mock()
            client.assets.side_effect = [{}, {path.name: {
                "state": "uploaded", "size": path.stat().st_size, "digest": "sha256:" + m.file_sha(path)}}]
            with patch.object(m.time, "sleep") as sleep:
                m.transfer_upload(client, {"tag_name": "mirror-run-123-1"}, path)
            client.upload.assert_called_once_with("mirror-run-123-1", path, clobber=True)
            self.assertEqual(client.assets.call_count, 2)
            sleep.assert_called_once_with(2)

    def test_transfer_upload_fails_when_remote_digest_never_matches(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "catalog.json"
            path.write_text("{}")
            client = Mock()
            client.assets.return_value = {}
            with patch.object(m.time, "sleep"), self.assertRaises(m.PublicationError):
                m.transfer_upload(client, {"tag_name": "mirror-run-123-1"}, path)
            self.assertEqual(client.assets.call_count, 3)

    def test_stage_inventory_exposes_draft_id_and_does_not_publish_firmware(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(m.os.environ, {
                "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_OUTPUT": str(Path(temp) / "outputs")}), \
                patch.object(m, "prune_transfer_drafts"), patch.object(m, "transfer_upload") as upload:
            path = Path(temp) / "catalog.json"
            m.save(path, {"files": [{"filename": "public.bin"}]})
            client = Mock(repo="owner/repo")
            client.api.return_value = {"id": 5, "tag_name": "mirror-run-123-2"}
            with patch.object(m, "GitHub", return_value=client):
                self.assertFalse(m.stage_inventory(SimpleNamespace(repo="owner/repo", catalog=str(path))))
            self.assertTrue(client.api.call_args.args[1]["draft"])
            self.assertEqual(Path(m.os.environ["GITHUB_OUTPUT"]).read_text(), "release_id=5\n")
            upload.assert_called_once_with(client, client.api.return_value, path)

    def test_empty_inventory_does_not_create_draft(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(m, "GitHub") as client:
            path = Path(temp) / "catalog.json"
            m.save(path, {"files": []})
            with self.assertRaises(ValueError):
                m.stage_inventory(SimpleNamespace(repo="owner/repo", catalog=str(path)))
            client.assert_not_called()

    def test_fetch_reports_never_uses_another_runs_missing_shard(self):
        client = Mock(repo="owner/repo")
        client.assets.return_value = {"shard-0.json": {"name": "shard-0.json"},
                                      "shard-999.json": {"name": "shard-999.json"}}
        with patch.object(m, "GitHub", return_value=client), patch.object(m, "transfer_release"), \
                patch.object(m, "transfer_download") as download:
            self.assertFalse(m.fetch_reports(SimpleNamespace(repo="owner/repo", shards=2, report_dir="reports")))
            self.assertEqual(download.call_count, 1)
            self.assertEqual(download.call_args.args[2], Path("reports/shard-0.json"))

    def test_transfer_cleanup_deletes_only_validated_current_draft(self):
        client = Mock(repo="owner/repo")
        with patch.object(m, "GitHub", return_value=client), \
                patch.object(m, "transfer_release", return_value={"id": 5}):
            self.assertFalse(m.cleanup_transfer(SimpleNamespace(repo="owner/repo")))
        client.api.assert_called_once_with("repos/owner/repo/releases/5", method="DELETE")

    def test_stale_transfer_cleanup_preserves_other_drafts_and_recent_runs(self):
        client = Mock(repo="owner/repo")
        client.api.side_effect = [[
            {"id": 1, "draft": True, "tag_name": "mirror-run-1-1", "body": json.dumps({"schema": "ikuai-workflow-transfer/v1", "created_at": "2020-01-01T00:00:00+00:00"})},
            {"id": 2, "draft": False, "tag_name": "mirror-run-2-1"},
            {"id": 3, "draft": True, "tag_name": "manual-draft"},
            {"id": 4, "draft": True, "tag_name": "mirror-run-4-1", "body": json.dumps({"schema": "ikuai-workflow-transfer/v1", "created_at": m.now()})},
            {"id": 5, "draft": True, "tag_name": "mirror-run-5-1", "body": "unrelated"},
        ], None]
        m.prune_transfer_drafts(client)
        self.assertEqual(client.api.call_count, 2)
        self.assertEqual(client.api.call_args.args[0], "repos/owner/repo/releases/1")
        self.assertEqual(client.api.call_args.kwargs["method"], "DELETE")

    def test_draft_transfer_is_not_retargeted_as_a_public_tag(self):
        client = Mock(repo="owner/repo")
        client.api.return_value = [{"draft": True, "tag_name": "mirror-run-1-1"}]
        with patch.object(m, "dated_tag") as tag:
            m.retarget_release_tags(client, "root")
        tag.assert_not_called()

    def test_workflow_uses_verified_release_metadata_not_artifact_service(self):
        workflow = (m.ROOT / ".github/workflows/sync.yml").read_text()
        self.assertNotIn("actions/upload-artifact@", workflow)
        self.assertNotIn("actions/download-artifact@", workflow)
        for command in ("stage-inventory", "fetch-inventory", "stage-report", "fetch-reports", "cleanup-transfer"):
            self.assertIn("scripts/mirror.py " + command, workflow)

    def test_new_releases_target_current_main_after_history_compaction(self):
        client = m.GitHub("owner/repo")
        with patch.object(client, "release", return_value=None), \
                patch.object(client, "api", side_effect=[{"object": {"sha": "current-main"}}, {"id": 1}]) as api, \
                patch.object(m, "dated_tag") as tag, \
                patch.dict(m.os.environ, {"GITHUB_SHA": "obsolete-workflow-commit"}):
            client.ensure_release("enterprise-3.7.26-Build1")
        self.assertEqual(api.call_args.args[1]["target_commitish"], "main")
        self.assertEqual(tag.call_args.args[2], "current-main")

    def test_build_dates_use_china_timezone_and_undated_files_sort_last(self):
        self.assertEqual(m.build_date("enterprise-3.7.26-Enterprise-Build202609111742"), "2026-09-11T09:42:00+00:00")
        self.assertIsNone(m.build_date("bad-Build202699991742"))
        self.assertEqual(m.release_sort_date("hardware-M100", [{"name": "fw_Build202609111742.bin"}]), "2026-09-11T09:42:00+00:00")
        self.assertEqual(m.release_sort_date("resources-router-0"), "1970-01-04T00:00:00+00:00")
        self.assertLess(m.release_sort_date(m.INDEX_TAG), m.release_sort_date("resources-router-0"))

    def test_all_firmware_precedes_resources_even_without_build_dates(self):
        for tag in ("hardware-IK-WAQ", "free-tsos", "enterprise-unknown", "oem-unknown"):
            self.assertGreater(m.release_sort_date(tag), m.release_sort_date("resources-tools-0"))
        self.assertEqual(m.release_sort_date("resources-tutorial-0", [{"name": "tutorial_Build202611130000.pdf"}]),
                         "1970-01-04T00:00:00+00:00")
        self.assertLess(m.release_sort_date(m.CATEGORY_TAG), m.release_sort_date("resources-tools-0"))

    def test_undated_releases_never_precede_even_the_oldest_dated_firmware(self):
        undated = {"tag_name": "hardware-IK-WIPQ6018_X6_5G-99.0.0", "created_at": "2099-01-01T00:00:00Z",
                   "assets": [{"name": "IK-WIPQ6018_X6_5G_sysupgrade_99.0.0.bin"}]}
        dated = {"tag_name": "free-3.3.4-Build202003231122", "created_at": "1970-01-01T00:00:00Z",
                 "assets": [{"name": "iKuai8_x32_3.3.4_Build202003231122.bin"}]}
        resources = {"tag_name": "resources-tools-0", "assets": []}
        releases = [undated, resources, dated]
        self.assertEqual(sorted(releases, key=lambda r: m.release_order_key(r["tag_name"], r["assets"]), reverse=True),
                         [dated, undated, resources])
        dates = m.release_tag_dates(releases)
        self.assertGreater(dates[dated["tag_name"]], dates[undated["tag_name"]])

    def test_git_sort_refreshes_release_date_cache_once_and_combines_body_update(self):
        tag = "hardware-IK-WIPQ6018_X6_5G-1.7.6"
        release = {"id": 1, "tag_name": tag, "created_at": "2026-11-13T11:58:44Z", "body": "old body",
                   "assets": [{"name": "IK-WIPQ6018_X6_5G_sysupgrade_1.7.6.bin"}]}
        client = Mock(repo="o/r")
        client.api.side_effect = [[release], {"object": {"sha": "root"}}, {}, {}]
        with patch.dict(m.os.environ, {"GH_TOKEN": "test-token"}), patch.object(m, "push_dated_tags") as git:
            m.retarget_release_tags(client, "root", dates_only=True, refresh_bodies=True)
        git.assert_called_once_with(client, "root", {tag: "1971-01-01T00:00:00+00:00"})
        changes = [call for call in client.api.call_args_list if len(call.args) == 3 and call.args[2] == "PATCH"
                   and "tag_name" in call.args[1]]
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].args[1]["tag_name"], tag)
        self.assertIn("body", changes[0].args[1])
        self.assertIn("name", changes[0].args[1])
        client.upload.assert_not_called()

    def test_up_to_date_release_date_binding_is_not_rewritten(self):
        tag = "hardware-IK-WIPQ6018_X6_5G-1.7.6"
        release = {"id": 1, "tag_name": tag, "created_at": "1971-01-01T00:00:00Z",
                   "assets": [{"name": "IK-WIPQ6018_X6_5G_sysupgrade_1.7.6.bin"}]}
        client = Mock(repo="o/r")
        client.api.side_effect = [[release], {"object": {"sha": "root"}}, {}]
        with patch.dict(m.os.environ, {"GH_TOKEN": "test-token"}), patch.object(m, "push_dated_tags") as git:
            m.retarget_release_tags(client, "root", dates_only=True)
        git.assert_called_once_with(client, "root", {})
        self.assertFalse(any(len(call.args) > 1 and "tag_name" in call.args[1] for call in client.api.call_args_list))

    def test_release_order_uses_build_time_then_numeric_version(self):
        tags = ["free-3.7.9-Build202609111742", "free-3.7.26-Build202609111742",
                "free-4.0.313-Build202609281356", "free-4.0.315-beta-Build202610291123"]
        self.assertEqual(sorted(tags, key=m.release_order_key, reverse=True), list(reversed(tags)))

    def test_hardware_files_use_build_time_not_version_or_filename_order(self):
        names = ["IK-M360X_sysupgrade_4.0.222_beta_Build202605211754.bin",
                 "IK-M360X_sysupgrade_3.7.26_Build202609111742.bin",
                 "IK-M360X_sysupgrade_9.0.0.bin"]
        records = {name: {"id": name, "filename": name, "assets": [{"name": name}]} for name in names}
        body = m.release_body("owner/repo", "hardware-M360X", records, [])
        self.assertIn("最新固件 Build：**2026-09-11 17:42**", body)
        self.assertLess(body.index(names[1]), body.index(names[0]))
        self.assertLess(body.index(names[0]), body.index(names[2]))
        self.assertIn("| 2026-05-21 17:54 | " + names[0], body)
        self.assertIn("2026-09-11 17:42", m.release_title("hardware-M360X", [{"name": n} for n in names]))

    def test_presentation_migration_preserves_original_names_and_split_files(self):
        body = "| 原名_Build202609111742.bin | [English.bin.part-001](https://github.com/o/r/releases/download/t/a) |\n"
        body += "| 原名_Build202609111742.bin | [English.bin.part-002](https://github.com/o/r/releases/download/t/b) |"
        release = {"body": body, "assets": [{"name": name} for name in
                   ("English.bin.part-001", "English.bin.part-002", "checksums.sha256", "sources.json", "failures.json")]}
        records = m.presentation_records(release)
        self.assertEqual(len(records), 1)
        self.assertEqual(next(iter(records.values()))["filename"], "原名_Build202609111742.bin")
        release["body"] = m.release_body("o/r", "hardware-test", records, [])
        self.assertEqual(m.presentation_records(release), records)
        self.assertIn("/releases/download/hardware-test/English.bin.part-001", release["body"])

    def test_github_sort_days_resolve_same_day_minutes_without_changing_names(self):
        releases = [{"tag_name": "hardware-M360X", "assets": [{"name": "hw_Build202609111742.bin"}]},
                    {"tag_name": "free-3.7.26-Build202609111743"},
                    {"tag_name": "enterprise-3.7.26-Build202609111742"},
                    {"tag_name": "free-4.0.313-Build202609281457"},
                    {"tag_name": "resources-tools-0"}, {"tag_name": m.INDEX_TAG}]
        dates = m.release_tag_dates(releases)
        self.assertGreater(dates[releases[2]["tag_name"]][:10], dates[releases[0]["tag_name"]][:10])
        self.assertGreater(dates[releases[1]["tag_name"]][:10], dates[releases[2]["tag_name"]][:10])
        self.assertGreater(dates[releases[1]["tag_name"]][:10], dates[releases[0]["tag_name"]][:10])
        self.assertEqual(dates[releases[3]["tag_name"]], "2026-09-28T06:57:00+00:00")
        self.assertEqual(dates, m.release_tag_dates(list(reversed(releases))))
        self.assertEqual(m.release_tag_dates([]), {})

    def test_enterprise_same_build_precedes_all_hardware_without_overriding_newer_free(self):
        hardware = [{"tag_name": "hardware-" + model, "assets": [{"name": "hw_Build202609111742.bin"}]}
                    for model in ("M360X", "Y6000G-PRO", "A100-P")]
        enterprise = {"tag_name": "enterprise-3.7.26-Enterprise-Build202609111742"}
        free = {"tag_name": "free-3.7.26-Build202609111743"}
        releases = [*hardware, enterprise, free]
        dates = m.release_tag_dates(releases)
        self.assertEqual(sorted(releases, key=lambda r: m.release_order_key(r["tag_name"], r.get("assets", [])),
                                reverse=True)[:2], [free, enterprise])
        self.assertEqual(sorted(releases, key=lambda r: (dates[r["tag_name"]][:10], r["tag_name"]),
                                reverse=True)[:2], [free, enterprise])
        self.assertEqual(len({dates[r["tag_name"]] for r in hardware}), 1)

    def test_hardware_directory_ignores_upload_or_synthetic_tag_dates(self):
        releases = [{"tag_name": "hardware-older", "name": "older", "created_at": "2099-01-01",
                     "assets": [{"name": "old_Build202605211754.bin"}]},
                    {"tag_name": "hardware-newer", "name": "newer", "created_at": "1971-01-01",
                     "assets": [{"name": "new_Build202609111742.bin"}]}]
        body = m.category_body("owner/repo", releases)
        self.assertLess(body.index("[newer]"), body.index("[older]"))

    def test_quick_order_changes_only_dates_and_presentation_never_assets(self):
        client = Mock(repo="owner/repo")
        release = {"id": 1, "tag_name": "hardware-M360X", "created_at": "2026-09-11T09:42:00Z",
                   "assets": [{"name": "hw_Build202609111742.bin"}], "body": "old body"}
        client.api.side_effect = [[release], {"object": {"sha": "root"}}, {}, {}]
        with patch.object(m, "dated_tag") as tag:
            m.retarget_release_tags(client, "root", dates_only=True, refresh_bodies=True)
        tag.assert_not_called()
        client.upload.assert_not_called()
        client.assets.assert_not_called()
        body_update = client.api.call_args_list[2].args[1]
        self.assertIn("2026-09-11 17:42", body_update["body"])
        self.assertIn("2026-09-11 17:42", body_update["name"])

    def test_latest_label_is_for_firmware_not_the_recently_updated_index(self):
        client = Mock(repo="owner/repo")
        releases = [{"id": 1, "tag_name": m.INDEX_TAG},
                    {"id": 2, "tag_name": "free-4.0.313-Build202609281356"},
                    {"id": 3, "tag_name": "free-4.0.315-beta-Build202610291123", "prerelease": True},
                    {"id": 4, "tag_name": "resources-tools-0"}]
        client.api.side_effect = [releases, {"object": {"sha": "root"}}, {}]
        with patch.object(m, "dated_tag") as tag:
            m.retarget_release_tags(client, "root")
        self.assertEqual(tag.call_count, 4)
        self.assertEqual(client.api.call_args.args, ("repos/owner/repo/releases/2", {"make_latest": "true"}, "PATCH"))

    def test_publish_preserves_coverage_warning_and_does_not_pin_index(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            catalog = directory / "catalog.json"
            m.save(catalog, {"discovered_at": m.now(), "files": [{"tag": "free-test", "filename": "fw.bin"}],
                             "discovery_errors": [{"error": "HTTP Error 404: Not Found"}]})
            m.save(directory / "reports/shard-0.json", [{"tag": "free-test", "archived": 1, "bytes": 10,
                                                       "failures": [{"error": "HTTP Error 404: Not Found"}]}])
            client = Mock(repo="owner/repo")
            client.ensure_release.return_value = {"id": 1}
            uploaded = {}
            client.upload.side_effect = lambda tag, path, **kw: uploaded.update({path.name: path.read_text()})
            args = SimpleNamespace(repo="owner/repo", catalog=str(catalog), report_dir=str(directory / "reports"))
            with patch.object(m, "ROOT", directory), patch.object(m, "GitHub", return_value=client), \
                    patch.object(m, "refresh_categories"), patch.dict(m.os.environ, {"GITHUB_STEP_SUMMARY": str(directory / "summary")}):
                (directory / ".work").mkdir()
                self.assertFalse(m.publish(args))
            self.assertEqual(json.loads(uploaded["status.json"])["sync_status"], "warning")
            self.assertIn("覆盖警告", (directory / "summary").read_text())
            self.assertEqual(client.api.call_args.args[1]["make_latest"], "false")

    def test_coverage_warning_does_not_claim_every_file_is_archived(self):
        catalog = {"discovered_at": m.now(), "files": [{"tag": "free-test"}],
                   "discovery_errors": [{"error": "HTTP Error 404: Not Found"}]}
        reports = [{"tag": "free-test", "archived": 0, "bytes": 0, "failures": [
            {"known_source": True, "error": json.dumps([{"error": "固件签名接口: 400 固件不存在: firmware/a.bin"}])}]}]
        totals = m.coverage_totals(catalog, reports)
        self.assertEqual(totals["sync_status"], "warning")
        self.assertEqual(totals["archived_files"], 0)
        self.assertEqual(totals["unavailable_known_files"], 1)
        self.assertEqual(totals["fatal_file_errors"], 0)

    def test_coverage_keeps_integrity_conflict_and_unknown_errors_fatal(self):
        catalog = {"discovered_at": m.now(), "files": [{"tag": "free-test"}], "discovery_errors": []}
        for error in ("Git blob SHA-1 校验失败", "同名 Release 文件内容冲突，保留原包: a.bin",
                      "源文件大小不一致: 1/2", "unexpected exception"):
            with self.subTest(error=error):
                reports = [{"tag": "free-test", "archived": 0, "bytes": 0, "failures": [{"error": error}]}]
                self.assertEqual(m.coverage_totals(catalog, reports)["sync_status"], "error")
        catalog["discovery_errors"] = [{"error": "bad config", "kind": "error"}]
        self.assertEqual(m.coverage_totals(catalog, reports)["fatal_discovery_errors"], 1)

    def test_missing_duplicate_or_unexpected_group_reports_are_fatal(self):
        catalog = {"discovered_at": m.now(), "files": [{"tag": "free-test"}], "discovery_errors": []}
        report = {"tag": "free-test", "archived": 1, "bytes": 1, "failures": []}
        self.assertEqual(m.coverage_totals(catalog, [report])["sync_status"], "success")
        for reports in ([], [report, report], [report, {**report, "tag": "free-other"}]):
            self.assertEqual(m.coverage_totals(catalog, reports)["sync_status"], "error")

    def test_network_availability_does_not_swallow_auth_or_local_io_errors(self):
        self.assertEqual(m.failure_kind(TimeoutError("timed out")), "unavailable")
        self.assertEqual(m.failure_kind(urllib.error.HTTPError("url", 404, "Not Found", {}, None)), "unavailable")
        self.assertEqual(m.failure_kind(urllib.error.HTTPError("url", 403, "Forbidden", {}, None)), "error")
        self.assertEqual(m.failure_kind(OSError("disk full")), "error")

    def test_download_exhaustion_preserves_warning_vs_integrity_error(self):
        entry = m.merge_candidates([m.candidate("test.bin", "https://example.com/a", size=4)])[0]
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(m, "request", return_value=Response(b"<html>404</html>", "text/html")):
                with self.assertRaises(m.SourceUnavailable):
                    m.download(entry, Path(temp))
            with patch.object(m, "request", return_value=Response(b"bad")):
                with self.assertRaises(ValueError) as error:
                    m.download(entry, Path(temp))
                self.assertNotIsInstance(error.exception, m.SourceUnavailable)
            self.assertEqual(list(Path(temp).iterdir()), [])

    def test_annotation_is_reused_when_root_and_build_date_match(self):
        client = Mock(repo="owner/repo")
        client.api.side_effect = [
            {"object": {"type": "tag", "sha": "annotation"}},
            {"object": {"sha": "root"}, "tagger": {"date": "2026-09-11T09:42:00Z"}},
        ]
        m.dated_tag(client, "test", "root", "2026-09-11T09:42:00+00:00")
        self.assertEqual(client.api.call_count, 2)

    def test_annotation_retargets_root_without_losing_build_date(self):
        client = Mock(repo="owner/repo")
        client.api.side_effect = [
            {"object": {"type": "tag", "sha": "old-annotation"}},
            {"object": {"sha": "old-root"}, "tagger": {"date": "2026-09-11T09:42:00Z"}},
            {"sha": "new-annotation"}, {},
        ]
        m.dated_tag(client, "test", "new-root", "2026-09-11T09:42:00+00:00")
        payload = client.api.call_args_list[2].args[1]
        self.assertEqual(payload["object"], "new-root")
        self.assertEqual(payload["tagger"]["date"], "2026-09-11T09:42:00+00:00")
        self.assertEqual(client.api.call_args.args[1], {"sha": "new-annotation", "force": True})

    def test_github_transport_errors_have_bounded_retries(self):
        failure = SimpleNamespace(returncode=1, stderr="unexpected EOF")
        success = SimpleNamespace(returncode=0, stderr="")
        with patch.object(m.subprocess, "run", side_effect=[failure, success]) as run, patch.object(m.time, "sleep"):
            self.assertIs(m.run_gh(["api", "example"]), success)
            self.assertEqual(run.call_count, 2)
        with patch.object(m.subprocess, "run", return_value=failure) as run, patch.object(m.time, "sleep"):
            self.assertIs(m.run_gh(["api", "example"]), failure)
            self.assertEqual(run.call_count, 3)

    def test_shared_api_limit_waits_until_server_reset_without_polling(self):
        failure = SimpleNamespace(returncode=1, stderr="gh: API rate limit exceeded (HTTP 403)")
        quota = SimpleNamespace(returncode=0, stdout=json.dumps({"resources": {"core": {"remaining": 0, "reset": 160}}}))
        success = SimpleNamespace(returncode=0, stderr="")
        with patch.object(m.subprocess, "run", side_effect=[failure, quota, success]) as run, \
                patch.object(m.time, "time", return_value=100), patch.object(m.time, "sleep") as sleep:
            self.assertIs(m.run_gh(["api", "example"]), success)
        sleep.assert_called_once_with(65)
        self.assertEqual(run.call_args_list[1].args[0], ["gh", "api", "rate_limit"])

    def test_public_metadata_is_verified_without_authenticated_api_request(self):
        payload = b'{"files": []}'
        asset = {"size": len(payload), "digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
                 "browser_download_url": "https://github.com/o/r/releases/download/tag/sources.json"}
        with patch.object(m, "request", return_value=Response(payload)), patch.object(m, "gh") as gh:
            self.assertEqual(m.GitHub("o/r").read_asset({"sources.json": asset}, "sources.json", {}), {"files": []})
        gh.assert_not_called()

    def test_corrupt_public_metadata_never_falls_back_or_silently_passes(self):
        asset = {"size": 2, "digest": "sha256:" + "a" * 64,
                 "browser_download_url": "https://github.com/o/r/releases/download/tag/sources.json"}
        with patch.object(m, "request", return_value=Response(b"{}")), patch.object(m, "gh") as gh:
            with self.assertRaisesRegex(m.PublicationError, "SHA256"):
                m.GitHub("o/r").read_asset({"sources.json": asset}, "sources.json", {})
        gh.assert_not_called()

    def test_incremental_sync_reuses_snapshot_and_checks_every_asset_digest(self):
        entry = m.merge_candidates([m.candidate("iKuai8_x64_3.7.26_Build202609111743.bin", "https://example.com/fw")])[0]
        part = {"name": entry["asset_name"], "size": 4, "sha256": "a" * 64}
        record = {"id": entry["id"], "filename": entry["filename"], "assets": [part], "size": 4}
        release = {"id": 1, "assets": [{"name": part["name"], "size": 4, "digest": "sha256:" + part["sha256"]}],
                   "name": m.release_title(entry["tag"], [{"name": entry["filename"]}]), "prerelease": False}
        release["body"] = m.release_body("o/r", entry["tag"], {record["id"]: record}, [])
        client = Mock(repo="o/r")
        client.read_asset.side_effect = [{"files": [record]}, []]
        with tempfile.TemporaryDirectory() as directory, patch.object(m, "download") as download:
            result = m.sync_group(client, entry["tag"], [entry], Path(directory), snapshot={entry["tag"]: release})
        self.assertEqual(result["unchanged"], 1)
        client.release.assert_not_called()
        client.assets.assert_not_called()
        client.upload.assert_not_called()
        client.api.assert_not_called()
        download.assert_not_called()

    def test_identical_availability_failures_are_not_republished(self):
        entries = m.merge_candidates([m.candidate(f"iKuai8_{arch}_3.7.26_Build202609111743.bin", f"https://example.com/{arch}")
                                      for arch in ("x32", "x64")])
        present, missing = entries
        part = {"name": present["asset_name"], "size": 4, "sha256": "a" * 64}
        record = {"id": present["id"], "filename": present["filename"], "assets": [part], "size": 4}
        failures = [{"id": missing["id"], "filename": missing["filename"], "known_source": True,
                     "error": "not available", "kind": "unavailable"}]
        release = {"id": 1, "assets": [{"name": part["name"], "size": 4, "digest": "sha256:" + part["sha256"]}],
                   "name": m.release_title(present["tag"], [{"name": present["filename"]}]), "prerelease": False}
        release["body"] = m.release_body("o/r", present["tag"], {record["id"]: record}, failures)
        client = Mock(repo="o/r")
        client.read_asset.side_effect = [{"files": [record]}, failures]
        with tempfile.TemporaryDirectory() as directory, patch.object(m, "checkpoint") as checkpoint, \
                patch.object(m, "download", side_effect=m.SourceUnavailable("not available")):
            result = m.sync_group(client, present["tag"], entries, Path(directory), snapshot={present["tag"]: release})
        self.assertEqual(result["failures"], failures)
        checkpoint.assert_not_called()
        client.api.assert_not_called()

    def test_many_sorting_tags_use_one_atomic_git_push_not_per_tag_api(self):
        client = Mock(repo="o/r")
        client.api.return_value = {"object": {"sha": "root"}}
        dates = {"hardware-one": "2026-09-11T09:42:00+00:00", "hardware-two": "2024-03-04T06:02:00+00:00"}
        with patch.object(m, "git_remote_env", return_value={}), \
                patch.object(m, "git_run", side_effect=["", "sha-one", "sha-two", ""]) as git:
            m.push_dated_tags(client, "root", dates)
        self.assertEqual(client.api.call_count, 1)
        command = git.call_args.args[0]
        self.assertEqual(command[:4], ["push", "--atomic", "--force", "https://github.com/o/r.git"])
        self.assertEqual(command[4:], ["sha-one:refs/tags/hardware-one", "sha-two:refs/tags/hardware-two"])
        self.assertIn("tag hardware-one\n", git.call_args_list[1].args[2])

    def test_github_permission_errors_are_publication_failures(self):
        result = SimpleNamespace(returncode=1, stderr="gh: Resource not accessible by integration (HTTP 403)")
        with patch.object(m, "run_gh", return_value=result):
            with self.assertRaisesRegex(m.PublicationError, "POST repos/owner/repo/releases"):
                m.GitHub("owner/repo").api("repos/owner/repo/releases", {"tag_name": "test"})

    def test_publication_failure_stops_before_downloading_next_file(self):
        entries = m.merge_candidates([m.candidate("a.bin", "https://example.com/a"),
                                      m.candidate("b.bin", "https://example.com/b")])
        client = Mock(repo="owner/repo")
        client.release.return_value = None
        client.assets.return_value = {}
        client.read_asset.return_value = {"files": []}
        client.ensure_release.side_effect = m.PublicationError("HTTP 403")
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(m, "download", return_value=(Path(directory) / "a.bin", {})) as download, \
                patch.object(m, "split_file", return_value=[]):
            with self.assertRaisesRegex(m.PublicationError, "403"):
                m.sync_group(client, "hardware-test", entries, Path(directory))
        self.assertEqual(download.call_count, 1)
        client.upload.assert_not_called()

    def test_upload_permission_errors_do_not_retry(self):
        result = SimpleNamespace(returncode=1, stderr="gh: HTTP 403")
        with patch.object(m, "gh", return_value=result) as gh, patch.object(m.time, "sleep") as sleep:
            with self.assertRaises(m.PublicationError):
                m.GitHub("owner/repo").upload("test", Path("firmware.bin"))
        self.assertEqual(gh.call_count, 1)
        sleep.assert_not_called()

    def test_enterprise_and_numeric_newest_versions_are_first(self):
        tags = ["free-4.0.315-beta-Build1", "enterprise-3.7.9-Enterprise-Build1",
                "enterprise-3.7.26-Enterprise-Build2"]
        self.assertEqual(sorted(tags, key=m.group_priority, reverse=True), [tags[2], tags[1], tags[0]])

    def test_slow_download_switches_source_without_restarting_same_source(self):
        entry = m.merge_candidates([m.candidate("test.bin", "https://example.com/a")])[0]
        entry["sources"].append({"url": "https://example.com/b"})
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(m.time, "monotonic", side_effect=[0, 301, 302, 303]), \
                patch.object(m, "request", side_effect=[Response(b"slow"), Response(b"fast")]) as request:
            path, record = m.download(entry, Path(directory))
            self.assertEqual(path.read_bytes(), b"fast")
            self.assertEqual(record["source"]["url"], "https://example.com/b")
        self.assertEqual(request.call_count, 2)

    def test_html_content_type_is_rejected_before_reading_body(self):
        entry = m.merge_candidates([m.candidate("test.bin", "https://example.com/a")])[0]
        response = Response(b"blocked", content_type="text/html")
        with tempfile.TemporaryDirectory() as directory, patch.object(m, "request", return_value=response), \
                patch.object(response, "read1") as read:
            with self.assertRaises(ValueError):
                m.download(entry, Path(directory))
        read.assert_not_called()

    def test_old_completed_runs_are_removed_but_active_runs_are_kept(self):
        runs = [
            {"id": 1, "created_at": "2026-11-01T00:00:00Z", "status": "completed"},
            {"id": 2, "created_at": "2026-11-02T00:00:00Z", "status": "in_progress"},
            {"id": 3, "created_at": "2026-11-03T00:00:00Z", "status": "queued"},
            {"id": 4, "created_at": "2026-11-04T00:00:00Z", "status": "completed"},
        ]
        self.assertEqual(m.runs_to_delete(runs), [1])
        self.assertEqual(m.runs_to_delete(runs, current_run="1"), [])
        self.assertEqual(m.runs_to_delete([]), [])

    def test_history_compaction_and_keepalive_threshold(self):
        current = datetime(2026, 11, 6, tzinfo=timezone.utc)
        commit = {"parents": [], "committer": {"date": "2026-11-01T00:00:00Z"}}
        self.assertFalse(m.root_commit_needed(commit, current))
        commit["parents"] = [{"sha": "parent"}]
        self.assertTrue(m.root_commit_needed(commit, current))
        commit["parents"] = []
        commit["committer"]["date"] = "2026-09-01T00:00:00Z"
        self.assertTrue(m.root_commit_needed(commit, current))

    def test_compaction_uses_latest_tree_and_force_with_lease(self):
        client = Mock(repo="owner/repo")
        client.api.side_effect = [
            {"object": {"sha": "old-head"}},
            {"parents": [{"sha": "parent"}], "committer": {"date": "2026-11-01T00:00:00Z"},
             "author": {"name": "Owner", "email": "owner@example.com"}, "tree": {"sha": "latest-tree"}},
        ]
        with patch.object(m, "GitHub", return_value=client), \
                patch.object(m, "git_remote_env", return_value={}), \
                patch.object(m, "git_run", side_effect=["", "new-root", ""]) as git, \
                patch.object(m, "retarget_release_tags") as tags:
            self.assertFalse(m.compact_history(SimpleNamespace(repo="owner/repo")))
        self.assertEqual(git.call_args_list[1].args[0], ["commit-tree", "latest-tree"])
        self.assertIn("--force-with-lease=refs/heads/main:old-head", git.call_args_list[2].args[0])
        tags.assert_called_once_with(client, "new-root", dates_only=True, refresh_bodies=True)

    def test_git_authentication_stays_in_environment(self):
        with patch.dict(m.os.environ, {"GH_TOKEN": "example-token"}, clear=True):
            env = m.git_remote_env()
        self.assertEqual(env["GIT_CONFIG_COUNT"], "1")
        self.assertEqual(env["GIT_CONFIG_KEY_0"], "http.https://github.com/.extraheader")
        self.assertTrue(env["GIT_CONFIG_VALUE_0"].startswith("AUTHORIZATION: basic "))

    def test_compaction_retries_with_concurrent_updates_preserved(self):
        client = Mock(repo="owner/repo")
        metadata = {"parents": [{"sha": "parent"}], "committer": {"date": "2026-11-01T00:00:00Z"},
                    "author": {"name": "Owner", "email": "owner@example.com"}}
        client.api.side_effect = [
            {"object": {"sha": "old-head"}}, {**metadata, "tree": {"sha": "old-tree"}},
            {"object": {"sha": "new-user-head"}}, {**metadata, "tree": {"sha": "new-user-tree"}},
        ]
        with patch.object(m, "GitHub", return_value=client), \
                patch.object(m, "git_remote_env", return_value={}), \
                patch.object(m, "git_run", side_effect=["", "root1", RuntimeError("stale info"), "", "root2", ""]) as git, \
                patch.object(m, "retarget_release_tags") as tags:
            self.assertFalse(m.compact_history(SimpleNamespace(repo="owner/repo")))
        self.assertEqual(git.call_args_list[4].args[0], ["commit-tree", "new-user-tree"])
        self.assertIn("--force-with-lease=refs/heads/main:new-user-head", git.call_args_list[5].args[0])
        tags.assert_called_once_with(client, "root2", dates_only=True, refresh_bodies=True)

    def test_tag_maintenance_stops_when_main_changes(self):
        client = Mock(repo="owner/repo")
        client.api.side_effect = [[{"name": "tag", "commit": {"sha": "old"}}],
                                  {"object": {"sha": "new-user-head"}}]
        m.retarget_release_tags(client, "expected-root")
        self.assertEqual(client.api.call_count, 2)

    def test_scheduled_jitter_bounds(self):
        for delay in (0, 1800):
            with self.subTest(delay=delay), patch.dict(m.os.environ, {"GITHUB_EVENT_NAME": "schedule"}), \
                    patch.object(m.secrets, "randbelow", return_value=delay) as random_delay, \
                    patch.object(m.time, "sleep") as sleep:
                self.assertFalse(m.jitter(None))
                random_delay.assert_called_once_with(1801)
                sleep.assert_called_once_with(delay)

    def test_manual_runs_do_not_wait(self):
        with patch.dict(m.os.environ, {"GITHUB_EVENT_NAME": "workflow_dispatch"}), \
                patch.object(m.secrets, "randbelow") as random_delay, \
                patch.object(m.time, "sleep") as sleep:
            self.assertFalse(m.jitter(None))
            random_delay.assert_not_called()
            sleep.assert_not_called()

    def test_local_runs_do_not_wait(self):
        with patch.dict(m.os.environ, {}, clear=True), patch.object(m.time, "sleep") as sleep:
            self.assertFalse(m.jitter(None))
            sleep.assert_not_called()

    def test_architectures_share_release_not_assets(self):
        entries = m.merge_candidates(m.x86_candidates("3.7.26_Build202609111743"))
        self.assertEqual(len(entries), 10)
        self.assertEqual(len({e["tag"] for e in entries}), 1)
        self.assertEqual(len({e["asset_name"] for e in entries}), 10)

    def test_enterprise_filename(self):
        entries = m.x86_candidates("3.7.26_Enterprise_Build202609111742", "enterprise")
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["filename"], "iKuai8_x32_3.7.26_Enterprise_Build202609111742.bin")
        self.assertIn("/ent/", entries[0]["sources"][0]["url"])

    def test_beta_and_oem(self):
        self.assertEqual(len(m.x86_candidates("4.0.315_beta_Build202610291837")), 4)
        self.assertEqual(len(m.x86_candidates("3.6.5_Build202207280937", "oem")), 2)

    def test_prerelease_classification(self):
        self.assertFalse(m.is_prerelease("resources-router-1"))
        self.assertFalse(m.is_prerelease("free-3.7.26-Build202609111743"))
        self.assertTrue(m.is_prerelease("free-4.0.315-beta-Build202610291837"))

    def test_legacy_x86_group(self):
        self.assertTrue(m.group_for("iKuai8_2.7.18_Build20180409-09_33.iso").startswith("free-2.7.18"))

    def test_official_hardware_profiles(self):
        text = "[M100_BETA]\nfirmware_x64 = IK-MT7981V1-M100_sysupgrade_4.0.222_beta_Build202605191449.bin\n"
        entries, _ = m.parse_versions(text)
        api_source = next(s for e in entries for s in e["sources"] if "firmware" in s)
        self.assertEqual(api_source["device"], "M100")
        self.assertEqual(api_source["system"], "enterprise")
        self.assertEqual(api_source["platform"], "arm")
        self.assertTrue(any("/firmware/M100/" in s["url"] for e in entries for s in e["sources"]))
        self.assertEqual(m.platform_for("iKuai8_x32_3.7.26.bin"), "x86-32")

    def test_signing_does_not_store_ephemeral_credentials(self):
        api = m.FirmwareAPI()
        api.context = object()
        response = Response(json.dumps({"code": 0, "data": {"signUrl": "https://example.com/signed", "token": "ephemeral"}}).encode())
        source = {"device": "M100", "platform": "arm", "firmware": "test.bin", "system": "enterprise"}
        with patch.object(m, "request", return_value=response):
            url, headers, _ = api.resolve(source)
        self.assertEqual(headers["X-Auth-Token"], "ephemeral")
        self.assertNotIn("token", source)
        self.assertEqual(url, "https://example.com/signed")

    def test_source_merge_and_priority(self):
        a = m.candidate("iKuai8_x64_3.7.26_Build1.bin", "https://example.com/a", inferred=True)
        b = m.candidate(a["filename"], cloud_path="/历史固件/" + a["filename"], size=20)
        entries = m.merge_candidates([a, b, a])
        self.assertEqual(len(entries), 1)
        self.assertEqual(len(entries[0]["sources"]), 2)
        self.assertIn("cloud_path", entries[0]["sources"][0])
        self.assertEqual(entries[0]["size"], 20)
        self.assertEqual(m.merge_candidates(entries)[0]["id"], entries[0]["id"])

    def test_unicode_and_duplicate_paths(self):
        entries = m.merge_candidates([
            m.candidate("教程.pdf", cloud_path="/AP/a/教程.pdf", size=4),
            m.candidate("教程.pdf", cloud_path="/AP/b/教程.pdf", size=4),
        ])
        self.assertEqual(len({e["asset_name"] for e in entries}), 2)
        self.assertTrue(all(e["asset_name"].isascii() for e in entries))
        self.assertEqual(m.merge_candidates(entries), entries)
        self.assertTrue(all("_" not in e["asset_name"] for e in entries))

    def test_english_names(self):
        self.assertEqual(m.english_filename("DHCP静态分配和ARP绑定的作用.pdf", "a" * 64),
                         ("DHCP-Static-Leases-and-ARP-Binding.pdf", ""))
        self.assertEqual(m.english_filename("爱快IPSEC对接华为云IPSEC.pdf", "a" * 64),
                         ("iKuai-IPSEC-Integration-Huawei-Cloud-IPSEC.pdf", ""))

    def test_filename_table(self):
        records = {"a": {"id": "a", "filename": "中文.pdf", "assets": [{"name": "English.pdf"}]}}
        body = m.release_body("owner/repo", "resources-tools-0", records, [])
        self.assertIn("| 中文.pdf | [English.pdf]", body)
        self.assertEqual(m.release_title("resources-tutorial-2"), "功能配合类教程 · 3/4")

    def test_category_directory_groups_actual_releases_and_sorts_newest_first(self):
        releases = [
            {"tag_name": "free-3.7.9-Build202401121849", "name": "older", "created_at": "2024-01-12"},
            {"tag_name": "free-3.7.26-Build202609111743", "name": "newer", "created_at": "2026-09-11"},
            {"tag_name": "resources-router-2", "name": "router docs"},
            {"tag_name": "enterprise-3.7.26-Enterprise-Build202609111742", "name": "enterprise"},
            {"tag_name": m.INDEX_TAG, "name": "index"},
            {"tag_name": "free-4.0.1-Build1", "name": "draft", "draft": True},
        ]
        body = m.category_body("owner/repo", releases)
        self.assertLess(body.index("[newer]"), body.index("[older]"))
        self.assertIn('<a name="resources-router"></a>', body)
        self.assertNotIn("[draft]", body)
        self.assertNotIn("[index]", body)
        self.assertEqual(body.count("[router docs]"), 1)
        self.assertEqual(body.count("[enterprise]"), 1)

    def test_readme_category_shortcuts_all_have_real_directory_anchors(self):
        readme = (m.ROOT / "README.md").read_text()
        fragments = m.re.findall(r"/releases/tag/download-categories#user-content-([a-z0-9-]+)", readme)
        body = m.category_body("owner/repo", [])
        self.assertEqual(len(fragments), 20)
        self.assertEqual(len(set(fragments)), len(fragments))
        for fragment in fragments:
            self.assertIn(f'<a name="{fragment}"></a>', body)
        self.assertEqual(m.release_title(m.CATEGORY_TAG), "iKuai 分类下载目录")

    def test_enterprise_v4_beta_has_its_own_category_without_free_or_stable_releases(self):
        releases = [
            {"tag_name": "enterprise-4.0.223-beta-Enterprise-Build202605281557", "name": "Enterprise Beta"},
            {"tag_name": "enterprise-4.0.223-Enterprise-Build202605281557", "name": "Enterprise Stable"},
            {"tag_name": "free-4.0.223-beta-Build202605281556", "name": "Free Beta"},
            {"tag_name": "enterprise-3.7.26-Enterprise-Build202609111742", "name": "Enterprise 3.x"},
        ]
        body = m.category_body("owner/repo", releases)
        section = body.split('<a name="enterprise-4-beta"></a>', 1)[1].split('<a name="oem"></a>', 1)[0]
        self.assertIn("[Enterprise Beta]", section)
        self.assertNotIn("[Enterprise Stable]", section)
        self.assertNotIn("[Free Beta]", section)
        self.assertNotIn("[Enterprise 3.x]", section)
        self.assertEqual(body.count("[Enterprise Beta]"), 2)

    def test_rename_keeps_content_digest(self):
        entry = m.merge_candidates([m.candidate("教程.pdf", cloud_path="/AP/教程.pdf", size=8)])[0]
        old_name = m.legacy_asset_filename(entry)
        remote = {"id": 10, "name": old_name, "label": "", "size": 8,
                  "digest": "sha256:" + "1" * 64, "created_at": "2026-11-06T00:00:00Z"}
        assets, records = {old_name: remote}, {}
        class Client:
            repo = "owner/repo"
            def api(self, endpoint, data, method):
                return {**remote, **data}
        self.assertTrue(m.repair_group_names(Client(), [entry], records, assets))
        record = records[entry["id"]]
        self.assertEqual(record["assets"][0]["name"], entry["asset_name"])
        self.assertEqual(record["sha256"], "1" * 64)
        self.assertTrue(m.complete_record(record, assets))

    def test_incomplete_upload_without_digest_is_not_recovered(self):
        entry = m.merge_candidates([m.candidate("test.bin", "https://example.com/a")])[0]
        assets = {entry["asset_name"]: {"id": 1, "name": entry["asset_name"], "size": 8,
                                      "state": "starter", "digest": None}}
        records, client = {}, Mock(repo="owner/repo")
        self.assertFalse(m.repair_group_names(client, [entry], records, assets))
        self.assertEqual(records, {})
        client.api.assert_not_called()

    def test_names_preserve_file_extensions(self):
        examples = ("爱快App5.0.17更新2024-09-20-104309.apk", "链路聚合（WAN口）.pdf",
                    "高级自定义协议.txt", "小白说明.rar", "虚拟机安装爱快系统（英文版）.mp4")
        for original in examples:
            name, missing = m.english_filename(original, "a" * 64)
            self.assertFalse(missing)
            self.assertTrue(name.isascii())
            self.assertEqual(Path(name).suffix, Path(original).suffix)

    def test_reject_path_traversal(self):
        for name in ("../a", "..", "a/b", "a\\b", "a\nb"):
            with self.assertRaises(ValueError):
                m.candidate(name, "https://example.com/a")

    def test_cloud_pagination(self):
        pages = [
            {"code": 200, "data": {"content": [{"name": "a"}], "total": 2, "has_more": True}},
            {"code": 200, "data": {"content": [{"name": "b"}], "total": 2, "has_more": False}},
        ]
        with patch.object(m, "get_json", side_effect=pages) as get:
            self.assertEqual(len(m.cloud_list("/")), 2)
            self.assertEqual(get.call_args.args[1]["page"], 2)

    def test_reject_incomplete_pagination(self):
        with patch.object(m, "get_json", return_value={"code": 200, "data": {"content": [], "total": 5}}):
            with self.assertRaises(ValueError):
                m.cloud_list("/")

    def test_html_error_not_mirrored(self):
        entry = m.merge_candidates([m.candidate("firmware.bin", "https://example.com/a")])[0]
        with tempfile.TemporaryDirectory() as directory, patch.object(m, "request", return_value=Response(b"<!DOCTYPE html>blocked")):
            with self.assertRaises(ValueError):
                m.download(entry, Path(directory))
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_download_size_and_blob_integrity(self):
        body = b"real firmware data"
        sha1 = hashlib.sha1(f"blob {len(body)}\0".encode() + body).hexdigest()
        entry = m.merge_candidates([m.candidate("test.bin", "https://example.com/a", size=len(body), git_blob_sha1=sha1)])[0]
        with tempfile.TemporaryDirectory() as directory, patch.object(m, "request", return_value=Response(body)):
            path, record = m.download(entry, Path(directory))
            self.assertEqual(path.read_bytes(), body)
            self.assertEqual(record["sha256"], hashlib.sha256(body).hexdigest())

    def test_bad_size_rejected(self):
        entry = m.merge_candidates([m.candidate("test.bin", "https://example.com/a", size=99)])[0]
        with tempfile.TemporaryDirectory() as directory, patch.object(m, "request", return_value=Response(b"short")):
            with self.assertRaises(ValueError):
                m.download(entry, Path(directory))

    def test_404_not_retried(self):
        entry = m.merge_candidates([m.candidate("test.bin", "https://example.com/a")])[0]
        with tempfile.TemporaryDirectory() as directory, patch.object(m, "request", side_effect=urllib.error.HTTPError("url", 404, "gone", {}, None)) as get:
            with self.assertRaises(ValueError):
                m.download(entry, Path(directory))
            self.assertEqual(get.call_count, 1)

    def test_split_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "large.bin"
            original.write_bytes(bytes(range(256)))
            parts = m.split_file(original, size=100)
            self.assertEqual([p.stat().st_size for p in parts], [100, 100, 56])
            self.assertEqual(b"".join(p.read_bytes() for p in parts), original.read_bytes())

    def test_resume_requires_remote_digest(self):
        record = {"assets": [{"name": "a", "size": 8, "sha256": "1" * 64}]}
        assets = {"a": {"name": "a", "size": 8, "digest": "sha256:" + "1" * 64}}
        self.assertTrue(m.complete_record(record, assets))
        assets["a"]["digest"] = "sha256:" + "2" * 64
        self.assertFalse(m.complete_record(record, assets))


if __name__ == "__main__":
    unittest.main()
