#!/usr/bin/env python3
"""爱快公开下载与技术云盘的可续传 Release 镜像，只使用 Python 标准库。"""

from __future__ import annotations

import argparse
import atexit
import base64
import configparser
import hashlib
import hmac
import json
import os
import re
import shutil
import secrets
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath

from names import english_filename

ROOT = Path(__file__).resolve().parents[1]
SITE = "https://www.ikuai8.com"
CLOUD = "https://demo.ikuai8.com"
PATCH = "https://patch.ikuai8.com"
UPSTREAM = "https://raw.githubusercontent.com/LucienShui/ikuai-firmware/main"
ARCHIVE = "LOVECHEN/ikuaifw-2512500960-"
INDEX_TAG = "mirror-index"
CATEGORY_TAG = "download-categories"
PART_SIZE = 1900 * 1024 * 1024
CATEGORIES = {
    "AP": "ap", "OLT": "olt", "iKuai_x86_beta": "x86-beta",
    "云平台类": "cloud", "交换机": "switch", "产品素材": "product",
    "功能配合类教程": "tutorial", "升级文件": "upgrade", "历史固件": "history",
    "小工具综合": "tools", "路由": "router", "防火墙": "firewall",
}
SPLIT_META = "split-archive.json"
META = {"sources.json", "checksums.sha256", "failures.json", SPLIT_META}
TRANSFER_PREFIX = "mirror-run-"


class SourceUnavailable(ValueError):
    """源站缺失或暂不可用，保留覆盖缺口并在后续轮次重试。"""


def failure_kind(exc):
    if isinstance(exc, SourceUnavailable):
        return "unavailable"
    if isinstance(exc, urllib.error.HTTPError):
        return "unavailable" if exc.code in (404, 410, 429, 500, 502, 503, 504) else "error"
    if isinstance(exc, (urllib.error.URLError, TimeoutError, ConnectionError)):
        return "unavailable"
    return "error"


def source_issue(source, exc):
    return {"source": source, "error": str(exc), "kind": failure_kind(exc)}


def issue_kind(issue):
    if "kind" in issue:
        return issue["kind"]
    # 兼容旧报告；只认明确的源站不可用，未知错误和校验错误不能被降级。
    error = issue.get("error", "")
    try:
        nested = json.loads(error)
    except (ValueError, TypeError):
        nested = None
    if isinstance(nested, list) and nested:
        return "unavailable" if all(isinstance(item, dict) and issue_kind(item) == "unavailable" for item in nested) else "error"
    unavailable = ("HTTP Error 404: Not Found", "HTTP Error 410: Gone", "The read operation timed out",
                   "<urlopen error timed out>", "下载到 HTML 错误页，不是文件", "下载到 HTML/XML 错误页，不是文件")
    return "unavailable" if error in unavailable or error.startswith("固件签名接口: 400 固件不存在:") else "error"


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def save(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")


def request(url, data=None, method=None, headers=None, attempts=4, context=None, timeout=30):
    headers = {"User-Agent": "ikuai-release-mirror/1.0", **(headers or {})}
    if data is not None:
        data = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(urllib.parse.quote(url, safe=":/?=&%+@"),
                                 data=data, headers=headers, method=method)
    for attempt in range(attempts):
        try:
            return urllib.request.urlopen(req, timeout=timeout, context=context)
        except urllib.error.HTTPError as exc:
            if exc.code not in (429, 500, 502, 503, 504) or attempt == attempts - 1:
                raise
            time.sleep(min(60, int(exc.headers.get("Retry-After", 5 * (attempt + 1)))))
        except (OSError, TimeoutError):
            if attempt == attempts - 1:
                raise
            time.sleep(2 ** attempt)


def get_json(url, data=None):
    with request(url, data) as response:
        return json.load(response)


def get_text(url):
    with request(url) as response:
        return response.read().decode("utf-8", errors="replace")


def cloud_list(path):
    entries, page = [], 1
    while True:
        result = get_json(CLOUD + "/api/fs/list", {
            "path": path, "password": "", "page": page,
            "per_page": 200, "refresh": False,
        })
        if result.get("code") != 200:
            raise ValueError(f"云盘 {path}: {result.get('message')}")
        data = result["data"]
        chunk = data.get("content") or []
        entries.extend(chunk)
        if not data.get("has_more") and len(entries) >= data.get("total", len(entries)):
            return entries
        if not chunk:
            raise ValueError(f"云盘分页提前结束: {path}, page={page}")
        page += 1


class Links(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs)


def hardware_parts(name):
    match = re.fullmatch(r"(.+)_sysupgrade_(.+)\.bin", name, re.I)
    if match:
        return match[1], match[2]
    match = re.fullmatch(r"iKuai-([^_]+)_x(?:32|64)_(.+)\.bin", name, re.I)
    if match:
        return match[1], match[2]
    return None


def group_for(name, cloud_path=""):
    if parts := hardware_parts(name):
        model, version = parts
        return "hardware-" + re.sub(r"[^A-Za-z0-9_.-]", "-", model) + "-" + re.sub(r"[^A-Za-z0-9.-]", "-", version)
    match = re.fullmatch(r"(iKuai8?|oem)(?:_x(?:32|64))?_(.+?)\.(?:iso|img(?:\.(?:gz|rar))?|gho|bin|patch)", name, re.I)
    if match:
        version = match[2]
        edition = "enterprise" if "Enterprise" in version else ("oem" if match[1].lower() == "oem" else "free")
        return edition + "-" + version.replace("_", "-")
    category = cloud_path.strip("/").split("/")[0]
    bucket = int(digest(cloud_path or name)[:8], 16) % 4
    return "resources-" + CATEGORIES.get(category, digest(category)[:12]) + f"-{bucket}"


def candidate(name, url=None, cloud_path=None, size=None, **extra):
    if not name or name in (".", "..") or "/" in name or "\\" in name or any(ord(c) < 32 for c in name):
        raise ValueError(f"非法文件名: {name!r}")
    source = {"url": url} if url else {"cloud_path": cloud_path}
    return {"filename": name, "tag": group_for(name, cloud_path or ""),
            "sources": [{**source, **extra}], "size": size}


def discover_cloud(errors):
    result, pending, visited = [], deque(["/"]), set()
    while pending:
        path = pending.popleft()
        if path in visited:
            continue
        visited.add(path)
        try:
            entries = cloud_list(path)
        except Exception as exc:
            errors.append(source_issue(CLOUD + path, exc))
            continue
        for entry in entries:
            name = entry["name"]
            if name in (".", "..") or "/" in name:
                raise ValueError("云盘返回非法路径")
            child = path.rstrip("/") + "/" + name
            if entry["is_dir"]:
                pending.append(child)
            else:
                result.append(candidate(name, cloud_path=child, size=entry["size"],
                                        modified=entry.get("modified")))
        print(f"cloud {path}: {len(entries)}, files={len(result)}", flush=True)
    return result


def x86_candidates(version, edition="free"):
    result = []
    if edition == "enterprise":
        version = version.replace("_Enterprise", "").replace("_Build", "_Enterprise_Build")
    for arch in ("x32", "x64"):
        for folder, extension in (("iso", "iso"), ("img", "img.gz"), ("ghost", "gho"), ("patch", "bin"), ("patch", "patch")):
            if edition in ("enterprise", "oem") and extension != "bin":
                continue
            if version.startswith("4.") and extension not in ("iso", "bin"):
                continue
            name = f"{'oem' if edition == 'oem' else 'iKuai8'}_{arch}_{version}.{extension}"
            directory = "ent" if edition == "enterprise" else "3.x/" + folder
            result.append(candidate(name, f"{PATCH}/{directory}/{name}", inferred=True))
    return result


def parse_versions(text):
    config = configparser.ConfigParser(interpolation=None, strict=False)
    config.optionxform = str
    config.read_string(text)
    result = []
    for section in config.sections():
        for key, name in config[section].items():
            if key not in ("firmware", "firmware_x64") or not name.endswith(".bin"):
                continue
            device = re.sub(r"_BETA$", "", section)
            if name.startswith(("iKuai8_", "oem_x")):
                version = re.sub(r"^(?:iKuai8|oem)_x(?:32|64)_|\.bin$", "", name)
                edition = "oem" if name.startswith("oem_") else "enterprise" if "Enterprise" in name else "free"
                result.extend(x86_candidates(version, edition))
            else:
                result.append(candidate(name, f"{PATCH}/firmware/{device}/{name}", inferred=True))
            result.append(candidate(name, "https://devapi.ikuai8.com/firmware/sign-url",
                                    device=device, platform=platform_for(name),
                                    system="community" if device in ("X86", "X86_oem") else "enterprise",
                                    firmware=name))
    for section in ("GLOBAL", "APVER2"):
        if section not in config:
            continue
        for model, version in config[section].items():
            if not model.startswith("IK-") or not re.fullmatch(r"\d+\.\d+\.\d+", version):
                continue
            name = f"{model}_sysupgrade_{version}.bin"
            result.append(candidate(name, "https://devapi.ikuai8.com/firmware/sign-url", inferred=True,
                                    device=model, platform=platform_for(name), system="enterprise", firmware=name))
    return result, config


def discover_web(errors):
    result = []
    for page, edition in (("version_list.txt", "free"), ("version_enterprise_list.txt", "enterprise"), ("version_4_list.txt", "free")):
        try:
            for version in set(get_text(UPSTREAM + "/" + page).splitlines()):
                version = version.strip()
                if re.fullmatch(r"[34]\.[0-9.]+(?:_beta)?_Buil[d]?\d+", version):
                    result.extend(x86_candidates(version, edition))
        except Exception as exc:
            errors.append(source_issue(UPSTREAM + "/" + page, exc))
    for version in ("3.7.14_Build202408071731", "3.6.5_Build202207280937"):
        result.extend(x86_candidates(version, "oem"))
    urls = [SITE + "/component/download", "https://en.ikuai8.com/firmware.html"] + [
        SITE + f"/index.php?option=com_content&view=article&id={ident}" for ident in (331, 447, 446, 25)
    ] + ["https://download.ikuai8.com/submit3x/Version_all"]
    snapshots = {}
    for url in urls:
        try:
            text = get_text(url)
            snapshots[url] = text
            if "Version_all" in url:
                entries, config = parse_versions(text)
                result.extend(entries)
                devices = [s for s in config.sections() if s not in ("GLOBAL", "APVER2")]
                for device in devices:
                    try:
                        current = FIRMWARE_API.versions(device)
                        snapshots["https://devapi.ikuai8.com/firmware/version-all?model=" + device] = current
                        result.extend(parse_versions(current)[0])
                    except Exception as exc:
                        errors.append(source_issue("version-all:" + device, exc))
            else:
                if "en.ikuai8.com" in url:
                    for match in re.finditer(r"var info_([23])_x = (\{[^\n]+\})", text):
                        generation, info = match[1], json.loads(match[2])
                        for arch in ("x86", "x64"):
                            for folder, suffix, ext in (("iso", "iso", "iso"), ("img", "img", "img.rar" if generation == "2" else "img.gz"), ("ghost", "gho", "gho"), ("patch", "patch", "patch"), ("patch", "bin", "bin")):
                                if info.get(arch + "_" + suffix):
                                    name = info[arch + "_prefix"] + "." + ext
                                    base = PATCH + ("/3.x" if generation == "3" else "")
                                    result.append(candidate(name, f"{base}/{folder}/{name}", advertised_md5=info[arch + "_" + suffix]))
                for link in Links(text).links:
                    href = urllib.parse.urljoin(url, link["href"])
                    parsed = urllib.parse.urlsplit(href)
                    if parsed.path == "/download.php":
                        path = urllib.parse.parse_qs(parsed.query).get("n", [""])[0]
                        href = PATCH + "/" + path.lstrip("/")
                        parsed = urllib.parse.urlsplit(href)
                    if re.search(r"\.(?:bin|patch|iso|img\.gz|gho|zip|rar|exe|pdf)$", parsed.path, re.I):
                        name = urllib.parse.unquote(PurePosixPath(parsed.path).name)
                        result.append(candidate(name, href, advertised_md5=link.get("data-md5")))
                # 历史日志提供官方 build，不能从发布日期猜测 build 时间。
                for version in re.findall(r"(?:iKuai8_)?([34]\.[0-9.]+(?:_Enterprise)?_Build\d+)", text):
                    result.extend(x86_candidates(version, "enterprise" if "Enterprise" in version or "id=447" in url else "free"))
        except Exception as exc:
            errors.append(source_issue(url, exc))
    return result, snapshots


def discover_archive(errors):
    result = []
    try:
        tree = get_json(f"https://api.github.com/repos/{ARCHIVE}/git/trees/main?recursive=1")
        if tree.get("truncated"):
            raise ValueError("GitHub tree 被截断")
        for entry in tree["tree"]:
            name = entry["path"]
            if entry["type"] == "blob" and "/" not in name and name.endswith((".bin", ".iso", ".gho", ".img.gz", ".patch")):
                result.append(candidate(name, f"https://raw.githubusercontent.com/{ARCHIVE}/{tree['sha']}/{name}",
                                        size=entry["size"], git_blob_sha1=entry["sha"], provenance="community-archive"))
    except Exception as exc:
        errors.append(source_issue(ARCHIVE, exc))
    return result


def merge_candidates(entries):
    groups = {}
    for entry in entries:
        # 固件以原始文件名合并多来源；资料以云盘完整路径区分同名文件。
        path = next((s["cloud_path"] for s in entry["sources"] if "cloud_path" in s), "")
        if hardware_parts(entry["filename"]):
            entry = {**entry, "tag": group_for(entry["filename"], path)}
        identity = entry["filename"] if not entry["tag"].startswith("resources-") else path or entry["sources"][0].get("url")
        key = entry["tag"] + "/" + identity
        if key not in groups:
            groups[key] = {**entry, "id": digest(key), "sources": []}
        item = groups[key]
        if entry.get("size") is not None and item.get("size") is None:
            item["size"] = entry["size"]
        for source in entry["sources"]:
            if source not in item["sources"]:
                item["sources"].append(source)
    english_counts = Counter(english_filename(e["filename"], e["id"])[0] for e in groups.values())
    for item in groups.values():
        name = item["filename"]
        base = english_filename(name, item["id"])[0]
        item["asset_name"], missing = english_filename(name, item["id"], english_counts[base] > 1 or base in META)
        if missing:
            item["untranslated_name"] = missing
        else:
            item.pop("untranslated_name", None)
        item["sources"].sort(key=lambda s: ("cloud_path" not in s, bool(s.get("inferred")), s.get("provenance") == "community-archive"))
    return sorted(groups.values(), key=lambda e: (e["tag"], e["asset_name"]))


def legacy_asset_filename(entry):
    name = entry["filename"]
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name).strip(".")[:180] or "file"
    if safe != name or safe in META:
        safe = safe[:140] + "--" + entry["id"][:12] + "".join(PurePosixPath(name).suffixes)[-20:]
    return safe


def release_title(tag, assets=()):
    if tag == INDEX_TAG:
        return "iKuai 镜像总索引"
    if tag == CATEGORY_TAG:
        return "iKuai 分类下载目录"
    if tag.startswith("resources-") and release_kind(tag, assets) == "hardware":
        names = [a["name"] for a in assets if a["name"] not in META]
        newest = max(names, key=file_order_key)
        model = re.match(r"iKuai-([^_]+)", newest)
        title = "iKuai 硬件固件 · " + (model[1] if model else newest.split("_sysupgrade_")[0])
        dates = [date for name in names if (date := build_date(name))]
        return title + (" · " + display_build_date(max(dates)) if dates else "")
    if tag.startswith("resources-"):
        category, bucket = tag.removeprefix("resources-").rsplit("-", 1)
        title = next((key for key, value in CATEGORIES.items() if value == category), category)
        return f"{title} · {int(bucket) + 1}/4"
    if tag.startswith("hardware-"):
        parts = [hardware_parts(a["name"]) for a in assets if hardware_parts(a["name"])]
        if parts and len(set(parts)) == 1:
            model, version = parts[0]
            title = "iKuai 硬件固件 · " + model + " · " + version.split("_Build", 1)[0].replace("_", " ")
        else:
            title = "iKuai 硬件固件 · " + tag.removeprefix("hardware-")
        latest = max((date for asset in assets if (date := build_date(asset["name"]))), default=None)
        return title + (" · " + display_build_date(latest) if latest else "")
    edition, version = tag.split("-", 1)
    title = {"free": "免费版", "enterprise": "企业版", "oem": "OEM"}.get(edition, edition)
    return f"iKuai {title} {version}"


def discover(args):
    errors = []
    web, snapshots = discover_web(errors)
    files = discover_cloud(errors) + web + discover_archive(errors)
    if args.previous and Path(args.previous).exists():
        files += json.loads(Path(args.previous).read_text())["files"]
    files = merge_candidates(files)
    # 历史 BIN 同时尝试新签名接口，避免旧 CDN 删除后丢失仍存于官方对象存储的版本。
    for entry in files:
        name = entry["filename"]
        device = None
        if name.endswith(".bin") and name.startswith(("iKuai8_x", "oem_x")):
            device = "X86_oem" if name.startswith("oem_") else "X86ENT" if "Enterprise" in name else "X86"
        elif "_sysupgrade_" in name:
            model = name.split("_sysupgrade_")[0]
            if re.fullmatch(r"(?:IK-)?(?:MT\w+|MVL\w+|IPQ\w+)-[A-Za-z0-9-]+", model):
                device = model.split("-", 2)[-1] if model.startswith("IK-") else model.split("-", 1)[-1]
        if device:
            source = {"url": "https://devapi.ikuai8.com/firmware/sign-url", "device": device,
                      "platform": platform_for(name), "system": "community" if device in ("X86", "X86_oem") else "enterprise",
                      "firmware": name, "inferred": True}
            if not any(s.get("firmware") == name for s in entry["sources"]):
                entry["sources"].append(source)
    catalog = {"schema": 1, "discovered_at": now(), "files": files, "discovery_errors": errors,
               "source_snapshots": snapshots}
    save(args.catalog, catalog)
    summary = {"files": len(files), "release_groups": len({e['tag'] for e in files}),
               "known_bytes": sum(e.get("size") or 0 for e in files),
               "categories": dict(Counter(e["tag"].split("-")[0] for e in files)), "errors": errors}
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if errors:
        print(f"::warning::扫描有 {len(errors)} 个来源缺口，详情保留在覆盖报告中，下轮重试")
    return any(issue_kind(error) != "unavailable" for error in errors)


def gh(*args, check=True):
    proc = run_gh(args)
    if check and proc.returncode:
        raise RuntimeError(proc.stderr.strip())
    return proc


def run_gh(args, payload=None):
    network_failures = 0
    for attempt in range(65):
        proc = subprocess.run(["gh", *args], input=payload, capture_output=True, text=True)
        if proc.returncode and any(term in proc.stderr.lower() for term in (
            "eof", "connection reset", "tls handshake timeout", "i/o timeout",
        )):
            network_failures += 1
            if network_failures >= 3:
                return proc
            time.sleep(2 ** network_failures)
            continue
        if not proc.returncode or not any(term in proc.stderr.lower() for term in (
            "rate limit", "abuse detection", "http 429", "http 502", "http 503", "http 504",
        )):
            return proc
        delay = 60
        if any(term in proc.stderr.lower() for term in ("rate limit", "abuse detection", "http 429")):
            # rate_limit 不消耗主请求额度；所有分片共享仓库额度，不能靠重启任务恢复。
            status = subprocess.run(["gh", "api", "rate_limit"], capture_output=True, text=True)
            try:
                quota = json.loads(status.stdout)["resources"]["core"]
                if quota["remaining"] == 0:
                    delay = max(1, int(quota["reset"]) - int(time.time()) + 5)
                else:
                    delay = min(60 * 2 ** min(attempt, 4), 900)
            except (ValueError, KeyError, TypeError):
                pass
        print(f"GitHub 请求暂缓，{delay} 秒后重试 ({attempt + 1}/65)", flush=True)
        time.sleep(delay)
    return proc


class PublicationError(RuntimeError):
    """发布端失败必须中止分片，不能伪装成源文件不可用。"""


class GitHub:
    def __init__(self, repo):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
            raise ValueError("非法仓库名")
        self.repo = repo

    def api(self, endpoint, data=None, method=None):
        args = ["api", endpoint]
        if method:
            args += ["--method", method]
        if data is not None:
            proc = run_gh([*args, "--input", "-"], payload=json.dumps(data))
        else:
            proc = gh(*args, check=False)
        if proc.returncode:
            if "HTTP 404" in proc.stderr and data is None and method in (None, "GET"):
                return None
            raise PublicationError(f"GitHub {method or ('POST' if data is not None else 'GET')} {endpoint}: {proc.stderr.strip()}")
        return json.loads(proc.stdout) if proc.stdout.strip() else None

    def release(self, tag):
        return self.api(f"repos/{self.repo}/releases/tags/{urllib.parse.quote(tag, safe='')}")

    def assets(self, release):
        if not release:
            return {}
        result, page = {}, 1
        while True:
            items = self.api(f"repos/{self.repo}/releases/{release['id']}/assets?per_page=100&page={page}")
            result.update({a["name"]: a for a in items})
            if len(items) < 100:
                return result
            page += 1

    def ensure_release(self, tag):
        release = self.release(tag)
        if release:
            return release
        head = self.api(f"repos/{self.repo}/git/ref/heads/main")["object"]["sha"]
        dated_tag(self, tag, head, release_sort_date(tag))
        return self.api(f"repos/{self.repo}/releases", {
            "tag_name": tag, "name": release_title(tag),
            "body": "镜像进行中。完整性与来源详见 sources.json 和 checksums.sha256。",
            "draft": False, "prerelease": is_prerelease(tag),
            "make_latest": "false", "target_commitish": "main",
        })

    def read_asset(self, assets, name, fallback):
        if name not in assets:
            return fallback
        asset = assets[name]
        public = asset.get("browser_download_url") or ""
        expected = asset.get("digest") or ""
        if public.startswith(f"https://github.com/{self.repo}/releases/download/") and expected.startswith("sha256:"):
            try:
                with request(public + "?mirror_metadata=" + secrets.token_hex(8), attempts=2, timeout=30) as response:
                    payload = response.read(asset["size"] + 1)
            except (urllib.error.URLError, TimeoutError, ConnectionError):
                pass
            else:
                if len(payload) != asset["size"] or "sha256:" + hashlib.sha256(payload).hexdigest() != expected:
                    raise PublicationError(f"公开清单大小或 SHA256 不一致: {name}")
                return json.loads(payload)
        proc = gh("api", asset["url"], "-H", "Accept: application/octet-stream")
        return json.loads(proc.stdout)

    def upload(self, tag, path, clobber=False):
        args = ["release", "upload", tag, str(path), "--repo", self.repo]
        if clobber:
            args.append("--clobber")
        for attempt in range(4):
            proc = gh(*args, check=False)
            if proc.returncode == 0:
                return
            # 上传超时可能已在服务端完成；由调用者在重跑时通过 digest 恢复。
            if attempt == 3 or any(term in proc.stderr for term in ("already_exists", "HTTP 401", "HTTP 403")):
                raise PublicationError(f"GitHub upload {tag}/{path.name}: {proc.stderr.strip()}")
            time.sleep(5 * (attempt + 1))


def platform_for(name):
    if name.startswith(("iKuai", "oem_x")):
        return "x86-64" if "x64" in name else "x86-32"
    return "mips" if re.search(r"MT762|QCA95|AR934|RTL8197", name) else "arm"


class FirmwareAPI:
    """兼容公开下载客户端的短时签名；证书仅在任务临时目录内使用。"""

    def __init__(self):
        self.gwid = secrets.token_hex(16)
        self.context = None
        self.temp = None

    def signed_headers(self, params):
        raw = "&".join(f"{key}={params[key]}" for key in sorted(params) if params[key])
        signature = hmac.new(self.gwid[-10:].encode(), raw.encode(), hashlib.sha256).hexdigest()
        return {**params, "X-Sign": signature}

    def versions(self, device):
        headers = self.signed_headers({"X-Device-Platform": device, "X-Gw-Id": self.gwid,
                                       "X-Nonce": str(secrets.randbelow(10**10)).zfill(10)})
        with request("https://devapi.ikuai8.com/firmware/version-all", headers=headers) as response:
            result = json.load(response)
        url = (result.get("data") or {}).get("fileUrl")
        if result.get("code") != 0 or not url:
            raise ValueError(f"版本接口: {result.get('code')} {result.get('message')}")
        return get_text(url)

    def resolve(self, source):
        headers = self.signed_headers({
            "X-Device-Platform": source["platform"], "X-Firmware-Name": source["firmware"],
            "X-Gw-Id": self.gwid, "X-Nonce": str(secrets.randbelow(10**10)).zfill(10),
            "X-System-Version": source["system"], "X-Model-Type": source["device"],
        })
        with request("https://devapi.ikuai8.com/firmware/sign-url", method="POST", headers=headers) as response:
            result = json.load(response)
        data = result.get("data") or {}
        if result.get("code") != 0 or not data.get("signUrl") or not data.get("token"):
            if result.get("code") == 400 and "固件不存在" in str(result.get("message")):
                raise SourceUnavailable(f"固件签名接口: 400 {result.get('message')}")
            raise ValueError(f"固件签名接口: {result.get('code')} {result.get('message')}")
        if self.context is None:
            (ROOT / ".work").mkdir(exist_ok=True)
            self.temp = tempfile.TemporaryDirectory(prefix="ikuai-client-", dir=ROOT / ".work")
            atexit.register(self.temp.cleanup)
            # 固定公开兼容客户端版本，不执行第三方代码，不导入系统 Keychain。
            base = "https://raw.githubusercontent.com/iKuaiPatch/tools/ac974757cc18cc8b3c28b415121e7e7064f953ea/new_download_firmware/mtls/"
            for name in ("ca.crt", "client.crt", "client.key"):
                path = Path(self.temp.name) / name
                path.write_text(get_text(base + name))
                path.chmod(0o600)
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE
            self.context.set_ciphers("ALL:@SECLEVEL=0")
            self.context.load_cert_chain(str(Path(self.temp.name) / "client.crt"), str(Path(self.temp.name) / "client.key"))
        return data["signUrl"], {"X-Auth-Token": str(data["token"]), "X-Gw-Id": self.gwid}, self.context


FIRMWARE_API = FirmwareAPI()


def is_prerelease(tag):
    return bool(re.search(r"(?:^|[-_])(?:beta|rc)\d*(?:[-_]|$)", tag, re.I))


def resolve_source(source):
    if "firmware" in source:
        return FIRMWARE_API.resolve(source)
    if "cloud_path" not in source:
        return source["url"], {}, None
    result = get_json(CLOUD + "/api/fs/get", {"path": source["cloud_path"], "password": ""})
    if result.get("code") != 200 or not result.get("data", {}).get("raw_url"):
        raise ValueError(f"云盘直链解析失败: {result.get('message')}")
    return result["data"]["raw_url"], {}, None


def download(entry, directory):
    errors = []
    target = directory / entry["asset_name"]
    for source in entry["sources"]:
        try:
            url, headers, context = resolve_source(source)
            started = progress = time.monotonic()
            budget = min(1800, max(300, (entry.get("size") or 0) / (128 * 1024)))
            print(f"downloading {entry['tag']}/{entry['asset_name']}", flush=True)
            with request(url, headers=headers, context=context, attempts=2) as response, target.open("wb") as output:
                expected = response.headers.get("Content-Length")
                is_html = entry["filename"].lower().endswith((".html", ".htm"))
                if not is_html and "text/html" in response.headers.get("Content-Type", "").lower():
                    raise SourceUnavailable("下载到 HTML 错误页，不是文件")
                sha = hashlib.sha256()
                git_sha = hashlib.sha1()
                if source.get("git_blob_sha1"):
                    git_sha.update(f"blob {entry['size']}\0".encode())
                first, size = b"", 0
                while chunk := response.read1(64 * 1024):
                    current = time.monotonic()
                    if current - started > budget:
                        raise TimeoutError(f"源站下载超过 {budget:.0f} 秒，切换来源或下轮重试")
                    if not first:
                        first = chunk[:2048].lstrip().lower()
                        if not is_html and first.startswith((b"<!doctype html", b"<html")):
                            raise SourceUnavailable("下载到 HTML/XML 错误页，不是文件")
                    output.write(chunk)
                    sha.update(chunk)
                    git_sha.update(chunk)
                    size += len(chunk)
                    if current - progress >= 30:
                        print(f"progress {entry['asset_name']}: {size}/{expected or '?'} bytes, {size / max(1, current - started) / 1024:.0f} KiB/s", flush=True)
                        progress = current
            if expected is not None and size != int(expected):
                raise ValueError(f"传输不完整: {size}/{expected}")
            if entry.get("size") is not None and size != entry["size"]:
                raise ValueError(f"源文件大小不一致: {size}/{entry['size']}")
            if size == 0 and entry.get("size") != 0:
                raise ValueError("意外的空文件")
            if source.get("git_blob_sha1") and git_sha.hexdigest() != source["git_blob_sha1"]:
                raise ValueError("Git blob SHA-1 校验失败")
            return target, {"id": entry["id"], "filename": entry["filename"],
                            "sha256": sha.hexdigest(), "size": size,
                            "source": source, "archived_at": now()}
        except Exception as exc:
            errors.append(source_issue(source, exc))
            target.unlink(missing_ok=True)
    error_type = SourceUnavailable if errors and all(issue_kind(error) == "unavailable" for error in errors) else ValueError
    raise error_type(json.dumps(errors, ensure_ascii=False))


def split_file(path, size=PART_SIZE):
    if path.stat().st_size <= size:
        return [path]
    parts = []
    with path.open("rb") as original:
        number = 1
        while True:
            first = original.read(min(1024 * 1024, size))
            if not first:
                break
            part = path.with_name(path.name + f".part-{number:03d}")
            with part.open("wb") as output:
                output.write(first)
                remaining = size - len(first)
                while remaining:
                    chunk = original.read(min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    output.write(chunk)
                    remaining -= len(chunk)
            parts.append(part)
            number += 1
    return parts


def file_sha(path):
    with path.open("rb") as data:
        return hashlib.file_digest(data, "sha256").hexdigest()


def complete_record(record, assets):
    parts = record.get("assets", [])
    if not parts:
        return False
    return all(p["name"] in assets and assets[p["name"]]["size"] == p["size"]
               and assets[p["name"]].get("digest") == "sha256:" + p["sha256"] for p in parts)


def repair_group_names(client, entries, records, assets):
    changed = False
    for entry in entries:
        record = records.get(entry["id"])
        if record is None:
            old = assets.get(legacy_asset_filename(entry))
            if old is None:
                matches = [a for a in assets.values() if "--" + entry["id"][:12] in a["name"]
                           and a["name"] not in META and a["size"] == entry.get("size")]
                if len(matches) == 1:
                    old = matches[0]
            if old and (old.get("digest") or "").startswith("sha256:") and entry.get("size") in (None, old["size"]):
                record = {"id": entry["id"], "filename": entry["filename"], "size": old["size"],
                          "sha256": old["digest"].removeprefix("sha256:"), "source": entry["sources"][0],
                          "archived_at": old["created_at"], "assets": [{"name": old["name"], "size": old["size"],
                          "sha256": old["digest"].removeprefix("sha256:")}]}
                records[entry["id"]] = record
                changed = True
        if not record:
            continue
        for part in record["assets"]:
            remote = assets.get(part["name"])
            if remote is None:
                matches = [a for a in assets.values() if a.get("digest") == "sha256:" + part["sha256"] and a["size"] == part["size"] and a["name"] not in META]
                if len(matches) == 1:
                    remote = matches[0]
            if remote is None:
                continue
            split = re.search(r"\.part-\d+$", part["name"])
            suffix = split[0] if split else ""
            desired = entry["asset_name"] + suffix
            if remote["name"] != desired or remote.get("label") not in ("", None):
                updated = client.api(f"repos/{client.repo}/releases/assets/{remote['id']}",
                                     {"name": desired, "label": ""}, "PATCH")
                assets.pop(remote["name"], None)
                assets[updated["name"]] = updated
                part["name"] = updated["name"]
                changed = True
    return changed


def release_body(repo, tag, records, failures):
    lines = [f"已归档 **{len(records)}** 个文件，本轮不可用 **{len(failures)}** 项。",
             "", "校验：checksums.sha256；来源与原目录：sources.json。", ""]
    dates = [date for record in records.values() if (date := build_date(record["filename"]))]
    if dates:
        lines += [f"最新固件 Build：**{display_build_date(max(dates))}**（北京时间，取自原文件名）。",
                  "文件按 Build 时间从新到旧排列；未标注时间的文件放在最后。", ""]
    lines += ["## 文件名对照", "",
              "| Build 时间（北京时间） | 原始中文名 / 原文件名 | 英文文件名 |" if dates else "| 原始中文名 / 原文件名 | 英文文件名 |",
              "| --- | --- | --- |" if dates else "| --- | --- |"]
    ordered = sorted(records.values(), key=lambda r: (r["filename"].casefold(), r["id"]))
    ordered.sort(key=lambda r: file_order_key(r["filename"]), reverse=True)
    for record in ordered:
        original = record["filename"].replace("|", "&#124;").replace("\n", " ")
        date = build_date(record["filename"])
        prefix = (display_build_date(date) if date else "未标注") + " | " if dates else ""
        for part in record["assets"]:
            link = f"https://github.com/{repo}/releases/download/{urllib.parse.quote(tag, safe='')}/{urllib.parse.quote(part['name'], safe='')}"
            lines.append(f"| {prefix}{original} | [{part['name']}]({link}) |")
    return "\n".join(lines)


def checkpoint(client, tag, records, failures, directory):
    save(directory / "sources.json", {"schema": 1, "updated_at": now(), "files": list(records.values())})
    save(directory / "failures.json", failures)
    lines = sorted(f"{part['sha256']}  {part['name']}\n" for record in records.values() for part in record["assets"])
    (directory / "checksums.sha256").write_text("".join(lines))
    for name in ("checksums.sha256", "failures.json", "sources.json"):
        client.upload(tag, directory / name, clobber=True)


def sync_group(client, tag, entries, work, snapshot=None):
    release = client.release(tag) if snapshot is None else snapshot.get(tag)
    assets = client.assets(release) if snapshot is None else {a["name"]: a for a in (release or {}).get("assets", [])}
    previous = client.read_asset(assets, "sources.json", {"files": []})
    previous_failures = client.read_asset(assets, "failures.json", []) if snapshot is not None else None
    records = {r["id"]: r for r in previous["files"]}
    renamed = repair_group_names(client, entries, records, assets)
    failures, added, unchanged = [], 0, 0
    for entry in entries:
        record = records.get(entry["id"])
        if record and complete_record(record, assets):
            unchanged += 1
            continue
        with tempfile.TemporaryDirectory(prefix="ikuai-file-", dir=work) as temp:
            directory = Path(temp)
            try:
                path, record = download(entry, directory)
                parts = split_file(path)
                if release is None:
                    release = client.ensure_release(tag)
                record["assets"] = []
                for part in parts:
                    part_sha, size = file_sha(part), part.stat().st_size
                    existing = assets.get(part.name)
                    if existing:
                        if existing["size"] != size or existing.get("digest") != "sha256:" + part_sha:
                            raise ValueError(f"同名 Release 文件内容冲突，保留原包: {part.name}")
                    else:
                        client.upload(tag, part)
                    record["assets"].append({"name": part.name, "size": size, "sha256": part_sha})
                records[entry["id"]] = record
                added += 1
                print(f"archived {tag}/{entry['asset_name']} ({record['size']})", flush=True)
                if added % 10 == 0:
                    checkpoint(client, tag, records, failures, work)
            except PublicationError:
                raise
            except Exception as exc:
                failures.append({"id": entry["id"], "filename": entry["filename"],
                                 "known_source": any(not s.get("inferred") for s in entry["sources"]),
                                 "error": str(exc), "kind": failure_kind(exc)})
                print(f"unavailable {tag}/{entry['asset_name']}: {exc}", flush=True)
    failures_changed = failures != previous_failures if snapshot is not None else bool(failures)
    if release and (added or renamed or failures_changed or not previous["files"]):
        checkpoint(client, tag, records, failures, work)
    if release:
        body = release_body(client.repo, tag, records, failures)
        title = release_title(tag, [{"name": r["filename"]} for r in records.values()])
        if body != release.get("body") or title != release.get("name") or is_prerelease(tag) != release.get("prerelease"):
            client.api(f"repos/{client.repo}/releases/{release['id']}",
                       {"body": body, "name": title, "prerelease": is_prerelease(tag)}, "PATCH")
    return {"tag": tag, "added": added, "unchanged": unchanged, "failures": failures,
            "archived": len(records), "bytes": sum(r["size"] for r in records.values())}


def group_priority(tag):
    order = {"enterprise": 4, "free": 3, "oem": 2, "hardware": 1, "resources": 0}
    return order[tag.split("-")[0]], tuple(map(int, re.findall(r"\d+", tag))), tag


def transfer_tag():
    run = os.environ.get("GITHUB_RUN_ID", "")
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    if not re.fullmatch(r"[0-9]+", run) or not re.fullmatch(r"[0-9]+", attempt):
        raise ValueError("临时清单必须绑定有效的 Actions run 和 attempt")
    return f"{TRANSFER_PREFIX}{run}-{attempt}"


def transfer_release(client):
    release_id = os.environ.get("TRANSFER_RELEASE_ID", "")
    if not re.fullmatch(r"[0-9]+", release_id):
        raise ValueError("缺少有效的临时 Release ID")
    release = client.api(f"repos/{client.repo}/releases/{release_id}")
    if not release or not release.get("draft") or release["tag_name"] != transfer_tag():
        raise ValueError("临时 Release 不属于本次运行，拒绝读写或删除")
    return release


def transfer_upload(client, release, path):
    payload = path.read_bytes()
    if len(payload) > 10 * 1024 * 1024:
        raise ValueError("临时通道仅允许最多 10 MiB 的 JSON 清单或报告")
    json.loads(payload)
    client.upload(release["tag_name"], path, clobber=True)
    expected = "sha256:" + hashlib.sha256(payload).hexdigest()
    for attempt in range(3):
        asset = client.assets(release).get(path.name)
        if asset and asset.get("state") == "uploaded" and asset.get("size") == len(payload) and asset.get("digest") == expected:
            return
        if attempt < 2:
            time.sleep(2)
    raise PublicationError(f"临时清单上传后校验失败: {path.name}")


def transfer_download(client, asset, path):
    proc = gh("api", asset["url"], "-H", "Accept: application/octet-stream")
    payload = proc.stdout.encode("utf-8")
    if asset.get("state") != "uploaded" or len(payload) != asset["size"] or asset.get("digest") != "sha256:" + hashlib.sha256(payload).hexdigest():
        raise PublicationError(f"临时清单下载校验失败: {asset['name']}")
    json.loads(payload)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def restore_inventory(args):
    client = GitHub(args.repo)
    release = client.release(INDEX_TAG)
    if release is None:
        print("首次同步，无历史清单")
        return False
    for attempt in range(4):
        try:
            asset = client.assets(release).get("catalog.json")
            if asset is None:
                raise PublicationError("历史清单暂不可用，可能正在更新")
            transfer_download(client, asset, Path(args.previous))
            print("历史清单已通过大小及 SHA256 校验")
            return False
        except (RuntimeError, ValueError, KeyError) as exc:
            if attempt == 3:
                raise PublicationError(f"无法恢复历史清单，停止以免丢失累积来源: {exc}") from exc
            print(f"历史清单读取失败，重新获取附件并重试 ({attempt + 1}/4)", flush=True)
            time.sleep(5 * (attempt + 1))


def stage_inventory(args):
    path = Path(args.catalog)
    catalog = json.loads(path.read_text())
    if not isinstance(catalog.get("files"), list) or not catalog["files"]:
        raise ValueError("扫描未生成有效清单，不能用旧清单静默替代")
    client = GitHub(args.repo)
    prune_transfer_drafts(client)
    release = client.api(f"repos/{client.repo}/releases", {
        "tag_name": transfer_tag(), "target_commitish": "main", "draft": True,
        "name": "Temporary Actions metadata", "body": json.dumps({"schema": "ikuai-workflow-transfer/v1", "created_at": now()}),
        "make_latest": "false",
    })
    # 即使上传失败，后续收尾也能定位本次创建的草稿。
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with Path(output).open("a") as handle:
            handle.write(f"release_id={release['id']}\n")
    transfer_upload(client, release, path)
    print(f"清单已发布到临时草稿 {release['id']}，共 {len(catalog['files'])} 项", flush=True)
    return False


def prune_transfer_drafts(client):
    stale, page = [], 1
    while True:
        releases = client.api(f"repos/{client.repo}/releases?per_page=100&page={page}")
        for release in releases:
            if not release.get("draft") or not re.fullmatch(r"mirror-run-\d+-\d+", release["tag_name"]):
                continue
            try:
                marker = json.loads(release.get("body") or "{}")
                created = datetime.fromisoformat(marker["created_at"])
                if marker.get("schema") == "ikuai-workflow-transfer/v1" and (datetime.now(timezone.utc) - created).total_seconds() > 86400:
                    stale.append(release["id"])
            except (ValueError, KeyError, TypeError):
                continue
        if len(releases) < 100:
            break
        page += 1
    for release_id in stale:
        client.api(f"repos/{client.repo}/releases/{release_id}", method="DELETE")
        print(f"已清理超过 1 天的临时草稿 {release_id}", flush=True)


def fetch_inventory(args):
    client = GitHub(args.repo)
    release = transfer_release(client)
    asset = client.assets(release).get(Path(args.catalog).name)
    if not asset:
        raise PublicationError("本轮临时清单不存在")
    transfer_download(client, asset, Path(args.catalog))
    return False


def stage_report(args):
    path = Path(args.report_dir) / f"shard-{args.shard}.json"
    if not path.exists():
        print(f"::warning::分片 {args.shard} 未生成报告，索引将标记未完成")
        return False
    client = GitHub(args.repo)
    transfer_upload(client, transfer_release(client), path)
    return False


def fetch_reports(args):
    client = GitHub(args.repo)
    assets = client.assets(transfer_release(client))
    for shard in range(args.shards):
        name = f"shard-{shard}.json"
        if name not in assets:
            print(f"::warning::本轮缺少分片报告 {shard}，不复用其他运行的报告")
            continue
        transfer_download(client, assets[name], Path(args.report_dir) / name)
    return False


def cleanup_transfer(args):
    client = GitHub(args.repo)
    release = transfer_release(client)
    client.api(f"repos/{client.repo}/releases/{release['id']}", method="DELETE")
    print(f"已删除本轮临时草稿 {release['id']}", flush=True)
    return False


def sync(args):
    if not 0 <= args.shard < args.shards:
        raise ValueError("非法 shard")
    client = GitHub(args.repo)
    catalog = json.loads(Path(args.catalog).read_text())
    snapshot = {r["tag_name"]: r for r in release_snapshot(client)}
    groups = defaultdict(list)
    for entry in catalog["files"]:
        if int(digest(entry["tag"])[:8], 16) % args.shards == args.shard:
            groups[entry["tag"]].append(entry)
    results = []
    work = ROOT / ".work" / f"worker-{args.shard}"
    work.mkdir(parents=True, exist_ok=True)
    try:
        for tag, entries in sorted(groups.items(), key=lambda pair: group_priority(pair[0]), reverse=True):
            result = sync_group(client, tag, entries, work, snapshot=snapshot)
            results.append(result)
            save(Path(args.report_dir) / f"shard-{args.shard}.json", results)
            print(json.dumps({k: v for k, v in result.items() if k != "failures"}), flush=True)
    finally:
        shutil.rmtree(work)
    return False


def coverage_totals(catalog, reports):
    expected = {entry["tag"] for entry in catalog["files"]}
    counts = Counter(r["tag"] for r in reports)
    completed = set(counts)
    failures = [failure for report in reports for failure in report["failures"]]
    totals = {"discovered_at": catalog["discovered_at"], "published_at": now(),
              "candidates": len(catalog["files"]), "release_groups": len(expected),
              "processed_groups": len(completed), "archived_files": sum(r["archived"] for r in reports),
              "archived_bytes": sum(r["bytes"] for r in reports),
              "missing_groups": sorted(expected - completed), "discovery_errors": catalog["discovery_errors"],
              "invalid_groups": sorted(tag for tag, count in counts.items() if tag not in expected or count != 1),
              "unavailable_files": len(failures),
              "unavailable_known_files": sum(bool(f.get("known_source")) for f in failures),
              "fatal_file_errors": sum(issue_kind(f) != "unavailable" for f in failures),
              "fatal_discovery_errors": sum(issue_kind(e) != "unavailable" for e in catalog["discovery_errors"])}
    fatal = bool(totals["missing_groups"] or totals["invalid_groups"] or totals["fatal_file_errors"] or totals["fatal_discovery_errors"])
    totals["sync_status"] = "error" if fatal else "warning" if failures or catalog["discovery_errors"] else "success"
    return totals


def publish(args):
    client = GitHub(args.repo)
    catalog_path = Path(args.catalog)
    catalog = json.loads(catalog_path.read_text())
    reports = [item for path in Path(args.report_dir).rglob("shard-*.json") for item in json.loads(path.read_text())]
    totals = coverage_totals(catalog, reports)
    with tempfile.TemporaryDirectory(prefix="ikuai-index-", dir=ROOT / ".work") as temp:
        directory = Path(temp)
        shutil.copyfile(catalog_path, directory / "catalog.json")
        save(directory / "status.json", totals)
        save(directory / "reports.json", reports)
        release = client.ensure_release(INDEX_TAG)
        for path in sorted(directory.iterdir()):
            client.upload(INDEX_TAG, path, clobber=True)
        body = ("爱快全量镜像总索引。\n\n"
                f"已发现 **{totals['candidates']}** 个候选文件；已归档 **{totals['archived_files']}** 个文件 "
                f"（{totals['archived_bytes'] / 1024**3:.2f} GiB）。\n\n"
                f"本轮不可用 **{totals['unavailable_files']}** 项，未完成分组 **{len(totals['missing_groups'])}**。\n\n"
                f"同步状态：**{totals['sync_status']}**。源站缺失会继续重试，不代表全量到齐；"
                f"文件处理错误 **{totals['fatal_file_errors']}** 项，扫描错误 **{totals['fatal_discovery_errors']}** 项。\n\n"
                "下载 `INDEX.md` 浏览分类与版本；`catalog.json` 是累积来源清单；"
                "`status.json` 是覆盖情况；`reports.json` 记录失败项。候选直链不代表实际可用。")
        client.api(f"repos/{client.repo}/releases/{release['id']}", {"body": body, "make_latest": "false"}, "PATCH")
    print(json.dumps(totals, ensure_ascii=False, indent=2))
    if totals["sync_status"] != "success":
        level = "error" if totals["sync_status"] == "error" else "warning"
        print(f"::{level}::覆盖报告：{totals['unavailable_files']} 个文件未归档，{len(totals['discovery_errors'])} 个来源缺口；详见 mirror-index 的 status.json / reports.json")
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(summary).open("a") as handle:
            handle.write(f"## 镜像同步：{totals['sync_status']}\n\n"
                         f"已归档 **{totals['archived_files']}** 个文件（{totals['archived_bytes'] / 1024**3:.2f} GiB）。\n\n"
                         f"本轮不可用 **{totals['unavailable_files']}** 项；来源缺口 **{len(totals['discovery_errors'])}** 项，后续自动重试。\n\n"
                         f"[完整覆盖报告](https://github.com/{client.repo}/releases/tag/{INDEX_TAG})。"
                         "源站不可用属于覆盖警告；校验、冲突、上传及缺失报告仍会使工作流失败。\n")
    refresh_categories(args)
    return totals["sync_status"] == "error"


def category_body(repo, releases):
    groups = defaultdict(list)
    for release in releases:
        tag = release["tag_name"]
        if release.get("draft") or tag in (INDEX_TAG, CATEGORY_TAG):
            continue
        category = release_kind(tag, release.get("assets", []))
        if category == "free":
            version = re.match(r"free-([234])\.", tag)
            category = "free-" + version[1] if version else "free-other"
        elif category == "resources":
            category = tag.rsplit("-", 1)[0]
        groups[category].append(release)
        if tag.startswith("enterprise-4.") and is_prerelease(tag):
            groups["enterprise-4-beta"].append(release)
    sections = [("free", "免费版"), ("free-2", "免费版 2.x"), ("free-3", "免费版 3.x"),
                ("free-4", "免费版 4.x"), ("free-other", "其他免费版"),
                ("enterprise", "企业版"), ("enterprise-4-beta", "企业版 4.x Beta"),
                ("oem", "OEM"), ("hardware", "硬件固件")]
    sections += [("resources-" + code, title) for title, code in CATEGORIES.items()]
    sections.append(("archive", "旧链接兼容（不作为版本下载入口）"))
    known = {slug for slug, _ in sections}
    sections += [(slug, "其他资料 · " + slug.removeprefix("resources-")) for slug in sorted(groups) if slug not in known]
    lines = ["# 按类型下载", "", "点击版本进入 Release，选择 x32 / x64 或所需格式。只列出已发布的分组，空分类仍在补齐。", ""]
    for slug, title in sections:
        lines += [f'<a name="{slug}"></a>', f"## {title}", ""]
        if slug == "free":
            lines += ["[2.x](#user-content-free-2) · [3.x](#user-content-free-3) · [4.x](#user-content-free-4) · [其他](#user-content-free-other)", ""]
            continue
        entries = sorted(groups[slug], key=lambda r: release_order_key(r["tag_name"], r.get("assets", [])), reverse=True)
        if not entries:
            lines += ["暂无已发布镜像。", ""]
            continue
        for release in entries:
            tag = release["tag_name"]
            title = (release.get("name") or tag).replace("|", "&#124;").replace("\n", " ")
            lines.append(f"- [{title}](https://github.com/{repo}/releases/tag/{urllib.parse.quote(tag, safe='')})")
        lines.append("")
    return "\n".join(lines)


def refresh_categories(args):
    client = GitHub(args.repo)
    releases = release_snapshot(client)
    release = client.ensure_release(CATEGORY_TAG)
    client.api(f"repos/{client.repo}/releases/{release['id']}",
               {"name": release_title(CATEGORY_TAG), "body": category_body(client.repo, releases)}, "PATCH")
    (ROOT / ".work").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ikuai-order-index-", dir=ROOT / ".work") as temp:
        path = Path(temp) / "INDEX.md"
        path.write_text(release_index_body(client.repo, releases))
        client.upload(INDEX_TAG, path, clobber=True)
    return False


def jitter(args):
    if os.environ.get("GITHUB_EVENT_NAME") != "schedule":
        return False
    delay = secrets.randbelow(1801)
    print(f"定时扫描随机延迟 {delay} 秒", flush=True)
    time.sleep(delay)
    return False


def runs_to_delete(runs, current_run=""):
    if not runs:
        return []
    newest = max(runs, key=lambda run: (run["created_at"], int(run["id"])))["id"]
    return [run["id"] for run in runs if run["id"] != newest
            and str(run["id"]) != str(current_run) and run["status"] == "completed"]


def prune_runs(args):
    client = GitHub(args.repo)
    runs, page = [], 1
    while True:
        result = client.api(f"repos/{client.repo}/actions/runs?per_page=100&page={page}")
        batch = result["workflow_runs"]
        runs.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    for run_id in runs_to_delete(runs, os.environ.get("GITHUB_RUN_ID", "")):
        client.api(f"repos/{client.repo}/actions/runs/{run_id}", method="DELETE")
        print(f"已清理旧 Actions 记录 {run_id}", flush=True)
    return False


def root_commit_needed(commit, current_time=None):
    date = datetime.fromisoformat(commit["committer"]["date"].replace("Z", "+00:00"))
    age = ((current_time or datetime.now(timezone.utc)) - date).days
    return bool(commit["parents"]) or age >= 50


def git_remote_env():
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        raise ValueError("维护 Git 历史需要 GH_TOKEN")
    env = os.environ.copy()
    # 认证只通过子进程环境传递，不落到配置文件或命令参数。
    position = int(env.get("GIT_CONFIG_COUNT", "0"))
    env["GIT_CONFIG_COUNT"] = str(position + 1)
    env[f"GIT_CONFIG_KEY_{position}"] = "http.https://github.com/.extraheader"
    encoded = base64.b64encode(("x-access-token:" + token).encode()).decode()
    env[f"GIT_CONFIG_VALUE_{position}"] = "AUTHORIZATION: basic " + encoded
    return env


def git_run(arguments, env, input_text=None):
    result = subprocess.run(["git", *arguments], cwd=ROOT, env=env, input=input_text,
                            capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(result.stderr.strip())
    return result.stdout.strip()


def build_date(value):
    match = re.search(r"Build(\d{12}|\d{8})(?!\d)", value)
    if not match:
        return None
    try:
        stamp = datetime.strptime(match[1], "%Y%m%d%H%M" if len(match[1]) == 12 else "%Y%m%d")
        return stamp.replace(tzinfo=timezone(timedelta(hours=8))).astimezone(timezone.utc).isoformat(timespec="seconds")
    except ValueError:
        return None


def display_build_date(date):
    return datetime.fromisoformat(date).astimezone(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M")


def file_order_key(name):
    version = re.search(r"(?:_sysupgrade_|_(?:x(?:32|64)_)?)[vV]?(\d+(?:\.\d+)+)", name)
    numbers = tuple(map(int, version[1].split("."))) if version else ()
    return build_date(name) or "", numbers, not bool(re.search(r"(?:^|_)beta(?:_|\.)", name, re.I))


def release_kind(tag, assets=()):
    if any(a["name"] == SPLIT_META for a in assets):
        return "archive"
    kind = tag.split("-", 1)[0]
    if kind == "resources":
        names = [re.sub(r"\.part-\d+$", "", a["name"]) for a in assets if a["name"] not in META]
        firmware = r"^(?:iKuai|oem|IK-|MT\d|MVL\d|IPQ\d).*(?:_Build\d|_sysupgrade_).*\.(?:bin|iso|img(?:\.gz)?|gho|patch)$"
        if names and all(re.search(firmware, name, re.I) for name in names):
            return "hardware"
    return kind


def release_sort_date(tag, assets=()):
    if release_kind(tag, assets) == "archive":
        return "1970-01-01T00:00:00+00:00"
    if tag == INDEX_TAG:
        return "1970-01-02T00:00:00+00:00"
    if tag == CATEGORY_TAG:
        return "1970-01-03T00:00:00+00:00"
    if release_kind(tag, assets) == "resources":
        return "1970-01-04T00:00:00+00:00"
    dates = [date for value in [tag, *(a["name"] for a in assets)] if (date := build_date(value))]
    # 占位日期仅用于排序：无日期固件仍在文档、工具和下载目录之前。
    return max(dates, default="1971-01-01T00:00:00+00:00")


def release_order_key(tag, assets=()):
    version = re.match(r"(?:free|enterprise|oem)-(\d+(?:\.\d+)+)", tag)
    numbers = tuple(map(int, version[1].split("."))) if version else ()
    if release_kind(tag, assets) == "hardware":
        numbers = max((file_order_key(a["name"])[1] for a in assets if a["name"] not in META), default=())
    priority = {"enterprise": 4, "free": 3, "oem": 2, "hardware": 1}.get(release_kind(tag, assets), 0)
    return release_sort_date(tag, assets), priority, numbers, not is_prerelease(tag), tag


def release_tag_dates(releases):
    canonical = {r["tag_name"]: release_order_key(r["tag_name"], r.get("assets", []))[:-1] for r in releases}
    mapped, previous = {}, None
    # GitHub 原生列表按天分桶，同日会改按标签名排序。不同 Build 或类型优先级
    # 分配不同排序日；相同时间的企业版不能被一批硬件标签挤到后面。
    for key in sorted(set(canonical.values())):
        stamp = datetime.fromisoformat(key[0])
        if previous is not None and stamp.date() <= previous:
            stamp += timedelta(days=(previous - stamp.date()).days + 1)
        previous = stamp.date()
        mapped[key] = stamp.isoformat(timespec="seconds")
    return {tag: mapped[key] for tag, key in canonical.items()}


def file_table_rows(body):
    rows = []
    for line in (body or "").splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) >= 2 and (match := re.match(r"\[([^]]+)\]\(https://github.com/", cells[-1])):
            rows.append({"asset": match[1], "filename": cells[-2],
                         "date": cells[0] if len(cells) == 3 else None})
    return rows


def presentation_records(release):
    originals = {row["asset"]: row["filename"] for row in file_table_rows(release.get("body"))}
    records = {}
    for asset in release.get("assets", []):
        if asset["name"] in META:
            continue
        name = originals.get(asset["name"], asset["name"])
        # 同名资料在不同目录下是不同文件，只有同一文件的分卷可以合并。
        key = digest(name + "\0" + re.sub(r"\.part-\d+$", "", asset["name"]))
        record = records.setdefault(key, {"id": key, "filename": name, "assets": []})
        record["assets"].append({"name": asset["name"]})
    return records


def release_snapshot(client):
    releases, page = [], 1
    while True:
        batch = client.api(f"repos/{client.repo}/releases?per_page=100&page={page}")
        releases.extend(r for r in batch if not r.get("draft"))
        if len(batch) < 100:
            break
        page += 1
    for release in releases:
        if len(release.get("assets", [])) >= 30:
            release["assets"] = list(client.assets(release).values())
    return releases


def release_index_body(repo, releases):
    entries = [r for r in releases if not r.get("draft") and r["tag_name"] not in (INDEX_TAG, CATEGORY_TAG)
               and release_kind(r["tag_name"], r.get("assets", [])) != "archive"]
    entries.sort(key=lambda r: release_order_key(r["tag_name"], r.get("assets", [])), reverse=True)
    lines = ["# iKuai 镜像下载索引", "", "只列出实际已归档的 Release，不使用未下载的候选文件推算排序。",
             "固件按文件名中的完整 Build 时间倒序；同时间依次为企业版、免费版、OEM、硬件。",
             "无日期固件随后，资料和工具最后。覆盖及失败情况见 status.json / reports.json，全库排序校验见 ordering-audit.json。",
             "", "| 最新 Build（北京时间） | Release | 文件 | 字节 |", "| --- | --- | ---: | ---: |"]
    for release in entries:
        tag = release["tag_name"]
        records = presentation_records(release)
        dates = [date for r in records.values() if (date := build_date(r["filename"]))]
        label = "资料 / 工具" if release_kind(tag, release.get("assets", [])) == "resources" else display_build_date(max(dates)) if dates else "未标注"
        size = sum(a.get("size", 0) for a in release.get("assets", []) if a["name"] not in META)
        title = (release.get("name") or tag).replace("|", "&#124;").replace("\n", " ")
        link = f"https://github.com/{repo}/releases/tag/{urllib.parse.quote(tag, safe='')}"
        lines.append(f"| {label} | [{title}]({link}) | {len(records)} | {size} |")
    return "\n".join(lines) + "\n"


def ordering_audit(repo, releases, index_text, category_text):
    published = [r for r in releases if not r.get("draft")]
    issues, files, assets, dated_tables = [], 0, 0, 0
    keys = [release_order_key(r["tag_name"], r.get("assets", []))[:-1] for r in published]
    for i in range(len(keys) - 1):
        if keys[i] < keys[i + 1]:
            issues.append({"kind": "release_order", "before": published[i]["tag_name"], "after": published[i + 1]["tag_name"]})
    downloads = [r for r in published if r["tag_name"] not in (INDEX_TAG, CATEGORY_TAG)
                 and release_kind(r["tag_name"], r.get("assets", [])) != "archive"]
    for release in downloads:
        tag = release["tag_name"]
        rows = file_table_rows(release.get("body"))
        remote = {a["name"]: a for a in release.get("assets", []) if a["name"] not in META}
        if Counter(row["asset"] for row in rows) != Counter(remote.keys()):
            issues.append({"kind": "file_table_coverage", "tag": tag})
        row_keys = [file_order_key(row["filename"]) for row in rows]
        if any(row_keys[i] < row_keys[i + 1] for i in range(len(row_keys) - 1)):
            issues.append({"kind": "file_table_order", "tag": tag})
        for row in rows:
            date = build_date(row["filename"])
            asset_date = build_date(row["asset"])
            if (date and row["date"] != display_build_date(date)) or (asset_date and date != asset_date):
                issues.append({"kind": "file_build_time", "tag": tag, "filename": row["filename"]})
        records = presentation_records(release)
        if release_kind(tag, release.get("assets", [])) == "hardware":
            groups = {group_for(row["filename"]) for row in rows if hardware_parts(row["filename"])}
            if groups != {tag}:
                issues.append({"kind": "hardware_version_grouping", "tag": tag, "expected_groups": sorted(groups)})
        expected_title = release_title(tag, [{"name": r["filename"]} for r in records.values()])
        if release.get("name") != expected_title:
            issues.append({"kind": "release_title", "tag": tag})
        files += len(records)
        assets += len(remote)
        dated_tables += any(build_date(row["filename"]) for row in rows)
    if index_text != release_index_body(repo, published):
        issues.append({"kind": "index_order_or_coverage"})
    if category_text != category_body(repo, published):
        issues.append({"kind": "category_order_or_coverage"})
    for release in downloads:
        link = f"https://github.com/{repo}/releases/tag/{urllib.parse.quote(release['tag_name'], safe='')}"
        if link not in (category_text or ""):
            issues.append({"kind": "category_missing_release", "tag": release["tag_name"]})
    return {"schema": 1, "checked_at": now(), "status": "error" if issues else "success",
            "releases": len(published), "download_releases": len(downloads),
            "firmware_releases": sum(release_kind(r["tag_name"], r.get("assets", [])) in ("free", "enterprise", "oem", "hardware") for r in downloads),
            "resource_releases": sum(release_kind(r["tag_name"], r.get("assets", [])) == "resources" for r in downloads),
            "files": files, "download_assets": assets, "dated_file_tables": dated_tables,
            "legacy_compat_releases": sum(release_kind(r["tag_name"], r.get("assets", [])) == "archive" for r in published),
            "issues": issues}


def audit_release_order(args):
    client = GitHub(args.repo)
    releases = release_snapshot(client)
    by_tag = {r["tag_name"]: r for r in releases}
    index = by_tag.get(INDEX_TAG, {})
    asset = next((a for a in index.get("assets", []) if a["name"] == "INDEX.md"), None)
    index_text = None
    if asset:
        index_text = gh("api", asset["url"], "-H", "Accept: application/octet-stream").stdout
        payload = index_text.encode()
        if len(payload) != asset["size"] or "sha256:" + hashlib.sha256(payload).hexdigest() != asset.get("digest"):
            raise PublicationError("总索引下载校验失败")
    report = ordering_audit(client.repo, releases, index_text, by_tag.get(CATEGORY_TAG, {}).get("body"))
    (ROOT / ".work").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ikuai-order-audit-", dir=ROOT / ".work") as temp:
        path = Path(temp) / "ordering-audit.json"
        save(path, report)
        client.upload(INDEX_TAG, path, clobber=True)
    print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(summary).open("a") as handle:
            handle.write(f"## 全库排序校验：{report['status']}\n\n"
                         f"检查 **{report['releases']}** 个 Release、**{report['files']}** 个文件、全部文件表格及两个索引。"
                         f"发现 **{len(report['issues'])}** 个问题。\n\n"
                         f"[校验报告](https://github.com/{client.repo}/releases/download/{INDEX_TAG}/ordering-audit.json)\n")
    if report["issues"]:
        raise PublicationError(f"全库排序校验失败，共 {len(report['issues'])} 项，不能只凭抽查宣告完成")
    return False


def dated_tag(client, tag, root, date, existing=None):
    endpoint = f"repos/{client.repo}/git/refs/tags/{urllib.parse.quote(tag, safe='')}"
    existing = existing or client.api(endpoint.replace("/git/refs/", "/git/ref/"))
    if date is None:
        if not existing or existing["object"]["sha"] != root:
            client.api(endpoint if existing else f"repos/{client.repo}/git/refs",
                       {"sha": root, "force": True} if existing else {"ref": "refs/tags/" + tag, "sha": root},
                       "PATCH" if existing else "POST")
        return
    if existing and existing["object"]["type"] == "tag":
        annotation = client.api(f"repos/{client.repo}/git/tags/{existing['object']['sha']}")
        old_date = datetime.fromisoformat(annotation["tagger"]["date"].replace("Z", "+00:00"))
        if annotation["object"]["sha"] == root and old_date == datetime.fromisoformat(date):
            return
    annotation = client.api(f"repos/{client.repo}/git/tags", {
        "tag": tag, "message": "Mirror ordering key, not a firmware timestamp. Exact firmware Build times are parsed from filenames and shown in the release body. Firmware first, resources and indexes last.",
        "object": root, "type": "commit", "tagger": {
            "name": "iKuai mirror", "email": "41898282+github-actions[bot]@users.noreply.github.com", "date": date,
        },
    })
    client.api(endpoint if existing else f"repos/{client.repo}/git/refs",
               {"sha": annotation["sha"], "force": True} if existing else {"ref": "refs/tags/" + tag, "sha": annotation["sha"]},
               "PATCH" if existing else "POST")


def push_dated_tags(client, root, dates):
    if not dates:
        return
    env = git_remote_env()
    git_run(["cat-file", "-e", root + "^{commit}"], env)
    refs = []
    for tag, date in dates.items():
        stamp = int(datetime.fromisoformat(date).timestamp())
        payload = (f"object {root}\ntype commit\ntag {tag}\n"
                   f"tagger iKuai mirror <41898282+github-actions[bot]@users.noreply.github.com> {stamp} +0000\n\n"
                   "Mirror ordering key only. Exact firmware Build time is shown in each Release.\n")
        sha = git_run(["mktag"], env, payload)
        refs.append(f"{sha}:refs/tags/{tag}")
    if client.api(f"repos/{client.repo}/git/ref/heads/main")["object"]["sha"] != root:
        raise PublicationError("main 已变化，禁止推送过期排序标签")
    # 一次原子 Git push 替代每个标签的查询、创建对象和修改引用三个 REST 请求。
    git_run(["push", "--atomic", "--force", f"https://github.com/{client.repo}.git", *refs], env)
    print(f"已通过一次 Git push 更新 {len(refs)} 个排序标签", flush=True)


def retarget_release_tags(client, root, dates_only=False, refresh_bodies=False, shard=0, shards=1):
    releases, page = [], 1
    while True:
        batch = client.api(f"repos/{client.repo}/releases?per_page=100&page={page}")
        releases.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    # 改标签日期会改变分页顺序，必须先取得完整快照。
    published = [release for release in releases if not release.get("draft")]
    if published and client.api(f"repos/{client.repo}/git/ref/heads/main")["object"]["sha"] != root:
        print("main 已有并发更新，停止调整标签，交由下一轮维护处理", flush=True)
        return
    for release in published:
        if len(release.get("assets", [])) >= 30 or release["tag_name"].startswith("hardware-") and "assets" not in release:
            release["assets"] = list(client.assets(release).values())
    dates = release_tag_dates(published)
    published.sort(key=lambda r: release_order_key(r["tag_name"], r.get("assets", [])), reverse=True)
    firmware, pending_dates, pending_updates = [], {}, []
    batch_git = bool(os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"))
    for index, release in enumerate(published):
        if int(digest(release["tag_name"])[:8], 16) % shards != shard:
            continue
        tag = release["tag_name"]
        assets = release.get("assets", [])
        current_date = release.get("created_at", "").replace("Z", "+00:00")
        updates = {}
        if not dates_only or current_date != dates[tag]:
            if batch_git:
                pending_dates[tag] = dates[tag]
                # Git push 不刷新 Release 缓存；显式绑定同一标签后列表才使用新日期。
                updates["tag_name"] = tag
            else:
                dated_tag(client, tag, root, dates[tag])
        is_firmware = release_kind(tag, assets) in ("free", "enterprise", "oem", "hardware")
        if refresh_bodies and tag not in (INDEX_TAG, CATEGORY_TAG) and release_kind(tag, assets) != "archive":
            records = presentation_records(release)
            failed = re.search(r"本轮不可用 \*\*(\d+)\*\*", release.get("body") or "")
            failures = [None] * int(failed[1]) if failed else []
            body = release_body(client.repo, tag, records, failures)
            title = release_title(tag, [{"name": r["filename"]} for r in records.values()])
            if body != release.get("body") or title != release.get("name"):
                updates.update({"body": body, "name": title})
        if updates:
            pending_updates.append((release, updates))
        if is_firmware and not release.get("prerelease"):
            firmware.append((release_order_key(tag, assets), release["id"]))
        if (index + 1) % 25 == 0:
            print(f"排序与说明已处理 {index + 1}/{len(published)} 个 Release", flush=True)
    if batch_git:
        push_dated_tags(client, root, pending_dates)
    for index, (release, updates) in enumerate(pending_updates, 1):
        client.api(f"repos/{client.repo}/releases/{release['id']}", updates, "PATCH")
        if index % 25 == 0 or index == len(pending_updates):
            print(f"已刷新 {index}/{len(pending_updates)} 个变更 Release 的列表日期及说明", flush=True)
    if firmware and shards == 1:
        latest_id = max(firmware)[1]
        client.api(f"repos/{client.repo}/releases/{latest_id}", {"make_latest": "true"}, "PATCH")


def refresh_release_order(args):
    client = GitHub(args.repo)
    root = client.api(f"repos/{client.repo}/git/ref/heads/main")["object"]["sha"]
    retarget_release_tags(client, root, dates_only=True, refresh_bodies=True)
    refresh_categories(args)
    return audit_release_order(args)


def sort_release_shard(args):
    if not 0 <= args.shard < args.shards:
        raise ValueError("非法排序分片")
    client = GitHub(args.repo)
    root = client.api(f"repos/{client.repo}/git/ref/heads/main")["object"]["sha"]
    retarget_release_tags(client, root, dates_only=True, refresh_bodies=True, shard=args.shard, shards=args.shards)
    return False


def plan_hardware_split(args):
    client = GitHub(args.repo)
    releases = release_snapshot(client)
    index = next(r for r in releases if r["tag_name"] == INDEX_TAG)
    index_assets = {a["name"]: a for a in index["assets"]}
    catalog = client.read_asset(index_assets, "catalog.json", None)
    reports = client.read_asset(index_assets, "reports.json", None)
    if not catalog or not reports:
        raise PublicationError("拆分前必须取得累积来源清单和覆盖报告")
    plan, signatures, owners = [], {}, {}
    existing_targets = {}
    for release in releases:
        remote = {a["name"]: a for a in release.get("assets", [])}
        binaries = [a for a in remote.values() if a["name"] not in META]
        if not binaries or not all(hardware_parts(a["name"]) for a in binaries):
            continue
        if all(group_for(a["name"]) == release["tag_name"] for a in binaries):
            existing_targets[release["tag_name"]] = {
                key: release[key] for key in ("id", "tag_name", "name", "body") if key in release}
            existing_targets[release["tag_name"]]["assets"] = [
                {key: a[key] for key in ("id", "name", "size", "digest", "url", "state", "browser_download_url") if key in a}
                for a in release["assets"]]
            continue
        previous = client.read_asset(remote, "sources.json", {"files": []})
        records = previous["files"]
        if {p["name"] for r in records for p in r["assets"]} != {a["name"] for a in binaries}:
            raise PublicationError(f"旧分组清单与附件不一致: {release['tag_name']}")
        for record in records:
            if not hardware_parts(record["filename"]) or not complete_record(record, remote):
                raise PublicationError(f"旧包校验失败，禁止迁移: {release['tag_name']}/{record['filename']}")
            target = group_for(record["filename"])
            signature = hardware_parts(record["filename"])
            if target in signatures and signatures[target] != signature:
                raise PublicationError(f"版本标签冲突: {target}")
            if target in owners and owners[target] != release["tag_name"]:
                raise PublicationError(f"多个旧分组指向同一目标，请先合并迁移计划: {target}")
            signatures[target] = signature
            owners[target] = release["tag_name"]
        plan.append({"legacy_tag": release["tag_name"], "legacy_release_id": release["id"],
                     "records": records, "model": hardware_parts(records[0]["filename"])[0]})
    by_tag = {r["tag_name"]: r for r in releases}
    for tag in signatures:
        if tag not in by_tag:
            continue
        release = by_tag[tag]
        if any(a["name"] not in META and group_for(a["name"]) != tag for a in release["assets"]):
            raise PublicationError(f"目标 Release 含有其他版本附件: {tag}")
        existing_targets[tag] = {key: release[key] for key in ("id", "tag_name", "name", "body") if key in release}
        existing_targets[tag]["assets"] = [{key: a[key] for key in ("id", "name", "size", "digest", "url", "state", "browser_download_url") if key in a}
                                            for a in release["assets"]]
    plan.sort(key=lambda r: (not r["model"].endswith("-Q3S"), r["legacy_tag"]))
    inventory = {"purpose": "ikuai-hardware-split/v1", "created_at": now(), "shards": args.shards,
                 "files": plan, "catalog": catalog, "previous_reports": reports, "existing_targets": existing_targets}
    save(args.catalog, inventory)
    print(json.dumps({"legacy_models": len(plan), "files": sum(len(r["records"]) for r in plan),
                      "version_releases": len(signatures), "bytes": sum(f["size"] for r in plan for f in r["records"])}, indent=2), flush=True)
    return False


def split_inventory(args):
    plan = json.loads(Path(args.catalog).read_text())
    if plan.get("purpose") != "ikuai-hardware-split/v1" or plan.get("shards") != args.shards:
        raise ValueError("拆分清单类型或分片数量不匹配")
    return plan


def upload_rate_delay(error):
    if not isinstance(error, urllib.error.HTTPError) or error.code not in (403, 429):
        return None
    headers = error.headers or {}
    retry = headers.get("Retry-After", "")
    reset = headers.get("X-RateLimit-Reset", "")
    if headers.get("X-RateLimit-Remaining") == "0" and reset.isdigit():
        return max(1, int(reset) - int(time.time()) + 1)
    if retry.isdigit():
        return max(1, int(retry))
    message = error.read(8192).decode("utf-8", errors="replace").lower()
    if error.code == 429 or "rate limit" in message or "abuse detection" in message:
        return 60
    return None


def upload_split_asset(client, release, path, assets, clobber=False):
    expected = "sha256:" + file_sha(path)
    existing = assets.get(path.name)
    if existing:
        if existing.get("digest") == expected and existing["size"] == path.stat().st_size:
            return
        if not clobber:
            raise PublicationError(f"禁止覆盖固件附件: {release['tag_name']}/{path.name}")
        client.api(f"repos/{client.repo}/releases/assets/{existing['id']}", method="DELETE")
        assets.pop(path.name)
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        raise PublicationError("上传迁移附件需要仓库 token")
    url = f"https://uploads.github.com/repos/{client.repo}/releases/{release['id']}/assets?name={urllib.parse.quote(path.name, safe='')}"
    for attempt in range(4):
        try:
            # Content-Length 配合文件流上传，不将全库或整个文件读入内存。
            with path.open("rb") as payload:
                req = urllib.request.Request(url, data=payload, method="POST", headers={
                    "Authorization": "Bearer " + token, "Content-Type": "application/octet-stream",
                    "Content-Length": str(path.stat().st_size), "User-Agent": "ikuai-release-migration/1.0",
                })
                with urllib.request.urlopen(req, timeout=300) as response:
                    asset = json.load(response)
            assets[path.name] = asset
            if asset.get("digest") == expected and asset.get("size") == path.stat().st_size:
                return
            raise PublicationError("迁移附件上传响应的 SHA256/大小不一致")
        except (OSError, PublicationError) as exc:
            delay = upload_rate_delay(exc)
            if delay is not None:
                print(f"GitHub 附件上传限流，{delay} 秒后重新校验并重试", flush=True)
                time.sleep(delay)
            # 超时可能已上传完成，重新读取后验证，不能盲目覆盖或重复创建。
            assets.update(client.assets(release))
            uploaded = assets.get(path.name)
            if uploaded and uploaded.get("digest") == expected and uploaded["size"] == path.stat().st_size:
                return
            if attempt == 3 or isinstance(exc, urllib.error.HTTPError) and exc.code in (401, 403, 422) and delay is None:
                raise PublicationError(f"迁移附件上传失败: {release['tag_name']}/{path.name}: {exc}") from exc
            if delay is None:
                time.sleep(10 * (attempt + 1))


def copy_hardware_part(client, legacy_tag, release, part, assets, work):
    target = release["tag_name"]
    existing = assets.get(part["name"])
    if existing:
        if existing.get("digest") != "sha256:" + part["sha256"] or existing["size"] != part["size"]:
            raise PublicationError(f"目标存在同名不同内容，保留原文件: {target}/{part['name']}")
        return
    if Path(part["name"]).name != part["name"]:
        raise ValueError("非法附件路径")
    url = (f"https://github.com/{client.repo}/releases/download/{urllib.parse.quote(legacy_tag, safe='')}/"
           f"{urllib.parse.quote(part['name'], safe='')}?mirror_split={secrets.token_hex(8)}")
    with tempfile.TemporaryDirectory(prefix="ikuai-split-file-", dir=work) as temp:
        path = Path(temp) / part["name"]
        sha, size = hashlib.sha256(), 0
        with request(url, attempts=2, timeout=60) as response, path.open("wb") as output:
            while chunk := response.read1(256 * 1024):
                output.write(chunk)
                sha.update(chunk)
                size += len(chunk)
                if size > part["size"]:
                    raise PublicationError("旧附件下载超出预期大小")
        if size != part["size"] or sha.hexdigest() != part["sha256"]:
            raise PublicationError(f"迁移下载 SHA256/大小不一致: {legacy_tag}/{part['name']}")
        upload_split_asset(client, release, path, assets)


def migrate_legacy_hardware(client, item, work, existing_targets=None):
    existing_targets = existing_targets if existing_targets is not None else {}
    legacy = client.release(item["legacy_tag"])
    if not legacy or legacy["id"] != item["legacy_release_id"]:
        raise PublicationError("旧 Release 与本次拆分计划不匹配")
    targets = set()
    ordered = sorted(item["records"], key=lambda r: file_order_key(r["filename"]), reverse=True)
    for old in ordered:
        tag = group_for(old["filename"])
        targets.add(tag)
        release = existing_targets.get(tag)
        if release is None:
            release = client.api(f"repos/{client.repo}/releases", {
                "tag_name": tag, "target_commitish": "main", "draft": False, "make_latest": "false",
                "prerelease": is_prerelease(tag), "name": release_title(tag, [{"name": old["filename"]}]),
                "body": "正在迁移并校验本版本的固件附件；完成后将显示下载表及校验文件。",
            })
            existing_targets[tag] = release
        assets = {a["name"]: a for a in release.get("assets", [])}
        previous = client.read_asset(assets, "sources.json", {"files": []})
        records = {r["id"]: r for r in previous["files"]}
        record_id = digest(tag + "/" + old["filename"])
        existing = records.get(record_id)
        if existing and complete_record(existing, assets) and complete_record(old, assets):
            if existing["sha256"] != old["sha256"] or existing["size"] != old["size"]:
                raise PublicationError(f"目标来源记录冲突: {tag}")
        else:
            for part in old["assets"]:
                copy_hardware_part(client, item["legacy_tag"], release, part, assets, work)
            record = {**old, "id": record_id, "split_migrated_at": now(),
                      "migrated_from": {"tag": item["legacy_tag"], "release_id": item["legacy_release_id"]}}
            for attempt in range(3):
                if complete_record(record, assets):
                    break
                if attempt == 2:
                    raise PublicationError(f"目标附件上传后校验失败: {tag}")
                time.sleep(2)
                assets.update(client.assets(release))
            records[record_id] = record
            with tempfile.TemporaryDirectory(prefix="ikuai-split-meta-", dir=work) as temp:
                directory = Path(temp)
                save(directory / "sources.json", {"schema": 1, "updated_at": now(), "files": list(records.values())})
                save(directory / "failures.json", [])
                (directory / "checksums.sha256").write_text("".join(sorted(
                    f"{p['sha256']}  {p['name']}\n" for r in records.values() for p in r["assets"])))
                for path in sorted(directory.iterdir()):
                    upload_split_asset(client, release, path, assets, clobber=True)
        release["assets"] = list(assets.values())
        body = release_body(client.repo, tag, records, [])
        title = release_title(tag, [{"name": r["filename"]} for r in records.values()])
        if body != release.get("body") or title != release.get("name"):
            client.api(f"repos/{client.repo}/releases/{release['id']}",
                       {"body": body, "name": title, "prerelease": is_prerelease(tag)}, "PATCH")
        print(f"verified split {tag}/{old['filename']}", flush=True)
    marker = {"schema": "ikuai-hardware-split/v1", "legacy_tag": item["legacy_tag"],
              "targets": sorted(targets), "files": len(ordered), "completed_at": now()}
    with tempfile.TemporaryDirectory(prefix="ikuai-split-marker-", dir=work) as temp:
        path = Path(temp) / SPLIT_META
        save(path, marker)
        client.upload(item["legacy_tag"], path, clobber=True)
    lines = ["本型号已按 **型号＋版本＋Build** 拆成独立 Release。", "",
             "此页仅保留旧下载链接兼容，不作为版本发布入口，不参与固件版本排序或重复统计。", "", "## 独立版本", ""]
    for old in ordered:
        tag = group_for(old["filename"])
        date = build_date(old["filename"])
        label = (display_build_date(date) + " · " if date else "") + hardware_parts(old["filename"])[1]
        lines.append(f"- [{label}](https://github.com/{client.repo}/releases/tag/{urllib.parse.quote(tag, safe='')})")
    client.api(f"repos/{client.repo}/releases/{legacy['id']}",
               {"name": "旧链接兼容 · " + item["model"], "body": "\n".join(lines)}, "PATCH")
    return {"legacy_tag": item["legacy_tag"], "files": len(ordered), "targets": sorted(targets),
            "bytes": sum(r["size"] for r in ordered)}


def migrate_hardware(args):
    plan = split_inventory(args)
    if not 0 <= args.shard < args.shards:
        raise ValueError("非法迁移分片")
    client = GitHub(args.repo)
    work = ROOT / ".work" / f"hardware-split-{args.shard}"
    work.mkdir(parents=True, exist_ok=True)
    results = []
    try:
        for item in plan["files"]:
            if int(digest(item["legacy_tag"])[:8], 16) % args.shards != args.shard:
                continue
            results.append(migrate_legacy_hardware(client, item, work, plan.get("existing_targets", {})))
            save(Path(args.report_dir) / f"shard-{args.shard}.json", results)
    finally:
        shutil.rmtree(work)
    return False


def finish_hardware_split(args):
    plan = split_inventory(args)
    reports = [item for path in Path(args.report_dir).glob("shard-*.json") for item in json.loads(path.read_text())]
    expected = {item["legacy_tag"]: item for item in plan["files"]}
    counts = Counter(r["legacy_tag"] for r in reports)
    if set(counts) != set(expected) or any(count != 1 for count in counts.values()):
        raise PublicationError("拆分分片报告不完整或重复，禁止宣告全部迁移完成")
    client = GitHub(args.repo)
    releases = release_snapshot(client)
    by_tag = {r["tag_name"]: r for r in releases}
    for report in reports:
        item = expected[report["legacy_tag"]]
        if report["files"] != len(item["records"]) or release_kind(item["legacy_tag"], by_tag[item["legacy_tag"]]["assets"]) != "archive":
            raise PublicationError("拆分完成标记或文件数量不一致")
        for record in item["records"]:
            tag = group_for(record["filename"])
            if tag not in by_tag or not complete_record(record, {a["name"]: a for a in by_tag[tag]["assets"]}):
                raise PublicationError(f"最终全量附件校验失败: {tag}")
    catalog = {**plan["catalog"], "files": merge_candidates(plan["catalog"]["files"]), "hardware_split_at": now()}
    groups = defaultdict(list)
    for entry in catalog["files"]:
        groups[entry["tag"]].append(entry)
    old_failures = {f["filename"]: f for r in plan["previous_reports"] for f in r["failures"]}
    rebuilt = []
    for tag, entries in groups.items():
        release = by_tag.get(tag, {"assets": []})
        records = presentation_records(release)
        names = {r["filename"] for r in records.values()}
        failures = []
        for entry in entries:
            if entry["filename"] not in names:
                old = old_failures.get(entry["filename"], {"error": "迁移后缺少文件", "kind": "error"})
                failures.append({**old, "id": entry["id"], "filename": entry["filename"]})
        rebuilt.append({"tag": tag, "archived": len(records), "bytes": sum(a["size"] for a in release["assets"] if a["name"] not in META),
                        "added": 0, "unchanged": len(records), "failures": failures})
    with tempfile.TemporaryDirectory(prefix="ikuai-split-finish-", dir=ROOT / ".work") as temp:
        directory = Path(temp)
        save(directory / "catalog.json", catalog)
        save(directory / "reports" / "shard-0.json", rebuilt)
        final_args = argparse.Namespace(repo=args.repo, catalog=str(directory / "catalog.json"), report_dir=str(directory / "reports"))
        if publish(final_args):
            raise PublicationError("拆分后的累积覆盖报告包含新的硬错误")
    return refresh_release_order(args)


def compact_history(args):
    client = GitHub(args.repo)
    remote = f"https://github.com/{client.repo}.git"
    for attempt in range(3):
        head = client.api(f"repos/{client.repo}/git/ref/heads/main")["object"]["sha"]
        commit = client.api(f"repos/{client.repo}/git/commits/{head}")
        root = head
        if root_commit_needed(commit):
            env = git_remote_env()
            for role in ("AUTHOR", "COMMITTER"):
                env[f"GIT_{role}_NAME"] = commit["author"]["name"]
                env[f"GIT_{role}_EMAIL"] = commit["author"]["email"]
            git_run(["fetch", "--no-tags", "--depth=1", remote, head], env)
            root = git_run(["commit-tree", commit["tree"]["sha"]], env,
                           "chore: maintain iKuai release mirror [skip actions]\n")
            try:
                git_run(["push", f"--force-with-lease=refs/heads/main:{head}",
                         remote, f"{root}:refs/heads/main"], env)
            except RuntimeError as exc:
                if attempt < 2 and any(term in str(exc).lower() for term in ("stale info", "[rejected]", "fetch first")):
                    continue
                raise
            print(f"main 已维护为单个根提交 {root}", flush=True)
        retarget_release_tags(client, root, dates_only=True, refresh_bodies=True)
        return False
    raise RuntimeError("main 持续并发更新，本轮未压缩")


def maintain(args):
    compact_history(args)
    refresh_categories(args)
    audit_release_order(args)
    return prune_runs(args)


def repair_names(args):
    client = GitHub(args.repo)
    catalog = json.loads(Path(args.catalog).read_text())
    entries = merge_candidates(catalog["files"])
    groups = defaultdict(list)
    for entry in entries:
        groups[entry["tag"]].append(entry)
    (ROOT / ".work").mkdir(exist_ok=True)
    page = 1
    while True:
        releases = client.api(f"repos/{client.repo}/releases?per_page=100&page={page}")
        for release in releases:
            tag = release["tag_name"]
            if tag not in groups or (args.tag and tag not in args.tag):
                continue
            assets = client.assets(release)
            previous = client.read_asset(assets, "sources.json", {"files": []})
            failures = client.read_asset(assets, "failures.json", [])
            records = {r["id"]: r for r in previous["files"]}
            if repair_group_names(client, groups[tag], records, assets):
                with tempfile.TemporaryDirectory(prefix="ikuai-rename-", dir=ROOT / ".work") as temp:
                    checkpoint(client, tag, records, failures, Path(temp))
                print(f"repaired {tag}: {len(records)} files", flush=True)
            client.api(f"repos/{client.repo}/releases/{release['id']}",
                       {"body": release_body(client.repo, tag, records, failures),
                        "name": release_title(tag, [{"name": r["filename"]} for r in records.values()]),
                        "prerelease": is_prerelease(tag)}, "PATCH")
        if len(releases) < 100:
            break
        page += 1
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["discover", "sync", "publish", "maintain", "prune-runs", "compact-history", "repair-names", "jitter", "refresh-categories", "refresh-release-order", "audit-order", "plan-hardware-split", "migrate-hardware", "finish-hardware-split", "sort-release-shard", "restore-inventory", "stage-inventory", "fetch-inventory", "stage-report", "fetch-reports", "cleanup-transfer"])
    parser.add_argument("--catalog", default=".work/catalog.json")
    parser.add_argument("--previous")
    parser.add_argument("--tag", action="append", default=[])
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", "LOVECHEN/ikuai-release"))
    parser.add_argument("--shard", type=int, default=0)
    parser.add_argument("--shards", type=int, default=1)
    parser.add_argument("--report-dir", default=".work/reports")
    args = parser.parse_args()
    commands = {"discover": discover, "sync": sync, "publish": publish, "maintain": maintain,
                "prune-runs": prune_runs, "compact-history": compact_history,
                "repair-names": repair_names, "jitter": jitter, "refresh-categories": refresh_categories,
                "refresh-release-order": refresh_release_order,
                "audit-order": audit_release_order,
                "plan-hardware-split": plan_hardware_split, "migrate-hardware": migrate_hardware,
                "finish-hardware-split": finish_hardware_split, "sort-release-shard": sort_release_shard,
                "restore-inventory": restore_inventory, "stage-inventory": stage_inventory, "fetch-inventory": fetch_inventory,
                "stage-report": stage_report, "fetch-reports": fetch_reports, "cleanup-transfer": cleanup_transfer}
    raise SystemExit(int(commands[args.command](args)))


if __name__ == "__main__":
    main()
