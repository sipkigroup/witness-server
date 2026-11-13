"""0.2.17 (R9-06): the documents moved to docs/internal in 0.2.16. Every relative markdown link of the living documents resolves, and no code,
test or living document still names a moved document by its old path (historical reports, task texts and reviews keep theirs)."""
import os
import re

CLOUD = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", ".."))
WITNESS = os.path.dirname(CLOUD)
HISTORY = re.compile(r"(^|/)(OTCHET[^/]*|CHANGELOG\.md|ZADANI[^/]*|review[0-9]*|node_modules|\.[^/]+|__pycache__|dist|fixtures)(/|$)")
MOVED = ("api.md", "approvals.md", "coverage.md", "dlp.md")


def _files(exts):
    for top in (CLOUD, os.path.join(WITNESS, "spec")):
        for root, dirs, files in os.walk(top):
            rel = os.path.relpath(root, WITNESS)
            dirs[:] = [d for d in dirs if not HISTORY.search(rel + "/" + d)]
            for f in files:
                if f.endswith(exts) and not HISTORY.search(rel + "/" + f):
                    yield os.path.join(root, f)


def _published_page(src, target):
    """cloud/docs/*.md are the sources of the public pages (build_html.py -> web/dl/docs/*.html); a link to NAME.html is valid when that page exists."""
    if os.path.dirname(src) != os.path.join(CLOUD, "docs") or not target.endswith(".html") or "/" in target:
        return False
    return os.path.exists(os.path.join(CLOUD, "web", "dl", "docs", target))


def test_relative_markdown_links_resolve():
    bad = []
    for p in _files((".md",)):
        for m in re.finditer(r"\]\(([^)\s#]+)(#[^)]*)?\)", open(p, encoding="utf-8", errors="replace").read()):
            t = m.group(1)
            if re.match(r"[a-z]+:", t) or t.startswith("/"):
                continue
            if not os.path.exists(os.path.normpath(os.path.join(os.path.dirname(p), t))) and not _published_page(p, t):
                bad.append((os.path.relpath(p, WITNESS), t))
    assert not bad, bad


def test_no_old_path_of_a_moved_document():
    old = re.compile(r"(?<![\w/])(cloud/)?docs/(%s)" % "|".join(re.escape(m) for m in MOVED))
    bad = []
    for p in _files((".md", ".py", ".js", ".mjs", ".html", ".sh", ".ts", ".toml")):
        for i, line in enumerate(open(p, encoding="utf-8", errors="replace"), 1):
            if old.search(line) and "0.2.16" not in line:
                bad.append("%s:%d" % (os.path.relpath(p, WITNESS), i))
    assert not bad, bad
    for m in MOVED:
        assert os.path.exists(os.path.join(CLOUD, "docs", "internal", m)) and not os.path.exists(os.path.join(CLOUD, "docs", m))
