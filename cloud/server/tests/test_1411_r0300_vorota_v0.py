"""r0300 (prepared, not released; deploy/VERSION stays 0.2.122): gate В0 of vorota/vorota.sh takes the BRANCH's prediction first.

Before r0300 В0 took vorota/predskazanie-<date>-<class>.md, the day's common file, even when another branch wrote it (r0299, report p.4).
Now: VOROTA_PREDSKAZANIE if set; else predskazanie-<date>-<class>-<branch>.md (branch = `git branch --show-current`); else the common file.
The В0 row says which file was taken and why. The script runs on a COPY in a temporary git repository (its report and logs stay there),
with a lock of its own (a gate run of this tree holds the shared lock while it runs this test)."""
import os
import shutil
import subprocess
import time

import pytest

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "vorota", "vorota.sh")


def _repo(tmp_path, branch="r9999"):
    root = tmp_path / "tree"
    (root / "vorota").mkdir(parents=True)
    shutil.copy(SRC, root / "vorota" / "vorota.sh")
    g = ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"]
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(g + ["checkout", "-q", "-b", branch], check=True)
    subprocess.run(g + ["add", "-A"], check=True)
    subprocess.run(g + ["commit", "-q", "-m", "x"], check=True)
    return root


def _run(root, tmp_path, env_extra=None):
    env = dict(os.environ, VOROTA_LOCK=str(tmp_path / "lock"), VOROTA_LOGS=str(tmp_path / "logs"), PY="python3")
    env.pop("VOROTA_PREDSKAZANIE", None)
    env.update(env_extra or {})
    r = subprocess.run(["bash", str(root / "vorota" / "vorota.sh"), "М", "V0"], env=env, capture_output=True, text=True, timeout=60)
    day = time.strftime("%Y-%m-%d")
    rep = (root / "vorota" / "otchety" / ("%s-M.md" % day)).read_text()
    row = next(l for l in rep.splitlines() if l.startswith("| В0 "))
    return r.returncode, row


def _pred(root, name):
    p = root / "vorota" / name
    p.write_text("предсказание\n")
    return p


def test_branch_file_wins_over_the_common_one(tmp_path):
    root = _repo(tmp_path)
    day = time.strftime("%Y-%m-%d")
    _pred(root, "predskazanie-%s-M.md" % day)                 # another branch's common file of the day
    _pred(root, "predskazanie-%s-M-r9999.md" % day)
    rc, row = _run(root, tmp_path)
    # before r0300: "| В0 | предсказание | ОК | predskazanie-<day>-M.md, 1 строк ..." (the common file)
    assert rc == 0, row
    assert "взят predskazanie-%s-M-r9999.md (файл ветки r9999)" % day in row, row


def test_no_branch_file_falls_back_to_the_common_one_and_says_so(tmp_path):
    root = _repo(tmp_path)
    day = time.strftime("%Y-%m-%d")
    _pred(root, "predskazanie-%s-M.md" % day)
    _pred(root, "predskazanie-%s-M-r0001.md" % day)           # another branch's own file is never taken
    rc, row = _run(root, tmp_path)
    assert rc == 0, row
    assert "взят predskazanie-%s-M.md (общий файл дня, файла ветки r9999 нет)" % day in row, row


def test_an_empty_branch_file_is_no_prediction(tmp_path):
    root = _repo(tmp_path)
    day = time.strftime("%Y-%m-%d")
    (root / "vorota" / ("predskazanie-%s-M-r9999.md" % day)).write_text("")
    rc, row = _run(root, tmp_path)
    assert rc == 1 and "БЛОКЕР" in row and "файла ветки r9999 нет" in row, row


def test_neither_file_is_a_blocker(tmp_path):
    root = _repo(tmp_path)
    rc, row = _run(root, tmp_path)
    assert rc == 1 and "БЛОКЕР" in row and "нет файла предсказания" in row, row


def test_the_variable_still_comes_first(tmp_path):
    root = _repo(tmp_path)
    day = time.strftime("%Y-%m-%d")
    _pred(root, "predskazanie-%s-M-r9999.md" % day)
    p = _pred(root, "moe.md")
    rc, row = _run(root, tmp_path, {"VOROTA_PREDSKAZANIE": str(p)})
    assert rc == 0 and "взят moe.md (задан VOROTA_PREDSKAZANIE)" in row, row


def test_a_branch_with_a_slash(tmp_path):
    root = _repo(tmp_path, branch="feat/x")
    day = time.strftime("%Y-%m-%d")
    _pred(root, "predskazanie-%s-M-feat_x.md" % day)
    rc, row = _run(root, tmp_path)
    assert rc == 0 and "взят predskazanie-%s-M-feat_x.md (файл ветки feat/x)" % day in row, row
