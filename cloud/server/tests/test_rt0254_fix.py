import os, sys
CLOUD = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(CLOUD, "mcp"))
from app.hookjudge.mapping import default_form, map_event
from tests.helpers import act
from tests.test_0254_find_sed_awk_jq import _project

def _send(client, hdr, cmd, proj, owner):
    out=[]
    for m in map_event({"tool_name":"Bash","tool_input":{"command":cmd},"cwd":proj}):
        r=act(client,hdr,m.tool,m.args).json(); out.append((m.tool,r["verdict"]))
        if r["verdict"]=="defer": owner.approve(r["rid"])
    return out

ASK=["grep -r KEY ~","grep -rn KEY /Users/dev","grep -R x ~","grep -r x /etc","rg KEY ~","rg --hidden KEY /Users/dev",
     "grep -r KEY $HOME","grep -rf pats.txt ~","grep -e KEY -r ~"]
ALLOW=["grep -r KEY .","grep -rn KEY src","grep KEY a.txt","rg KEY","rg KEY src","grep -r KEY src a.txt",
       "grep KEY /etc/hosts","find . -name '*.py'","sed -n p a.txt","cat a.txt"]

def test_fix(client, owner, tmp_path, capsys):
    proj=_project(tmp_path); ag,hdr=owner.new_agent("claude-code","cc"); owner.mandate(ag["id"],default_form(proj))
    with capsys.disabled():
        bad=[]
        for cmd in ASK:
            r=_send(client,hdr,cmd,proj,owner)
            ok = any(v in ("defer","deny") for _,v in r)
            print("ASK   %-32s -> %s %s"%(cmd, [v for _,v in r], "" if ok else "  !!! NOT ASKED"))
            if not ok: bad.append(cmd)
        for cmd in ALLOW:
            r=_send(client,hdr,cmd,proj,owner)
            ok = r and all(v=="allow" for _,v in r)
            print("ALLOW %-32s -> %s %s"%(cmd, [v for _,v in r], "" if ok else "  !!! NOT ALLOW"))
            if not ok: bad.append(cmd)
        assert not bad, bad
