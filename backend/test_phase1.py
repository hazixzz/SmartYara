"""Phase 1 tests: upload checks, rule editing, versions, approval, export,
history filters and ownership. Run from backend/: python test_phase1.py
(also works with pytest). Uses a temporary DB and upload folder, and never
calls Gemini or Ollama."""
import asyncio, os, sys, tempfile

TMP = tempfile.mkdtemp()
# must be set before main is imported; load_dotenv() never overrides them
os.environ.update({
    "DB_PATH": os.path.join(TMP, "test.db"),
    "UPLOAD_DIR": os.path.join(TMP, "uploads"),
    "MAX_UPLOAD_MB": "1",
    "GCP_NLP_API_KEY": "",      # regex extraction only, no network
    "ADMIN_PASSWORD": "",
})
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.chdir(TMP)
import main
from fastapi.testclient import TestClient

GOOD_RULE = '''rule Test_Rule {
    strings:
        $a = "evil.exe"
    condition:
        $a
}'''
EDITED_RULE = GOOD_RULE.replace('$a\n}', '$a and filesize < 1MB\n}')
BAD_RULE = 'rule Broken { condition: $missing }'
CHECKLIST = {item: True for item in main.REVIEW_CHECKLIST}

async def fake_generate(filename, indicators, raw_text):
    return GOOD_RULE, "gemini:test-model"
main.generate_yara_rule = fake_generate   # the upload route looks it up at call time

client = TestClient(main.app)

def login(username):
    client.post("/auth/register", json={"username": username, "password": "pw"})
    r = client.post("/auth/login", data={"username": username, "password": "pw"})
    return {"Authorization": "Bearer " + r.json()["access_token"]}

A, B = login("alice"), login("bob")

def upload(headers, name="sample.txt", data=b"CreateProcess evil.exe 10.0.0.1"):
    return client.post("/artifacts/upload", headers=headers, files={"file": (name, data)})

def new_rule(headers=A, name="sample.txt"):
    r = upload(headers, name)
    assert r.status_code == 200, r.text
    return r.json()

def approve(rule_id, checklist=CHECKLIST, headers=A):
    return client.post(f"/rules/{rule_id}/approve", headers=headers,
                       json={"checklist": checklist})

# ── Upload checks ──────────────────────────────────────────────────────────────
def test_upload_rejects_bad_extension():
    r = upload(A, "payload.exe", b"MZ...")
    assert r.status_code == 400 and "Unsupported file type" in r.json()["detail"]

def test_upload_rejects_too_large():
    # just over the limit: caught while reading the file in chunks
    r = upload(A, "big.txt", b"a" * (1024 * 1024 + 1))
    assert r.status_code == 413 and "too large" in r.json()["detail"]
    # far over the limit: caught earlier from the Content-Length header
    r = upload(A, "huge.txt", b"a" * (2 * 1024 * 1024))
    assert r.status_code == 413 and "too large" in r.json()["detail"]

def test_upload_rejects_binary():
    r = upload(A, "bin.txt", b"text\0\0\0\0" * 100)
    assert r.status_code == 400 and "binary" in r.json()["detail"]

def test_upload_rejects_empty():
    for data in (b"", b"   \n"):
        r = upload(A, "empty.txt", data)
        assert r.status_code == 400 and "empty" in r.json()["detail"]

def test_path_traversal_filename_is_stored_safely():
    before = set(os.listdir(main.UPLOAD_DIR))
    r = upload(A, "../../evil.txt", b"hello evil.exe")
    assert r.status_code == 200
    assert r.json()["filename"] == "evil.txt"
    assert not os.path.exists(os.path.join(TMP, "evil.txt"))
    new_files = set(os.listdir(main.UPLOAD_DIR)) - before
    assert len(new_files) == 1
    stored = new_files.pop()
    assert stored.endswith(".txt") and len(stored) == 32 + 4   # uuid4 hex + ".txt"
    conn = main.get_db()
    path = conn.execute("SELECT filepath FROM artifacts WHERE id=?",
                        (r.json()["artifact_id"],)).fetchone()[0]
    conn.close()
    assert os.path.dirname(os.path.abspath(path)) == os.path.abspath(main.UPLOAD_DIR)

def test_upload_creates_version_1():
    up = new_rule()
    assert up["status"] == "draft" and up["current_version"] == 1
    versions = client.get(f"/rules/{up['rule_id']}/versions", headers=A).json()
    assert [v["version"] for v in versions] == [1] and versions[0]["source"] == "generated"

# ── Edit / versions ────────────────────────────────────────────────────────────
def test_edit_valid_rule_creates_v2():
    rid = new_rule()["rule_id"]
    r = client.put(f"/rules/{rid}", headers=A,
                   json={"rule_text": EDITED_RULE, "change_note": "tighten condition"})
    assert r.status_code == 200, r.text
    assert r.json()["rule"]["current_version"] == 2
    versions = client.get(f"/rules/{rid}/versions", headers=A).json()
    assert versions[0]["version"] == 2 and versions[0]["source"] == "edited"
    assert versions[0]["change_note"] == "tighten condition"
    v2 = client.get(f"/rules/{rid}/versions/2", headers=A).json()
    assert v2["rule_text"] == EDITED_RULE.strip()

def test_edit_invalid_rule_returns_422_and_saves_nothing():
    rid = new_rule()["rule_id"]
    r = client.put(f"/rules/{rid}", headers=A, json={"rule_text": BAD_RULE})
    assert r.status_code == 422 and "does not compile" in r.json()["detail"]
    assert len(client.get(f"/rules/{rid}/versions", headers=A).json()) == 1

def test_edit_rejects_empty_and_too_long():
    rid = new_rule()["rule_id"]
    assert client.put(f"/rules/{rid}", headers=A, json={"rule_text": "  "}).status_code == 400
    huge = GOOD_RULE + "\n// " + "x" * (100 * 1024)
    assert client.put(f"/rules/{rid}", headers=A, json={"rule_text": huge}).status_code == 413

def test_restore_creates_new_version():
    rid = new_rule()["rule_id"]
    client.put(f"/rules/{rid}", headers=A, json={"rule_text": EDITED_RULE})
    r = client.post(f"/rules/{rid}/versions/1/restore", headers=A)
    assert r.status_code == 200, r.text
    assert r.json()["rule"]["current_version"] == 3
    versions = client.get(f"/rules/{rid}/versions", headers=A).json()
    assert [v["version"] for v in versions] == [3, 2, 1]   # nothing deleted
    assert versions[0]["source"] == "restored"
    v3 = client.get(f"/rules/{rid}/versions/3", headers=A).json()
    assert v3["rule_text"] == GOOD_RULE

# ── Approve / export ───────────────────────────────────────────────────────────
def test_approve_fails_with_incomplete_checklist():
    rid = new_rule()["rule_id"]
    partial = dict(CHECKLIST, **{main.REVIEW_CHECKLIST[2]: False})
    r = approve(rid, partial)
    assert r.status_code == 400 and main.REVIEW_CHECKLIST[2] in r.json()["detail"]
    r = approve(rid, {})
    assert r.status_code == 400

def test_approve_succeeds_then_409():
    rid = new_rule()["rule_id"]
    r = approve(rid)
    assert r.status_code == 200, r.text
    rule = r.json()["rule"]
    assert rule["status"] == "approved" and rule["approved_by_name"] == "alice"
    assert rule["approved_at"]
    assert approve(rid).status_code == 409

def test_export_only_after_approval():
    rid = new_rule()["rule_id"]
    assert client.get(f"/rules/{rid}/export", headers=A).status_code == 409
    approve(rid)
    r = client.get(f"/rules/{rid}/export", headers=A)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    assert r.headers["content-disposition"] == 'attachment; filename="Test_Rule.yar"'
    body = r.text
    assert body.startswith("// Generated by SmartYARA")
    assert "version 1" in body and "Approved by: alice" in body
    assert "Generated by: gemini:test-model" in body
    assert GOOD_RULE in body
    ok, msg = main.validate_yara(body)   # the header comments must not break it
    assert ok, msg

def test_edit_after_approval_resets_to_draft():
    rid = new_rule()["rule_id"]
    approve(rid)
    r = client.put(f"/rules/{rid}", headers=A, json={"rule_text": EDITED_RULE})
    assert r.status_code == 200
    rule = r.json()["rule"]
    assert rule["status"] == "draft" and rule["approved_at"] is None
    assert client.get(f"/rules/{rid}/export", headers=A).status_code == 409
    assert approve(rid).status_code == 200   # can be approved again

# ── History filters / dashboard ────────────────────────────────────────────────
def test_history_filters():
    h = login("carol")
    first = new_rule(h, "alpha_report.txt")
    new_rule(h, "beta_log.log")
    approve(first["rule_id"], headers=h)
    get = lambda **p: client.get("/artifacts", headers=h, params=p)

    all_rows = get().json()
    assert len(all_rows) == 2
    assert {"status", "generated_by", "current_version", "rule_id",
            "indicator_count"} <= set(all_rows[0])
    assert [r["filename"] for r in get(q="alpha").json()] == ["alpha_report.txt"]
    assert get(q="%").json() == []   # % is matched literally
    assert [r["filename"] for r in get(status="approved").json()] == ["alpha_report.txt"]
    assert [r["filename"] for r in get(status="draft").json()] == ["beta_log.log"]
    assert len(get(generated_by="gemini").json()) == 2
    assert get(generated_by="ollama").json() == []
    today = main.get_db().execute("SELECT date('now')").fetchone()[0]
    assert len(get(date_from=today, date_to=today).json()) == 2
    assert get(date_to="2000-01-01").json() == []
    assert get(status="bogus").status_code == 400
    assert get(date_from="28/10/2026").status_code == 400

    stats = client.get("/dashboard/stats", headers=h).json()
    assert stats["approved_rules"] == 1 and stats["draft_rules"] == 1

# ── Ownership ──────────────────────────────────────────────────────────────────
def test_other_user_gets_404_everywhere():
    up = new_rule(A)
    rid, aid = up["rule_id"], up["artifact_id"]
    calls = [
        ("get",  f"/artifacts/{aid}/rule", None),
        ("put",  f"/rules/{rid}", {"rule_text": EDITED_RULE}),
        ("get",  f"/rules/{rid}/versions", None),
        ("get",  f"/rules/{rid}/versions/1", None),
        ("post", f"/rules/{rid}/versions/1/restore", None),
        ("post", f"/rules/{rid}/approve", {"checklist": CHECKLIST}),
        ("get",  f"/rules/{rid}/export", None),
    ]
    for method, url, body in calls:
        kwargs = {"headers": B}
        if body is not None:
            kwargs["json"] = body
        r = getattr(client, method)(url, **kwargs)
        assert r.status_code == 404, f"{method.upper()} {url} -> {r.status_code}"
    assert all(a["id"] != aid for a in client.get("/artifacts", headers=B).json())
    # and nothing changed for alice
    assert client.get(f"/rules/{rid}/versions", headers=A).json()[0]["version"] == 1

def test_endpoints_require_login():
    rid = new_rule()["rule_id"]
    assert client.get(f"/rules/{rid}/versions").status_code == 401
    assert client.get(f"/rules/{rid}/export").status_code == 401

if __name__ == "__main__":
    tests = [(n, f) for n, f in list(globals().items()) if n.startswith("test_")]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"ok    {name}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL  {name}: {e}")
    print(f"\n{len(tests) - failed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
