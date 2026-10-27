"""Registry key extraction tests. Run from backend/: python test_indicators.py"""
import asyncio, os, sys, tempfile

# main.py creates its DB and uploads/ in the cwd on import; keep them out of the repo
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.chdir(tempfile.mkdtemp())
import main

SAMPLE = r'''
CreateProcessA VirtualAlloc WriteProcessMemory
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\updater
persistence via HKLM\SYSTEM\CurrentControlSet\Services\evilsvc, then
reg add "HKCU\Software\Classes\mscfile\shell\open\command" /d payload.exe
sid hive HKU\S-1-5-21-1004\Software\Microsoft\Windows\CurrentVersion\RunOnce.
the word HKU on its own is not a key
'''

EXPECTED = [
    r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\updater",
    r"HKLM\SYSTEM\CurrentControlSet\Services\evilsvc",
    r"HKCU\Software\Classes\mscfile\shell\open\command",
    r"HKU\S-1-5-21-1004\Software\Microsoft\Windows\CurrentVersion\RunOnce",
]

def _keys(indicators):
    return [i["value"] for i in indicators if i["type"] == "registry_key"]

def test_regex_extractor_keeps_full_paths():
    assert _keys(main.extract_indicators_regex(SAMPLE)) == EXPECTED

def test_nlp_mapping_keeps_full_paths():
    # GCP splits the key at backslashes; the full key must still come through
    entities = [{"name": "HKEY_LOCAL_MACHINE", "type": "OTHER"},
                {"name": "Software", "type": "OTHER"},
                {"name": "HKLM", "type": "OTHER"}]

    class FakeResponse:
        status_code = 200
        def json(self): return {"entities": entities}

    async def fake_post(self, url, **kw): return FakeResponse()

    orig_post, orig_key = main.httpx.AsyncClient.post, main.GCP_NLP_API_KEY
    main.httpx.AsyncClient.post, main.GCP_NLP_API_KEY = fake_post, "test-key"
    try:
        indicators = asyncio.run(main.extract_indicators_nlp(SAMPLE))
    finally:
        main.httpx.AsyncClient.post, main.GCP_NLP_API_KEY = orig_post, orig_key
    assert _keys(indicators) == EXPECTED

if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"ok  {name}")
