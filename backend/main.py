from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional
from dotenv import load_dotenv
import sqlite3, os, hashlib, jwt, shutil, httpx, json, re, bcrypt, asyncio, time

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

app = FastAPI(title="SmartYARA API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Config ──────────────────────────────────────────────────────────────────
SECRET_KEY      = os.getenv("SECRET_KEY", "smartyara-secret-change-in-prod")
ALGORITHM       = "HS256"
TOKEN_EXPIRE_MIN = 60 * 8   # 8 hours

GEMINI_API_KEY  = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL    = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")
# Gemini 3.x uses thinkingLevel (low/medium/high; 3.6 also allows minimal)
GEMINI_THINKING_LEVEL = os.getenv("GEMINI_THINKING_LEVEL", "low")
GEMINI_RETRIES  = 3
# Per-request timeout; Gemini 3.x can take over a minute under heavy load
GEMINI_TIMEOUT  = float(os.getenv("GEMINI_TIMEOUT", "90"))
# Total time shared by ALL Gemini attempts (both models, all retries) before
# moving on to the local model, so an overloaded Gemini can't stall an upload
GEMINI_TOTAL_BUDGET = float(os.getenv("GEMINI_TOTAL_BUDGET", "90"))
# Optional second Gemini model tried if GEMINI_MODEL fails (e.g. gemini-3.5-flash)
GEMINI_FALLBACK_MODEL = os.getenv("GEMINI_FALLBACK_MODEL", "")
GCP_NLP_API_KEY = os.getenv("GCP_NLP_API_KEY", "")

# Local Ollama model, tried after Gemini and before the template rule
OLLAMA_ENABLED  = os.getenv("OLLAMA_ENABLED", "true").lower() in ("1", "true", "yes")
OLLAMA_URL      = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
OLLAMA_MODEL    = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:3b")
OLLAMA_TIMEOUT  = 120    # seconds; local models can be slow
OLLAMA_NUM_CTX  = 4096   # small context keeps a 3B model fully on a 4 GB GPU

UPLOAD_DIR = "uploads"
DB_PATH    = "smartyara.db"
os.makedirs(UPLOAD_DIR, exist_ok=True)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# ── Database ─────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role     TEXT DEFAULT 'analyst',
            created  TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS artifacts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            filename   TEXT NOT NULL,
            filepath   TEXT NOT NULL,
            filehash   TEXT NOT NULL,
            uploaded   TEXT DEFAULT CURRENT_TIMESTAMP,
            user_id    INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS indicators (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            artifact_id INTEGER,
            type        TEXT,
            value       TEXT,
            FOREIGN KEY(artifact_id) REFERENCES artifacts(id)
        );
        CREATE TABLE IF NOT EXISTS yara_rules (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            artifact_id INTEGER,
            rule_text   TEXT,
            is_valid    INTEGER DEFAULT 0,
            created     TEXT DEFAULT CURRENT_TIMESTAMP,
            user_id     INTEGER,
            generated_by TEXT,
            FOREIGN KEY(artifact_id) REFERENCES artifacts(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    """)
    # Migrate databases created before generated_by existed
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(yara_rules)")]
    if "generated_by" not in cols:
        conn.execute("ALTER TABLE yara_rules ADD COLUMN generated_by TEXT")
        conn.commit()
    # Seed an admin user only if ADMIN_PASSWORD is set in the environment
    admin_pw = os.getenv("ADMIN_PASSWORD")
    if admin_pw:
        try:
            conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                         (os.getenv("ADMIN_USERNAME", "admin"), hash_password(admin_pw), "admin"))
            conn.commit()
        except sqlite3.IntegrityError:
            pass
    conn.close()

# ── Auth helpers ──────────────────────────────────────────────────────────────
MAX_PASSWORD_BYTES = 72   # bcrypt limit

def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def verify_password(pw: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode(), hashed.encode())
    except ValueError:   # >72 bytes or non-bcrypt hash
        return False

def create_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRE_MIN)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

init_db()

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ── Auth routes ───────────────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    username: str
    password: str

@app.post("/auth/register")
def register(req: RegisterRequest):
    if len(req.password.encode()) > MAX_PASSWORD_BYTES:
        raise HTTPException(status_code=400,
                            detail=f"Password must be at most {MAX_PASSWORD_BYTES} bytes")
    conn = get_db()
    try:
        conn.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                     (req.username, hash_password(req.password)))
        conn.commit()
        return {"message": "User registered successfully"}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already exists")
    finally:
        conn.close()

@app.post("/auth/login")
def login(form: OAuth2PasswordRequestForm = Depends()):
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username=?", (form.username,)
    ).fetchone()
    conn.close()
    if not user or not verify_password(form.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token({"sub": user["username"], "role": user["role"], "id": user["id"]})
    return {"access_token": token, "token_type": "bearer",
            "username": user["username"], "role": user["role"]}

@app.get("/auth/me")
def me(user=Depends(get_current_user)):
    return user

# ── NLP: extract indicators via Google Cloud NLP ──────────────────────────────
# Registry key: full root name or short form (HKLM\ etc.), then the path up to
# whitespace, a quote or <>. Short forms need the backslash so "HKU" alone isn't a key.
REGISTRY_KEY_RE = re.compile(
    r'\b(?:HKEY_[A-Z_]+(?:\\[^\s"\'<>]*)?'
    r'|HK(?:LM|CU|CR|CC|U)\\[^\s"\'<>]*)',
    re.I)

def find_registry_keys(text: str) -> list[str]:
    # drop sentence punctuation that the path pattern swallows ("...\Run.")
    return [m.group().rstrip('.,;:)') for m in REGISTRY_KEY_RE.finditer(text)]

async def extract_indicators_nlp(text: str) -> list[dict]:
    """Call Google Cloud Natural Language API to extract named entities,
    then map them to malware indicator types."""
    if not GCP_NLP_API_KEY:
        return extract_indicators_regex(text)   # fallback

    url = f"https://language.googleapis.com/v1/documents:analyzeEntities?key={GCP_NLP_API_KEY}"
    body = {"document": {"type": "PLAIN_TEXT", "content": text[:5000]},
            "encodingType": "UTF8"}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(url, json=body)
    except httpx.HTTPError:   # timeout / network error
        return extract_indicators_regex(text)
    if r.status_code != 200:
        return extract_indicators_regex(text)   # fallback on error

    entities = r.json().get("entities", [])
    indicators = []
    for ent in entities:
        name = ent.get("name", "")
        etype = ent.get("type", "OTHER")
        # Map GCP entity types → malware indicator types
        if re.match(r'\d{1,3}(\.\d{1,3}){3}', name):
            indicators.append({"type": "ip_address", "value": name})
        elif re.match(r'https?://', name):
            indicators.append({"type": "url", "value": name})
        elif REGISTRY_KEY_RE.match(name):
            continue   # added below from the raw text, where the full path is intact
        elif re.match(r'.*\.(exe|dll|sys|bat|ps1|vbs)$', name, re.I):
            indicators.append({"type": "file", "value": name})
        elif etype in ("OTHER", "UNKNOWN") and len(name) > 4:
            indicators.append({"type": "string", "value": name})
    # GCP entities often split a key at its backslashes, so take keys from the text
    for key in dict.fromkeys(find_registry_keys(text)):
        indicators.append({"type": "registry_key", "value": key})
    return indicators or extract_indicators_regex(text)

def extract_indicators_regex(text: str) -> list[dict]:
    """Regex-based fallback indicator extractor."""
    indicators = []
    patterns = [
        ("ip_address",   r'\b\d{1,3}(?:\.\d{1,3}){3}\b'),
        ("domain",       r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|ru|cn|io|cc|top|xyz)\b'),
        ("url",          r'https?://[^\s"\'<>]+'),
        ("file_path",    r'[A-Za-z]:\\[^\s"\'<>]+'),
        ("api_import",   r'\b(?:CreateProcess|WriteFile|RegSetValue|VirtualAlloc|'
                         r'InternetOpen|LoadLibrary|GetProcAddress|ShellExecute|'
                         r'WinExec|URLDownloadToFile)\b'),
        ("file",         r'\b\w+\.(?:exe|dll|sys|bat|ps1|vbs|tmp)\b'),
    ]
    for itype, pattern in patterns:
        for m in re.finditer(pattern, text):
            indicators.append({"type": itype, "value": m.group()})
    for key in find_registry_keys(text):
        indicators.append({"type": "registry_key", "value": key})
    # deduplicate
    seen = set()
    unique = []
    for ind in indicators:
        key = (ind["type"], ind["value"])
        if key not in seen:
            seen.add(key)
            unique.append(ind)
    return unique

# ── LLM: generate YARA rule (Gemini → fallback Gemini → Ollama → template) ───
async def generate_yara_rule(filename: str, indicators: list[dict],
                             raw_text: str) -> tuple[str, str]:
    """Returns (rule_text, generated_by), where generated_by is
    "gemini:<model>", "ollama:<model>" or "template"."""
    prompt = _build_prompt(filename, indicators, raw_text)

    attempts = []
    if GEMINI_API_KEY:
        attempts.append(("gemini", GEMINI_MODEL))
        if GEMINI_FALLBACK_MODEL:
            attempts.append(("gemini", GEMINI_FALLBACK_MODEL))
    else:
        print("[gemini] skipped: GEMINI_API_KEY not set")
    if OLLAMA_ENABLED:
        attempts.append(("ollama", OLLAMA_MODEL))

    gemini_deadline = time.monotonic() + GEMINI_TOTAL_BUDGET
    for provider, model in attempts:
        if provider == "gemini":
            text, error = await _call_gemini(model, prompt, gemini_deadline)
        else:
            text, error = await _call_ollama(model, prompt)
        if text is None:
            print(f"[{provider}] {model}: {error}")
            continue
        text = _clean_rule(text)
        if "rule " not in text or "condition:" not in text:
            print(f"[{provider}] {model}: output is not a YARA rule")
            continue
        ok, msg = validate_yara(text)
        if not ok:
            print(f"[{provider}] {model}: rule did not compile: {msg}")
            continue
        return text, f"{provider}:{model}"

    print("[generate] no LLM produced a valid rule, using template")
    return _fallback_yara(filename, indicators), "template"

def _build_prompt(filename: str, indicators: list[dict], raw_text: str) -> str:
    """Same prompt for every model, so Gemini and local rules are comparable."""
    indicator_summary = "\n".join(
        f"- [{i['type']}] {i['value']}" for i in indicators[:30]
    )
    return f"""You are a malware analyst. Generate a valid YARA rule for the following malware artifact.

Artifact filename: {filename}

Extracted indicators:
{indicator_summary}

Raw artifact excerpt (first 1500 chars):
{raw_text[:1500]}

Requirements:
1. Use a descriptive rule name (no spaces, use underscores).
2. Include a meta section with description, author="SmartYARA", date="{datetime.now().strftime('%Y-%m-%d')}", and threat_level.
3. Include a strings section using the most relevant indicators. Write each one as a
   plain text string in double quotes, copied exactly from the indicators above
   (escape each backslash as \\\\). Do not convert strings to hex.
4. Write a condition section that makes logical sense and avoids false positives:
   - Never let a file-type check (e.g. uint16(0) == 0x5A4D) match on its own; combine it with AND, never OR.
   - Require several artifact-specific strings to match, not just one generic string.
5. Output ONLY the raw YARA rule — no explanation, no markdown fences.
"""

async def _call_gemini(model: str, prompt: str,
                       deadline: float) -> tuple[Optional[str], str]:
    """Returns (text, "") on success or (None, reason) on failure.
    Stops when `deadline` (time.monotonic) is reached. A timeout is not retried
    on the same model: an overloaded model usually times out again."""
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    # key goes in a header, not the URL, so it can't leak into logged errors
    headers = {"x-goog-api-key": GEMINI_API_KEY}
    body = {"contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2,
                                 # thinking tokens count toward this limit, so leave headroom
                                 "maxOutputTokens": 4096,
                                 "thinkingConfig": _thinking_config(model)}}
    # Retry transient failures (overloaded model, rate limit, timeout)
    reason = ""
    r = None
    async with httpx.AsyncClient() as client:
        for attempt in range(GEMINI_RETRIES):
            if attempt:
                await asyncio.sleep(2 ** attempt)
            remaining = deadline - time.monotonic()
            if remaining < 5:
                reason = (reason + "; " if reason else "") + "Gemini time budget used up"
                break
            try:
                r = await client.post(url, json=body, headers=headers,
                                      timeout=min(GEMINI_TIMEOUT, remaining))
            except httpx.TimeoutException:
                reason = f"timed out after {min(GEMINI_TIMEOUT, remaining):.0f}s"
                r = None
                break          # don't retry a model that is timing out
            except httpx.HTTPError as e:   # network error
                reason = type(e).__name__
                r = None
                continue
            if r.status_code in (429, 500, 503):
                reason = f"HTTP {r.status_code}"
                r = None
                continue
            break
    if r is None:
        return None, f"{reason} (attempt {attempt + 1}/{GEMINI_RETRIES})"
    if r.status_code != 200:
        try:
            detail = r.json()["error"]["message"]
        except (ValueError, KeyError, TypeError):
            detail = r.text
        return None, f"HTTP {r.status_code}: {detail[:200]}"
    try:
        parts = r.json()["candidates"][0]["content"]["parts"]
        # skip any thought-summary parts; keep only the answer text
        text = "".join(p.get("text", "") for p in parts if not p.get("thought"))
    except (KeyError, IndexError, ValueError):
        return None, f"unexpected response: {r.text[:200]}"
    if not text.strip():
        return None, "empty response"
    return text, ""

async def _call_ollama(model: str, prompt: str) -> tuple[Optional[str], str]:
    """Returns (text, "") on success or (None, reason) on failure."""
    body = {"model": model, "stream": False,
            "messages": [{"role": "user", "content": prompt}],
            "options": {"temperature": 0.2, "num_predict": 1024,
                        "num_ctx": OLLAMA_NUM_CTX}}
    try:
        async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT) as client:
            r = await client.post(f"{OLLAMA_URL}/api/chat", json=body)
    except httpx.ConnectError:
        return None, f"unreachable at {OLLAMA_URL} (is Ollama running?)"
    except httpx.HTTPError as e:   # timeout / network error
        return None, type(e).__name__
    if r.status_code != 200:
        return None, f"HTTP {r.status_code}: {r.text[:200]}"
    try:
        text = r.json()["message"]["content"]
    except (KeyError, ValueError):
        return None, f"unexpected response: {r.text[:200]}"
    if not text.strip():
        return None, "empty response"
    return text, ""

def _clean_rule(text: str) -> str:
    """Extract the YARA rule from model output that may add fences or chatter."""
    fenced = re.search(r'```[a-zA-Z]*\n(.*?)```', text, re.S)
    if fenced:
        text = fenced.group(1)
    text = re.sub(r'```[a-zA-Z]*\n?', '', text)
    # Drop any preamble before the first import/rule line ...
    start = re.search(r'^\s*(?:import\s+"|(?:(?:private|global)\s+)*rule\s)', text, re.M)
    if start:
        text = text[start.start():]
    # ... and any explanation after the rule's closing brace
    end = text.rfind("}")
    if end != -1:
        text = text[:end + 1]
    return text.strip()

def _thinking_config(model: str) -> dict:
    """Gemini 2.5 takes thinkingBudget; Gemini 3.x takes thinkingLevel."""
    if model.startswith("gemini-2"):
        return {"thinkingBudget": 0}
    return {"thinkingLevel": GEMINI_THINKING_LEVEL}

def _fallback_yara(filename: str, indicators: list[dict]) -> str:
    rule_name = re.sub(r'\W+', '_', filename.rsplit('.', 1)[0]) or "unknown_malware"
    strings_section = ""
    for i, ind in enumerate(indicators[:10]):
        safe = ind["value"].replace('\\', '\\\\').replace('"', '\\"')
        strings_section += f'        $s{i} = "{safe}"\n'
    if not strings_section:
        strings_section = '        $s0 = "malware"\n'
    return (f'rule {rule_name} {{\n'
            f'    meta:\n'
            f'        description = "Auto-generated by SmartYARA"\n'
            f'        author      = "SmartYARA"\n'
            f'        date        = "{datetime.now().strftime("%Y-%m-%d")}"\n'
            f'        threat_level = "medium"\n'
            f'    strings:\n'
            f'{strings_section}'
            f'    condition:\n'
            f'        any of them\n'
            f'}}')

# ── YARA validation ───────────────────────────────────────────────────────────
def validate_yara(rule_text: str) -> tuple[bool, str]:
    try:
        import yara
    except ImportError:
        # yara-python not installed — do basic structural check
        if "rule " in rule_text and "condition:" in rule_text:
            return True, "Basic structure check passed (yara-python not installed)"
        return False, "Invalid YARA structure"
    try:
        yara.compile(source=rule_text)
        return True, "Rule compiled successfully"
    except Exception as e:
        return False, str(e)

# ── Artifact routes ───────────────────────────────────────────────────────────
@app.post("/artifacts/upload")
async def upload_artifact(file: UploadFile = File(...),
                          user=Depends(get_current_user)):
    content = await file.read()
    filehash = hashlib.sha256(content).hexdigest()
    safe_name = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}"
    filepath  = os.path.join(UPLOAD_DIR, safe_name)

    with open(filepath, "wb") as f:
        f.write(content)

    conn = get_db()
    cur = conn.execute(
        "INSERT INTO artifacts (filename, filepath, filehash, user_id) VALUES (?,?,?,?)",
        (file.filename, filepath, filehash, user["id"])
    )
    artifact_id = cur.lastrowid
    conn.commit()

    # Decode text
    try:
        text = content.decode("utf-8", errors="ignore")
    except Exception:
        text = ""

    # NLP extraction
    indicators = await extract_indicators_nlp(text)
    for ind in indicators:
        conn.execute(
            "INSERT INTO indicators (artifact_id, type, value) VALUES (?,?,?)",
            (artifact_id, ind["type"], ind["value"])
        )
    conn.commit()

    # LLM YARA generation
    rule_text, generated_by = await generate_yara_rule(file.filename, indicators, text)
    is_valid, validation_msg = validate_yara(rule_text)
    conn.execute(
        "INSERT INTO yara_rules (artifact_id, rule_text, is_valid, user_id, generated_by) "
        "VALUES (?,?,?,?,?)",
        (artifact_id, rule_text, 1 if is_valid else 0, user["id"], generated_by)
    )
    conn.commit()
    conn.close()

    return {
        "artifact_id": artifact_id,
        "filename":    file.filename,
        "filehash":    filehash,
        "indicators":  indicators,
        "yara_rule":   rule_text,
        "is_valid":    is_valid,
        "validation":  validation_msg,
        "generated_by": generated_by,
    }

@app.get("/artifacts")
def list_artifacts(user=Depends(get_current_user)):
    conn = get_db()
    rows = conn.execute(
        "SELECT a.*, COUNT(i.id) as indicator_count "
        "FROM artifacts a LEFT JOIN indicators i ON a.id=i.artifact_id "
        "WHERE a.user_id=? GROUP BY a.id ORDER BY a.uploaded DESC",
        (user["id"],)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/artifacts/{artifact_id}/rule")
def get_rule(artifact_id: int, user=Depends(get_current_user)):
    conn = get_db()
    rule = conn.execute(
        "SELECT * FROM yara_rules WHERE artifact_id=? AND user_id=? ORDER BY id DESC LIMIT 1",
        (artifact_id, user["id"])
    ).fetchone()
    indicators = conn.execute(
        "SELECT i.type, i.value FROM indicators i JOIN artifacts a ON i.artifact_id=a.id "
        "WHERE i.artifact_id=? AND a.user_id=?",
        (artifact_id, user["id"])
    ).fetchall()
    conn.close()
    if not rule:
        raise HTTPException(status_code=404, detail="No rule found")
    return {"rule": dict(rule), "indicators": [dict(i) for i in indicators]}

@app.get("/dashboard/stats")
def dashboard_stats(user=Depends(get_current_user)):
    conn = get_db()
    total_artifacts = conn.execute(
        "SELECT COUNT(*) FROM artifacts WHERE user_id=?", (user["id"],)
    ).fetchone()[0]
    total_rules = conn.execute(
        "SELECT COUNT(*) FROM yara_rules WHERE user_id=?", (user["id"],)
    ).fetchone()[0]
    valid_rules = conn.execute(
        "SELECT COUNT(*) FROM yara_rules WHERE user_id=? AND is_valid=1", (user["id"],)
    ).fetchone()[0]
    total_indicators = conn.execute(
        "SELECT COUNT(*) FROM indicators i JOIN artifacts a ON i.artifact_id=a.id WHERE a.user_id=?",
        (user["id"],)
    ).fetchone()[0]
    conn.close()
    return {
        "total_artifacts":  total_artifacts,
        "total_rules":      total_rules,
        "valid_rules":      valid_rules,
        "total_indicators": total_indicators,
    }
