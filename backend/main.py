from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional
import sqlite3, os, hashlib, jwt, shutil, httpx, json, re

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
GCP_NLP_API_KEY = os.getenv("GCP_NLP_API_KEY", "")

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
            FOREIGN KEY(artifact_id) REFERENCES artifacts(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    """)
    # Seed a default admin user  (password: admin123)
    pw = hash_password("admin123")
    try:
        conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                     ("admin", pw, "admin"))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    conn.close()

# ── Auth helpers ──────────────────────────────────────────────────────────────
def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

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
        "SELECT * FROM users WHERE username=? AND password=?",
        (form.username, hash_password(form.password))
    ).fetchone()
    conn.close()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token({"sub": user["username"], "role": user["role"], "id": user["id"]})
    return {"access_token": token, "token_type": "bearer",
            "username": user["username"], "role": user["role"]}

@app.get("/auth/me")
def me(user=Depends(get_current_user)):
    return user

# ── NLP: extract indicators via Google Cloud NLP ──────────────────────────────
async def extract_indicators_nlp(text: str) -> list[dict]:
    """Call Google Cloud Natural Language API to extract named entities,
    then map them to malware indicator types."""
    if not GCP_NLP_API_KEY:
        return extract_indicators_regex(text)   # fallback

    url = f"https://language.googleapis.com/v1/documents:analyzeEntities?key={GCP_NLP_API_KEY}"
    body = {"document": {"type": "PLAIN_TEXT", "content": text[:5000]},
            "encodingType": "UTF8"}
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(url, json=body)
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
        elif re.match(r'HKEY_', name):
            indicators.append({"type": "registry_key", "value": name})
        elif re.match(r'.*\.(exe|dll|sys|bat|ps1|vbs)$', name, re.I):
            indicators.append({"type": "file", "value": name})
        elif etype in ("OTHER", "UNKNOWN") and len(name) > 4:
            indicators.append({"type": "string", "value": name})
    return indicators or extract_indicators_regex(text)

def extract_indicators_regex(text: str) -> list[dict]:
    """Regex-based fallback indicator extractor."""
    indicators = []
    patterns = [
        ("ip_address",   r'\b\d{1,3}(?:\.\d{1,3}){3}\b'),
        ("domain",       r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|ru|cn|io|cc|top|xyz)\b'),
        ("url",          r'https?://[^\s"\'<>]+'),
        ("registry_key", r'HKEY_[A-Z_\\]+'),
        ("file_path",    r'[A-Za-z]:\\[^\s"\'<>]+'),
        ("api_import",   r'\b(?:CreateProcess|WriteFile|RegSetValue|VirtualAlloc|'
                         r'InternetOpen|LoadLibrary|GetProcAddress|ShellExecute|'
                         r'WinExec|URLDownloadToFile)\b'),
        ("file",         r'\b\w+\.(?:exe|dll|sys|bat|ps1|vbs|tmp)\b'),
    ]
    for itype, pattern in patterns:
        for m in re.finditer(pattern, text):
            indicators.append({"type": itype, "value": m.group()})
    # deduplicate
    seen = set()
    unique = []
    for ind in indicators:
        key = (ind["type"], ind["value"])
        if key not in seen:
            seen.add(key)
            unique.append(ind)
    return unique

# ── LLM: generate YARA rule via Gemini ───────────────────────────────────────
async def generate_yara_rule(filename: str, indicators: list[dict], raw_text: str) -> str:
    if not GEMINI_API_KEY:
        return _fallback_yara(filename, indicators)

    indicator_summary = "\n".join(
        f"- [{i['type']}] {i['value']}" for i in indicators[:30]
    )
    prompt = f"""You are a malware analyst. Generate a valid YARA rule for the following malware artifact.

Artifact filename: {filename}

Extracted indicators:
{indicator_summary}

Raw artifact excerpt (first 1500 chars):
{raw_text[:1500]}

Requirements:
1. Use a descriptive rule name (no spaces, use underscores).
2. Include a meta section with description, author="SmartYARA", date, and threat_level.
3. Include a strings section using the most relevant indicators.
4. Write a condition section that makes logical sense.
5. Output ONLY the raw YARA rule — no explanation, no markdown fences.
"""
    url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
           f"gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}")
    body = {"contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 1024}}
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(url, json=body)
    if r.status_code != 200:
        return _fallback_yara(filename, indicators)
    try:
        text = r.json()["candidates"][0]["content"]["parts"][0]["text"]
        # Strip markdown fences if Gemini wraps it anyway
        text = re.sub(r'```(?:yara)?\n?', '', text).strip()
        return text
    except (KeyError, IndexError):
        return _fallback_yara(filename, indicators)

def _fallback_yara(filename: str, indicators: list[dict]) -> str:
    rule_name = re.sub(r'\W+', '_', filename.rsplit('.', 1)[0]) or "unknown_malware"
    strings_section = ""
    for i, ind in enumerate(indicators[:10]):
        safe = ind["value"].replace('"', '\\"').replace('\\', '\\\\')
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
        yara.compile(source=rule_text)
        return True, "Rule compiled successfully"
    except Exception as e:
        return False, str(e)
    except ImportError:
        # yara-python not installed — do basic structural check
        if "rule " in rule_text and "condition:" in rule_text:
            return True, "Basic structure check passed (yara-python not installed)"
        return False, "Invalid YARA structure"

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
    rule_text = await generate_yara_rule(file.filename, indicators, text)
    is_valid, validation_msg = validate_yara(rule_text)
    conn.execute(
        "INSERT INTO yara_rules (artifact_id, rule_text, is_valid, user_id) VALUES (?,?,?,?)",
        (artifact_id, rule_text, 1 if is_valid else 0, user["id"])
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
        "SELECT * FROM yara_rules WHERE artifact_id=? ORDER BY id DESC LIMIT 1",
        (artifact_id,)
    ).fetchone()
    indicators = conn.execute(
        "SELECT type, value FROM indicators WHERE artifact_id=?",
        (artifact_id,)
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
