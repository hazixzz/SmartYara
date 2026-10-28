# SmartYARA — Setup Guide

## Prerequisites
- Python 3.10+
- Flutter SDK 3.x
- Google Cloud account (for NLP API + Gemini)
- Git (optional, useful for cloning the repo)

---

## Quick start

1. Open PowerShell.
2. Start the backend first.
3. Then start the frontend in a second terminal.
4. Open the Flutter web app in your browser.

---

## Step 1 — Get your API Keys (10 minutes)

### Gemini API Key (LLM for YARA generation)
1. Go to https://aistudio.google.com/app/apikey
2. Click **Create API Key**
3. Copy the key

### Google Cloud NLP API Key
1. Go to https://console.cloud.google.com
2. Create a project (or use an existing one)
3. Enable **Cloud Natural Language API**
4. Go to **APIs & Services → Credentials → Create API Key**
5. Copy the key

---

## Step 2 — Backend Setup

Open PowerShell in the repository root and go to the backend folder:

```powershell
cd backend
```

Install the Python dependencies:

```powershell
python -m pip install -r requirements.txt
```

Create the environment file:

```powershell
Copy-Item .\.env.example .\.env
```

Open `backend\.env` and fill in:
- `GEMINI_API_KEY`
- `GCP_NLP_API_KEY`
- `SECRET_KEY` (any long random string)
- `ADMIN_PASSWORD` (optional, creates an `admin` account on first start)

`.env` is git-ignored, so never commit it.

Run the backend server:

```powershell
python -m uvicorn main:app --reload --port 8000
```

If `uvicorn` is not on PATH, use the command above with `python -m uvicorn`.

The API will be live at:
- http://127.0.0.1:8000
- http://127.0.0.1:8000/docs

**Login:** there is no default account. Either set `ADMIN_PASSWORD` in `.env` before the first start, or register a user via `POST /auth/register` (see `/docs`).

---

## Step 3 — Frontend Setup

Open a second terminal and go to the frontend folder:

```powershell
cd frontend
```

Get Flutter packages:

```powershell
flutter pub get
```

Run the app on Chrome:

```powershell
flutter run -d chrome
```

Or run on Windows desktop:

```powershell
flutter run -d windows
```

If `flutter` is not recognized, make sure the Flutter SDK is installed and the `bin` folder is added to your PATH.

---

## Demo Flow (for presentation)

1. Open the app and log in with the admin account from your `.env`
2. Dashboard shows stats (0 artifacts to start)
3. Click **Upload Artifact**
4. Upload a `.txt` file containing malware-like indicators
   - Example: `CreateProcess HKEY_LOCAL_MACHINE\Software\evil.exe 192.168.1.100`
5. Backend extracts indicators and generates a YARA rule
6. Review the generated rule on the Rule Review screen
7. Edit the rule if needed, add a change note and click **Save & Validate**
   (a rule that doesn't compile is rejected and the YARA error is shown)
8. Complete the analyst checklist and click **Approve Rule**
9. Click **Export .yar** to download the approved rule
10. Open **History** (top bar) to search and filter all artifacts and rules;
    **History** on the Rule Review screen shows every version of a rule

---

## Features

- **Upload checks:** only text files (`.txt .log .json .csv .xml .md`), at most
  `MAX_UPLOAD_MB` (default 5 MB); empty and binary files are rejected. Files are
  stored as `uploads/<random-id>.<ext>`, never under the name the client sent.
- **Rule generation:** Gemini → optional second Gemini model → local Ollama model
  → fallback template. Each rule records which one wrote it (`generated_by`).
- **Edit & validate:** edits are saved only if they compile with yara-python.
- **Version history:** every generated, edited or restored rule text is kept as
  a numbered version; restoring copies an old version into a new one, so
  history is never overwritten or deleted.
- **Approval:** a rule can be approved only when it compiles and every
  checklist item is ticked (checked by the server). Editing or restoring an
  approved rule sends it back to draft.
- **Export:** approved rules download as a `.yar` file with a header
  (version, approver, generator).
- **History:** search by filename and filter by status, generator and date.
- Each user only sees their own artifacts and rules; anyone else's rule
  returns 404.

---

## API endpoints

All endpoints except register/login need `Authorization: Bearer <token>`.

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/auth/register` | Create an account |
| POST | `/auth/login` | Log in, returns a JWT access token |
| GET | `/auth/me` | Current user from the token |
| POST | `/artifacts/upload` | Upload a text artifact; extracts indicators, generates and validates a rule (version 1) |
| GET | `/artifacts` | List my artifacts with rule status; filters `q`, `status`, `generated_by`, `date_from`, `date_to` |
| GET | `/artifacts/{artifact_id}/rule` | The artifact's rule, indicators and checklist items |
| PUT | `/rules/{rule_id}` | Save an edited rule as a new version (422 if it doesn't compile) |
| GET | `/rules/{rule_id}/versions` | List a rule's versions, newest first |
| GET | `/rules/{rule_id}/versions/{version}` | One version's full text |
| POST | `/rules/{rule_id}/versions/{version}/restore` | Copy an old version into a new version |
| POST | `/rules/{rule_id}/approve` | Approve with the completed checklist |
| GET | `/rules/{rule_id}/export` | Download an approved rule as `.yar` |
| GET | `/dashboard/stats` | Counts of artifacts, rules, approved/draft rules, indicators |

Interactive docs: http://127.0.0.1:8000/docs

---

## Settings (`backend/.env`)

| Setting | Default | Purpose |
|---------|---------|---------|
| `GEMINI_API_KEY` | – | Gemini key; without it Gemini is skipped |
| `GEMINI_MODEL` | `gemini-3.6-flash` | Main Gemini model |
| `GEMINI_FALLBACK_MODEL` | empty | Optional second Gemini model |
| `GEMINI_TIMEOUT` / `GEMINI_TOTAL_BUDGET` | `90` / `90` | Seconds per Gemini request / for all Gemini attempts |
| `OLLAMA_ENABLED`, `OLLAMA_URL`, `OLLAMA_MODEL` | `true`, `http://127.0.0.1:11434`, `qwen2.5-coder:3b` | Local backup model |
| `GCP_NLP_API_KEY` | – | Google NLP; without it indicators come from regex |
| `MAX_UPLOAD_MB` | `5` | Largest accepted upload |
| `ALLOWED_EXTENSIONS` | `txt,log,json,csv,xml,md` | Accepted upload types (keep the frontend picker in sync) |
| `DB_PATH` / `UPLOAD_DIR` | `smartyara.db` / `uploads` | Database file and upload folder (the tests use temporary ones) |

When the backend starts on an older database, it adds the new columns and
tables in place and first saves a copy as `smartyara.db.<timestamp>.bak`.

---

## Running the tests

From `backend/` (no API keys or network needed; the tests use a temporary
database and never call Gemini or Ollama):

```powershell
python test_indicators.py
python test_phase1.py
```

Both also run under `pytest` if you install it. For the frontend:

```powershell
cd frontend
flutter analyze
```

---

## Important notes

- The frontend expects the backend at `http://127.0.0.1:8000`
- Make sure the backend is running before logging in
- If no API keys are set, the backend falls back to regex-based extraction
- **Export .yar** downloads the file in the web app (Chrome); on Windows
  desktop use **Copy Rule** instead

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `uvicorn` not found | Run `python -m uvicorn main:app --reload --port 8000` |
| `flutter` not found | Add Flutter SDK `bin` to PATH and restart PowerShell |
| Cannot fetch `http://127.0.0.1:8000/auth/login` | Ensure backend is running on port 8000 |
| CORS error in Flutter web | Verify backend is live and running at `http://127.0.0.1:8000` |
| `yara-python` install fails | `pip install yara-python --break-system-packages` |
| NLP returns no indicators | The app falls back to regex extraction automatically |
| Gemini API errors | The app uses a fallback YARA template |


cd C:\Users\ctcom\OneDrive\Documents\GitHub\SmartYara\backend
python -m pip install -r requirements.txt
python -m uvicorn main:app --reload --port 8000


cd C:\Users\ctcom\OneDrive\Documents\GitHub\SmartYara\frontend
$env:Path = "$PWD\..\flutter\bin;$env:Path"
flutter pub get
flutter run -d chrome
