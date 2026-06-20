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

Open PowerShell in the backend folder:

```powershell
cd C:\Users\ctcom\Downloads\fyp1\smartyara_prototype\backend
```

Install the Python dependencies:

```powershell
python -m pip install -r requirements.txt
```

Create the environment file:

```powershell
Copy-Item .\.env.example .\.env
```

Open `backend\.env` and add your API keys:
- `GEMINI_API_KEY`
- `GCP_NLP_API_KEY`

Run the backend server:

```powershell
python -m uvicorn main:app --reload --port 8000
```

If `uvicorn` is not on PATH, use the command above with `python -m uvicorn`.

The API will be live at:
- http://127.0.0.1:8000
- http://127.0.0.1:8000/docs

**Default login:** `admin` / `admin123`

---

## Step 3 — Frontend Setup

Open a second terminal and go to the frontend folder:

```powershell
cd C:\Users\ctcom\Downloads\fyp1\smartyara_prototype\frontend
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

1. Open the app and login with **admin / admin123**
2. Dashboard shows stats (0 artifacts to start)
3. Click **Upload Artifact**
4. Upload a `.txt` file containing malware-like indicators
   - Example: `CreateProcess HKEY_LOCAL_MACHINE\Software\evil.exe 192.168.1.100`
5. Backend extracts indicators and generates a YARA rule
6. Review the generated rule on the Rule Review screen
7. Complete the analyst checklist
8. Export the final rule

---

## Important notes

- The frontend expects the backend at `http://127.0.0.1:8000`
- Make sure the backend is running before logging in
- If no API keys are set, the backend falls back to regex-based extraction

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
