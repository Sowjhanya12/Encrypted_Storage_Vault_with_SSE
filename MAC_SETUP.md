# Running cyber_pr on macOS

## 1. Install Python 3.10+
Check with `python3 --version`. If it's missing, install it from https://www.python.org/downloads/ (or `brew install python`).

## 2. Unzip and set up a virtual environment
```bash
cd ~/Downloads            # or wherever you unzipped it
cd cyber_pr
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r benchmarks/requirements.txt   # only if you'll run the benchmarks
```

## 3. Check everything works
```bash
pytest
```

## 4. Run the app (two Terminal windows, both inside cyber_pr with the venv active)
**Window 1 - untrusted cloud (port 5001):**
```bash
python3 -m cloud.cloud_app
```
**Window 2 - trusted client:**
```bash
CLIENT_PORT=5050 python3 -m client.client_app
```
Then open http://127.0.0.1:5050 in your browser.

First-time admin setup, registration, vault unlock and the full demo script are in **README.md**.

Why 5050: on macOS 12+, port 5000 is used by **AirPlay Receiver**, so the client can't start there
("Address already in use") or the browser gets a 403 from AirPlay. Either use `CLIENT_PORT=5050`
as above, or turn off System Settings -> General -> AirDrop & Handoff -> AirPlay Receiver and use 5000.

## Notes
- Use `python3`, not `python`, on a Mac.
- `vault.sqlite3` is the cloud's data (auto-migrated to the multi-user schema on start; nothing is deleted). `client_accounts.sqlite3` holds accounts and the audit log. Move both aside (don't delete) if you want a fresh install.
