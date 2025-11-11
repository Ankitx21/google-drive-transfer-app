import streamlit as st
import os, pickle, hashlib, time, atexit, math, random
from pathlib import Path
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.transport.requests import Request
from typing import List

# --------------------------------------------------------------
# 1. Page & Security
# --------------------------------------------------------------
st.set_page_config(page_title="Google Drive Transfer", layout="centered")
st.title("Google Drive Transfer")
st.markdown("### Transfer **ENTIRE** Google Drive → New Email")

hide = "<style>#MainMenu,footer,header{visibility:hidden;}</style>"
st.markdown(hide, unsafe_allow_html=True)

st.caption("**Nov 11, 2025** • Works on Streamlit Cloud • Manual code paste")

st.info("""
**How to use:**  
1. Upload `client_secrets.json` (Web App type)  
2. Click login → Open Google → Copy `4/...` code → Paste  
3. If error: Click **"Clear Logins"** → Re-login  
4. Click **START TRANSFER**
""")

# --------------------------------------------------------------
# 2. Session & Cleanup
# --------------------------------------------------------------
def uid() -> str:
    if "uid" not in st.session_state:
        st.session_state.uid = hashlib.sha256(str(time.time()).encode()).hexdigest()[:12]
    return st.session_state.uid

USER_ID = uid()
TEMP_DIR = Path("temp")
TOKEN_DIR = Path("tokens")
TEMP_DIR.mkdir(exist_ok=True)
TOKEN_DIR.mkdir(exist_ok=True)

def _cleanup():
    for p in TEMP_DIR.glob(f"client_{USER_ID}*"): p.unlink(missing_ok=True)
    for p in TOKEN_DIR.glob(f"token_{USER_ID}*"): p.unlink(missing_ok=True)
atexit.register(_cleanup)

# --------------------------------------------------------------
# 3. OAuth - Full Drive Scope (Fixes 403 & Scope Mismatch)
# --------------------------------------------------------------
SCOPES_FULL = ["https://www.googleapis.com/auth/drive"]

def auth(account: str):
    token_file = TOKEN_DIR / f"token_{USER_ID}_{account}.pkl"
    creds = None
    if token_file.exists():
        with token_file.open("rb") as f:
            creds = pickle.load(f)

    client_path = TEMP_DIR / f"client_{USER_ID}.json"
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                with token_file.open("wb") as f:
                    pickle.dump(creds, f)
            except:
                creds = None

        if not creds:
            flow = InstalledAppFlow.from_client_secrets_file(
                str(client_path),
                SCOPES_FULL,
                redirect_uri="http://127.0.0.1:8501/"
            )
            auth_url, _ = flow.authorization_url(
                prompt="consent",
                access_type="offline"
            )

            st.markdown(f"### Login to **{account.upper()}** Account")
            st.markdown(f"[**Open Google Sign-In**]({auth_url})")
            st.info("After allowing, **copy the code** (starts with `4/`)")

            code = st.text_input("**Paste code here:**", key=f"code_{account}")

            if code:
                with st.spinner("Verifying..."):
                    try:
                        flow.fetch_token(code=code)
                        creds = flow.credentials
                        with token_file.open("wb") as f:
                            pickle.dump(creds, f)
                        st.success("Login successful!")
                    except Exception as e:
                        st.error(f"Invalid code: {e}")
                        st.stop()

    service = build("drive", "v3", credentials=creds)
    email = service.about().get(fields="user/emailAddress").execute()["user"]["emailAddress"]
    return creds, email, service

# --------------------------------------------------------------
# 4. File Uploader
# --------------------------------------------------------------
st.markdown("### Step 1: Upload `client_secrets.json`")
st.info("**Web App Type** • From Google Cloud Console")

uploaded = st.file_uploader(
    "Drag & drop **client_secrets.json**",
    type=["json"],
    key="client_json"
)

if uploaded:
    client_path = TEMP_DIR / f"client_{USER_ID}.json"
    client_path.write_bytes(uploaded.getbuffer())
    st.success("`client_secrets.json` loaded")
else:
    st.stop()

# --------------------------------------------------------------
# 5. Login + Clear Logins
# --------------------------------------------------------------
st.warning("""
**Scope error?** → Click **"Clear Logins"** → Re-login to **both accounts**  
This fixes "Scope has changed" or "Insufficient permissions".
""")

col1, col2, col3 = st.columns([1, 1, 1])
with col1:
    if st.button("Login **Old** Gmail", use_container_width=True, type="primary"):
        c, e, s = auth("src")
        st.session_state.src_creds, st.session_state.src_email, st.session_state.src_service = c, e, s
        st.success(f"Source: **{e}**")
with col2:
    if st.button("Login **New** Gmail", use_container_width=True, type="secondary"):
        c, e, s = auth("dest")
        st.session_state.dst_creds, st.session_state.dst_email, st.session_state.dst_service = c, e, s
        st.success(f"Destination: **{e}**")
with col3:
    if st.button("Clear Logins", use_container_width=True, type="secondary"):
        for acc in ["src", "dest"]:
            (TOKEN_DIR / f"token_{USER_ID}_{acc}.pkl").unlink(missing_ok=True)
        for key in list(st.session_state.keys()):
            if key not in ["uid"]:
                del st.session_state[key]
        st.success("Logins cleared!")
        st.rerun()

if getattr(st.session_state, "src_email", None):
    st.info(f"**Source** → {st.session_state.src_email}")
if getattr(st.session_state, "dst_email", None):
    st.info(f"**Destination** → {st.session_state.dst_email}")

# --------------------------------------------------------------
# 6. Transfer Engine
# --------------------------------------------------------------
if not (getattr(st.session_state, "src_service", None) and getattr(st.session_state, "dst_service", None)):
    st.info("Log in to both accounts to enable transfer")
    st.stop()

class RateLimiter:
    def __init__(self, max_calls: int, period: float):
        self.max = max_calls
        self.period = period
        self.allowance = float(max_calls)
        self.last_check = time.time()

    def wait(self):
        current = time.time()
        time_passed = current - self.last_check
        self.last_check = current
        self.allowance += time_passed * (self.max / self.period)
        if self.allowance > self.max:
            self.allowance = float(self.max)
        if self.allowance < 1.0:
            delay = (1 - self.allowance) * (self.period / self.max)
            time.sleep(delay)
            self.allowance = 0.0
        else:
            self.allowance -= 1.0

limiter = RateLimiter(900, 100)

def api_call(fn, *args, **kwargs):
    retries = 5
    for attempt in range(retries):
        try:
            limiter.wait()
            return fn(*args, **kwargs).execute()
        except HttpError as e:
            if e.resp.status in (429, 500, 502, 503, 504) and attempt < retries-1:
                sleep = (2 ** attempt) + random.random()
                time.sleep(sleep)
                continue
            raise

status = st.empty()
log_exp = st.expander("Transfer Log", expanded=True)
stop_col, _ = st.columns([1, 4])
stop_btn = stop_col.button("STOP TRANSFER", type="secondary", use_container_width=True)
if stop_btn:
    st.session_state.stop_transfer = True

def ensure_folder(dst_parent: str, name: str, dst_service) -> str:
    res = api_call(dst_service.files().list,
        q=f"'{dst_parent}' in parents and mimeType='application/vnd.google-apps.folder' and name='{name}' and trashed=false",
        fields="files(id)", pageSize=1, supportsAllDrives=True)
    if res.get("files"):
        return res["files"][0]["id"]
    base, i = name, 1
    while True:
        try:
            folder = api_call(dst_service.files().create,
                body={"name": name, "mimeType": "application/vnd.google-apps.folder", "parents": [dst_parent]},
                fields="id", supportsAllDrives=True)
            return folder["id"]
        except HttpError as e:
            if "already exists" in str(e).lower():
                name = f"{base} (copy {i})"
                i += 1
                continue
            raise

def share_file(src_service, file_id: str, email: str):
    try:
        api_call(src_service.permissions().create,
            fileId=file_id,
            body={"type": "user", "role": "writer", "emailAddress": email},
            sendNotificationEmail=False, supportsAllDrives=True)
    except HttpError as e:
        if "already" not in str(e).lower() and "insufficient" not in str(e).lower():
            log_exp.warning(f"Share failed (skipped): {e}")

def copy_item(src_id: str, dst_parent: str, path: str, src_svc, dst_svc, dest_email):
    if st.session_state.get("stop_transfer", False):
        return False

    meta = api_call(src_svc.files().get, fileId=src_id,
                    fields="id,name,mimeType,size", supportsAllDrives=True)
    name, mime = meta["name"], meta["mimeType"]
    cur_path = f"{path}/{name}" if path else name
    status.info(f"**{cur_path}**")

    share_file(src_svc, src_id, dest_email)

    if mime == "application/vnd.google-apps.folder":
        new_folder_id = ensure_folder(dst_parent, name, dst_svc)
        children = []
        page_token = None
        while True:
            resp = api_call(src_svc.files().list,
                q=f"'{src_id}' in parents and trashed=false",
                fields="nextPageToken, files(id,name,mimeType,size)",
                pageSize=1000, pageToken=page_token, supportsAllDrives=True)
            children.extend(resp.get("files", []))
            page_token = resp.get("nextPageToken")
            if not page_token: break
        for child in children:
            copy_item(child["id"], new_folder_id, cur_path, src_svc, dst_svc, dest_email)
        log_exp.success(f"Folder **{cur_path}** ({len(children)} items)")

    else:
        try:
            copied = api_call(dst_svc.files().copy,
                fileId=src_id, body={"parents": [dst_parent]},
                supportsAllDrives=True, fields="id")
            size = meta.get("size", "—")
            log_exp.info(f"File **{cur_path}** ({size} B) → `{copied['id']}`")
        except Exception as e:
            log_exp.error(f"Failed **{cur_path}**: {e}")
    return True

# --------------------------------------------------------------
# 7. Start Transfer
# --------------------------------------------------------------
if st.button("START FULL DRIVE TRANSFER", type="primary", use_container_width=True):
    st.session_state.stop_transfer = False
    st.balloons()

    src = st.session_state.src_service
    dst = st.session_state.dst_service
    dest_email = st.session_state.dst_email

    status.info("Scanning drives...")
    root_items = []
    page_token = None
    while True:
        resp = api_call(src.files().list,
            q="trashed=false and 'root' in parents",
            fields="nextPageToken, files(id,name,mimeType)",
            pageSize=1000, pageToken=page_token, supportsAllDrives=True)
        root_items.extend(resp.get("files", []))
        page_token = resp.get("nextPageToken")
        if not page_token: break

    drives_resp = api_call(src.drives().list, pageSize=100, fields="drives(id,name)")
    for drv in drives_resp.get("drives", []):
        root_items.append({"id": drv["id"], "name": drv["name"], "mimeType": "application/vnd.google-apps.folder"})

    st.session_state.total = len(root_items)
    prog = st.progress(0)

    for idx, item in enumerate(root_items):
        if st.session_state.get("stop_transfer", False):
            break
        copy_item(item["id"], "root", "", src, dst, dest_email)
        prog.progress((idx + 1) / st.session_state.total)
        st.rerun()

    if not st.session_state.get("stop_transfer", False):
        st.success("TRANSFER COMPLETE!")
        st.balloons()
    else:
        st.warning("Transfer stopped.")
