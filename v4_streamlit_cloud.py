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

st.caption("Note: After clicking the link, copy the code from Google (starts with `4/`) and paste it below. If you see 'site can't be reached', copy the code from the URL bar.")

st.info("""
**Troubleshooting 403 Errors:**  
If you get "insufficient scopes" on transfer, click "Clear Login" below, then re-login to Source (old Gmail). This upgrades permissions for sharing files.
""")

# --------------------------------------------------------------
# 2. Session Helpers
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
# 3. OAuth (Full Drive Scope for Both - Fixes 403)
# --------------------------------------------------------------
SCOPES_FULL = ["https://www.googleapis.com/auth/drive"]  # Full access for source (needed for sharing) + dest

def auth(account: str, scopes: List[str]):
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
                st.toast(f"Token refreshed for {account}", icon="success")
            except:
                creds = None

        if not creds:
            flow = InstalledAppFlow.from_client_secrets_file(
                str(client_path),
                scopes,
                redirect_uri="http://127.0.0.1:8501/"
            )
            auth_url, _ = flow.authorization_url(
                prompt="consent",
                access_type="offline",
                include_granted_scopes="true"
            )

            st.info("**Step 1:** Click below to sign in with Google:")
            st.markdown(f"[**Open Google Sign-In**]({auth_url})")

            st.info("**Step 2:** After allowing access, **copy the code** (starts with `4/`)")
            code = st.text_input("**Paste code here:**", key=f"oauth_code_{account}")

            if code:
                with st.spinner("Verifying..."):
                    try:
                        flow.fetch_token(code=code)
                        creds = flow.credentials
                        with token_file.open("wb") as f:
                            pickle.dump(creds, f)
                        st.success("Authenticated!")
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
st.info("**Web App Type** • Safe • Auto-deleted after use")

uploaded = st.file_uploader(
    "Drag & drop **client_secrets.json** (from Google Cloud → Web Application)",
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
# 5. Login Buttons + Clear
# --------------------------------------------------------------
col1, col2, col3 = st.columns([1, 1, 1])
with col1:
    if st.button("Login **Old** Gmail", use_container_width=True, type="primary"):
        with st.spinner("Opening Google..."):
            c, e, s = auth("src", SCOPES_FULL)  # Full scope for source
            st.session_state.src_creds, st.session_state.src_email, st.session_state.src_service = c, e, s
            st.success(f"Source: **{e}**")
with col2:
    if st.button("Login **New** Gmail", use_container_width=True, type="secondary"):
        with st.spinner("Opening Google..."):
            c, e, s = auth("dest", SCOPES_FULL)  # Full scope for dest
            st.session_state.dst_creds, st.session_state.dst_email, st.session_state.dst_service = c, e, s
            st.success(f"Destination: **{e}**")
with col3:
    if st.button("Clear Logins", use_container_width=True, type="secondary"):
        for account in ["src", "dest"]:
            token_file = TOKEN_DIR / f"token_{USER_ID}_{account}.pkl"
            if token_file.exists():
                token_file.unlink()
        st.session_state.clear()  # Clears session vars
        st.success("Logins cleared — re-login to continue")
        st.rerun()

if getattr(st.session_state, "src_email", None):
    st.info(f"**Source** → {st.session_state.src_email}")
if getattr(st.session_state, "dst_email", None):
    st.info(f"**Destination** → {st.session_state.dst_email}")

# --------------------------------------------------------------
# 6. Transfer Engine
# --------------------------------------------------------------
if not (getattr(st.session_state, "src_service", None) and getattr(st.session_state, "dst_service", None)):
    st.info("Log in to both accounts to start transfer")
    st.stop()

# Rate Limiter
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

limiter = RateLimiter(max_calls=900, period=100)

# API Call with Retry
def api_call(fn, *args, **kwargs):
    retries = 5
    for attempt in range(retries):
        try:
            limiter.wait()
            return fn(*args, **kwargs).execute()
        except HttpError as e:
            if e.resp.status in (429, 500, 502, 503, 504) and attempt < retries-1:
                sleep = (2 ** attempt) + random.random()
                st.toast(f"Rate limit → retry in {sleep:.1f}s", icon="warning")
                time.sleep(sleep)
                continue
            raise

# UI Containers
status = st.empty()
log_exp = st.expander("Transfer Log", expanded=True)
stop_col, _ = st.columns([1, 4])
stop_btn = stop_col.button("STOP TRANSFER", type="secondary", use_container_width=True)

if stop_btn:
    st.session_state.stop_transfer = True

# Core Copy Logic
def ensure_folder(dst_parent: str, name: str, dst_service) -> str:
    res = api_call(
        dst_service.files().list,
        q=f"'{dst_parent}' in parents and mimeType='application/vnd.google-apps.folder' and name='{name}' and trashed=false",
        fields="files(id)", pageSize=1, supportsAllDrives=True
    )
    if res.get("files"):
        return res["files"][0]["id"]

    base, i = name, 1
    while True:
        try:
            folder = api_call(
                dst_service.files().create,
                body={"name": name, "mimeType": "application/vnd.google-apps.folder", "parents": [dst_parent]},
                fields="id", supportsAllDrives=True
            )
            return folder["id"]
        except HttpError as e:
            if "already exists" in str(e).lower():
                name = f"{base} (copy {i})"
                i += 1
                continue
            raise

def share_file(src_service, file_id: str, email: str):
    try:
        api_call(
            src_service.permissions().create,
            fileId=file_id,
            body={"type": "user", "role": "writer", "emailAddress": email},
            sendNotificationEmail=False,
            supportsAllDrives=True
        )
    except HttpError as e:
        if "already" not in str(e).lower() and "insufficientPermissions" not in str(e).lower():
            raise  # Re-raise if not "already shared" or scopes issue

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
            resp = api_call(
                src_svc.files().list,
                q=f"'{src_id}' in parents and trashed=false",
                fields="nextPageToken, files(id,name,mimeType,size)",
                pageSize=1000, pageToken=page_token, supportsAllDrives=True
            )
            children.extend(resp.get("files", []))
            page_token = resp.get("nextPageToken")
            if not page_token: break

        for child in children:
            copy_item(child["id"], new_folder_id, cur_path, src_svc, dst_svc, dest_email)

        log_exp.success(f"Folder **{cur_path}** ({len(children)} items)")

    else:
        try:
            copied = api_call(
                dst_svc.files().copy,
                fileId=src_id,
                body={"parents": [dst_parent]},
                supportsAllDrives=True,
                fields="id"
            )
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
    st.session_state.processed = 0
    st.session_state.total = 0
    st.balloons()

    src = st.session_state.src_service
    dst = st.session_state.dst_service
    dest_email = st.session_state.dst_email

    status.info("Scanning **My Drive**...")
    root_items = []
    page_token = None
    while True:
        resp = api_call(
            src.files().list,
            q="trashed=false and 'root' in parents",
            fields="nextPageToken, files(id,name,mimeType)",
            pageSize=1000, pageToken=page_token, supportsAllDrives=True
        )
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
        st.session_state.processed = idx + 1
        prog.progress((idx + 1) / st.session_state.total)
        st.rerun()

    if not st.session_state.get("stop_transfer", False):
        st.success("FULL DRIVE TRANSFER COMPLETE!")
        st.balloons()
    else:
        st.warning("Transfer stopped. Partial copy completed.")
