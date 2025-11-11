import streamlit as st
import os, pickle, hashlib, time, atexit, random
from pathlib import Path
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.transport.requests import Request

# --------------------------------------------------------------
# 1. Page Setup
# --------------------------------------------------------------
st.set_page_config(page_title="Drive Transfer Pro", layout="centered")
st.title("Google Drive Transfer Pro")
st.markdown("### **Old to New Gmail — Full Copy with Live Logs**")

hide = "<style>#MainMenu,footer,header{visibility:hidden;}</style>"
st.markdown(hide, unsafe_allow_html=True)

# --------------------------------------------------------------
# 2. Session & Cleanup
# --------------------------------------------------------------
def uid():
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
# 3. OAuth
# --------------------------------------------------------------
SCOPES = ["https://www.googleapis.com/auth/drive"]

def auth(account):
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
                str(client_path), SCOPES, redirect_uri="http://127.0.0.1:8501/"
            )
            auth_url, _ = flow.authorization_url(prompt="consent", access_type="offline")
            st.markdown(f"**{account.upper()} Account**")
            st.markdown(f"[Open Google Sign-In]({auth_url})")
            code = st.text_input("Paste code (4/...):", key=f"code_{account}")
            if code:
                try:
                    flow.fetch_token(code=code)
                    creds = flow.credentials
                    with token_file.open("wb") as f:
                        pickle.dump(creds, f)
                    st.success("Logged in!")
                except Exception as e:
                    st.error(f"Error: {e}")
                    st.stop()

    service = build("drive", "v3", credentials=creds)
    email = service.about().get(fields="user/emailAddress").execute()["user"]["emailAddress"]
    return creds, email, service

# --------------------------------------------------------------
# 4. Upload
# --------------------------------------------------------------
st.markdown("### 1. Upload `client_secrets.json` (Web App)")
uploaded = st.file_uploader("Choose file", type="json")
if uploaded:
    (TEMP_DIR / f"client_{USER_ID}.json").write_bytes(uploaded.getbuffer())
    st.success("`client_secrets.json` loaded")
else:
    st.stop()

# --------------------------------------------------------------
# 5. Login
# --------------------------------------------------------------
col1, col2, col3 = st.columns(3)
with col1:
    if st.button("Old Gmail", type="primary", use_container_width=True):
        c,e,s = auth("src")
        st.session_state.src_creds, st.session_state.src_email, st.session_state.src_service = c,e,s
with col2:
    if st.button("New Gmail", use_container_width=True):
        c,e,s = auth("dest")
        st.session_state.dst_creds, st.session_state.dst_email, st.session_state.dst_service = c,e,s
with col3:
    if st.button("Clear All", use_container_width=True):
        for f in TOKEN_DIR.glob("*"): f.unlink(missing_ok=True)
        for k in list(st.session_state.keys()):
            if k != "uid": del st.session_state[k]
        st.rerun()

if hasattr(st.session_state, "src_email"):
    st.info(f"**Source**: {st.session_state.src_email}")
if hasattr(st.session_state, "dst_email"):
    st.info(f"**Destination**: {st.session_state.dst_email}")

# --------------------------------------------------------------
# 6. Transfer Engine
# --------------------------------------------------------------
if not (hasattr(st.session_state, "src_service") and hasattr(st.session_state, "dst_service")):
    st.stop()

# Initialize
if "log" not in st.session_state:
    st.session_state.log = []
    st.session_state.processed = 0
    st.session_state.total = 0
    st.session_state.status = "Ready"

# Live Log Container
log_container = st.container()
status_placeholder = st.empty()
progress_bar = st.progress(0)

def log(msg, icon=""):
    st.session_state.log.append(f"{icon} {msg}")
    with log_container:
        st.markdown(f"{icon} {msg}", unsafe_allow_html=True)

def update_status(msg):
    st.session_state.status = msg
    status_placeholder.info(msg)

def api_call(fn, *a, **k):
    for _ in range(5):
        try:
            time.sleep(0.11)  # Rate limit
            return fn(*a, **k).execute()
        except HttpError as e:
            if e.resp.status in (429,500,502,503,504):
                time.sleep(2**_ + random.random())
            else:
                raise
    raise

def share_file(src_svc, file_id, email):
    try:
        api_call(src_svc.permissions().create, fileId=file_id,
                 body={"type": "user", "role": "writer", "emailAddress": email},
                 sendNotificationEmail=False, supportsAllDrives=True)
    except Exception as e:
        log(f"Share failed: {e}", "Warning")

def copy_item(src_id, dst_parent, path, src_svc, dst_svc, email):
    if st.session_state.get("stop_transfer", False):
        return

    try:
        meta = api_call(src_svc.files().get, fileId=src_id, fields="id,name,mimeType,size", supportsAllDrives=True)
        name, mime = meta["name"], meta["mimeType"]
        full_path = f"{path}/{name}" if path else name

        update_status(f"Transferring: **{full_path}**")

        share_file(src_svc, src_id, email)

        if mime == "application/vnd.google-apps.folder":
            folder = api_call(dst_svc.files().create,
                              body={"name": name, "mimeType": mime, "parents": [dst_parent]},
                              fields="id", supportsAllDrives=True)
            new_id = folder["id"]

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

            log(f"Folder: {full_path} ({len(children)} items)", "Folder")

            for child in children:
                copy_item(child["id"], new_id, full_path, src_svc, dst_svc, email)

            log(f"Folder transferred: {full_path}", "Checkmark")

        else:
            api_call(dst_svc.files().copy, fileId=src_id,
                     body={"parents": [dst_parent]}, supportsAllDrives=True)
            size = meta.get("size", "—")
            log(f"File transferred: {full_path} ({size} B)", "Checkmark")

        st.session_state.processed += 1
        progress_bar.progress(st.session_state.processed / st.session_state.total)

    except Exception as e:
        log(f"Failed: {full_path} → {str(e)}", "X")

# --------------------------------------------------------------
# 7. Start Transfer
# --------------------------------------------------------------
if st.button("START FULL TRANSFER", type="primary", use_container_width=True):
    st.session_state.stop_transfer = False
    st.session_state.log = []
    st.session_state.processed = 0
    st.session_state.status = "Scanning..."
    log_container.empty()
    status_placeholder.empty()
    progress_bar.progress(0)

    src = st.session_state.src_service
    dst = st.session_state.dst_service
    email = st.session_state.dst_email

    update_status("Scanning My Drive...")
    items = []
    page_token = None
    while True:
        resp = api_call(src.files().list,
                        q="trashed=false and 'root' in parents",
                        fields="nextPageToken, files(id,name,mimeType)",
                        pageSize=1000, pageToken=page_token, supportsAllDrives=True)
        items.extend(resp.get("files", []))
        page_token = resp.get("nextPageToken")
        if not page_token: break

    update_status("Scanning Shared Drives...")
    drives = api_call(src.drives().list, pageSize=100, fields="drives(id,name)").get("drives", [])
    for d in drives:
        items.append({"id": d["id"], "name": d["name"], "mimeType": "application/vnd.google-apps.folder"})

    st.session_state.total = len(items)
    log(f"Found {len(items)} root items to transfer", "MagnifyingGlass")

    for idx, item in enumerate(items):
        if st.session_state.get("stop_transfer", False):
            log("Transfer stopped by user", "StopSign")
            break
        copy_item(item["id"], "root", "", src, dst, email)

    if not st.session_state.get("stop_transfer", False):
        st.success("**TRANSFER COMPLETE!**")
        st.balloons()
    else:
        st.warning("Transfer stopped.")

# Stop Button
if st.button("STOP TRANSFER", type="secondary"):
    st.session_state.stop_transfer = True
    st.rerun()

# Live Status
if st.session_state.get("status"):
    status_placeholder.info(st.session_state.status)

# Progress
if st.session_state.get("total", 0) > 0:
    progress_bar.progress(st.session_state.processed / st.session_state.total)
    st.caption(f"**{st.session_state.processed} / {st.session_state.total}** items processed")

# Live Log
if st.session_state.get("log"):
    st.markdown("### Live Transfer Log")
    with log_container:
        for entry in st.session_state.log:
            st.markdown(entry, unsafe_allow_html=True)
