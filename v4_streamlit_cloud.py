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
# 4. Upload client_secrets.json
# --------------------------------------------------------------
st.markdown("### 1. Upload `client_secrets.json` (Web App)")
uploaded = st.file_uploader("Choose file", type="json")
if uploaded:
    (TEMP_DIR / f"client_{USER_ID}.json").write_bytes(uploaded.getbuffer())
    st.success("`client_secrets.json` loaded")
else:
    st.stop()

# --------------------------------------------------------------
# 5. Login + Auto Show Transfer Button
# --------------------------------------------------------------
col1, col2, col3 = st.columns(3)
with col1:
    if st.button("Old Gmail", type="primary", use_container_width=True):
        c, e, s = auth("src")
        st.session_state.src_creds = c
        st.session_state.src_email = e
        st.session_state.src_service = s
        st.success(f"Source: {e}")
        st.rerun()
with col2:
    if st.button("New Gmail", use_container_width=True):
        c, e, s = auth("dest")
        st.session_state.dst_creds = c
        st.session_state.dst_email = e
        st.session_state.dst_service = s
        st.success(f"Dest: {e}")
        st.rerun()
with col3:
    if st.button("Clear All", use_container_width=True):
        for f in TOKEN_DIR.glob("*"): f.unlink(missing_ok=True)
        for k in list(st.session_state.keys()):
            if k not in ["uid", "log", "status", "processed", "total"]:
                del st.session_state[k]
        st.rerun()

# Show emails
if getattr(st.session_state, "src_email", None):
    st.info(f"**Source**: {st.session_state.src_email}")
if getattr(st.session_state, "dst_email", None):
    st.info(f"**Destination**: {st.session_state.dst_email}")

# Show transfer button only if both ready
if (getattr(st.session_state, "src_service", None) and
    getattr(st.session_state, "dst_service", None)):
    st.markdown("---")
    st.markdown("### Ready to Transfer!")
    st.success("Both accounts authenticated")
else:
    st.warning("Please login to **both** accounts to start transfer")
    st.stop()

# --------------------------------------------------------------
# 6. Transfer Engine (FIXED)
# --------------------------------------------------------------
if "log" not in st.session_state:
    st.session_state.log = []
    st.session_state.processed = 0
    st.session_state.total = 0
    st.session_state.status = "Ready"

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
            time.sleep(0.11)
            return fn(*a, **k).execute()
        except HttpError as e:
            if e.resp.status in (429, 500, 502, 503, 504):
                time.sleep(2**_ + random.random())
            else:
                raise
    raise Exception("Max retries exceeded")

def share_file(src_svc, file_id, email):
    try:
        api_call(src_svc.permissions().create, fileId=file_id,
                 body={"type": "user", "role": "writer", "emailAddress": email},
                 sendNotificationEmail=False, supportsAllDrives=True)
    except Exception as e:
        log(f"Share failed: {e}", "Warning")

# ---- PRE-COUNT: Count every file and folder ----
def count_items(src_svc, file_id):
    meta = api_call(src_svc.files().get, fileId=file_id,
                    fields="id,name,mimeType", supportsAllDrives=True)
    if meta["mimeType"] == "application/vnd.google-apps.folder":
        folder_cnt = 1
        file_cnt = 0
        page_token = None
        while True:
            resp = api_call(src_svc.files().list,
                            q=f"'{file_id}' in parents and trashed=false",
                            fields="nextPageToken, files(id,name,mimeType)",
                            pageSize=1000, pageToken=page_token,
                            supportsAllDrives=True)
            children = resp.get("files", [])
            for child in children:
                f, d = count_items(src_svc, child["id"])
                file_cnt += f
                folder_cnt += d
            page_token = resp.get("nextPageToken")
            if not page_token: break
        return file_cnt, folder_cnt
    else:
        return 1, 0

# ---- COPY ITEM: Increment once per item ----
def copy_item(src_id, dst_parent, path, src_svc, dst_svc, email):
    if st.session_state.get("stop_transfer", False):
        return

    try:
        meta = api_call(src_svc.files().get, fileId=src_id,
                        fields="id,name,mimeType,size", supportsAllDrives=True)
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
                                pageSize=1000, pageToken=page_token,
                                supportsAllDrives=True)
                children.extend(resp.get("files", []))
                page_token = resp.get("nextPageToken")
                if not page_token: break

            log(f"Folder: {full_path} ({len(children)} items)", "Folder")
            for child in children:
                copy_item(child["id"], new_id, full_path, src_svc, dst_svc, email)

            log(f"Folder transferred: {full_path}", "Checkmark")
            st.session_state.processed += 1  # Only once

        else:
            api_call(dst_svc.files().copy, fileId=src_id,
                     body={"parents": [dst_parent]}, supportsAllDrives=True)
            size = meta.get("size", "—")
            log(f"File transferred: {full_path} ({size} B)", "Checkmark")
            st.session_state.processed += 1  # Only once

        # Safe progress
        if st.session_state.total > 0:
            prog = min(st.session_state.processed / st.session_state.total, 1.0)
            progress_bar.progress(prog)

    except Exception as e:
        log(f"Failed: {full_path} → {str(e)}", "X")
        st.session_state.processed += 1
        if st.session_state.total > 0:
            prog = min(st.session_state.processed / st.session_state.total, 1.0)
            progress_bar.progress(prog)

# --------------------------------------------------------------
# 7. Start Transfer Button
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

    update_status("Scanning My Drive & Shared Drives…")

    # Collect root items
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

    drives = api_call(src.drives().list, pageSize=100,
                      fields="drives(id,name)").get("drives", [])
    for d in drives:
        root_items.append({"id": d["id"], "name": d["name"],
                           "mimeType": "application/vnd.google-apps.folder"})

    # PRE-COUNT EVERYTHING
    total_files = total_folders = 0
    for item in root_items:
        f, d = count_items(src, item["id"])
        total_files += f
        total_folders += d
    st.session_state.total = total_files + total_folders

    log(f"Found {st.session_state.total} items (files + folders) to transfer", "MagnifyingGlass")

    # Transfer each root item
    for item in root_items:
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

# Live UI
if st.session_state.get("status"):
    status_placeholder.info(st.session_state.status)
if st.session_state.get("total", 0) > 0:
    prog = min(st.session_state.processed / st.session_state.total, 1.0)
    progress_bar.progress(prog)
    st.caption(f"**{st.session_state.processed} / {st.session_state.total}** items processed")
if st.session_state.get("log"):
    st.markdown("### Live Transfer Log")
    with log_container:
        for entry in st.session_state.log:
            st.markdown(entry, unsafe_allow_html=True)
