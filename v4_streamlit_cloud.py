import streamlit as st
import os, pickle, hashlib, time, atexit, random
from pathlib import Path

# No os.environ needed with google-auth==2.34.0

from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.transport.requests import Request

st.set_page_config(page_title="Drive Transfer", layout="centered")
st.title("Google Drive Transfer")
st.markdown("### Old to New Gmail (Full Copy)")

hide = "<style>#MainMenu,footer,header{visibility:hidden;}</style>"
st.markdown(hide, unsafe_allow_html=True)

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
            st.markdown(f"[Open Google]({auth_url})")
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

st.markdown("### 1. Upload `client_secrets.json`")
uploaded = st.file_uploader("Web App JSON", type="json")
if uploaded:
    (TEMP_DIR / f"client_{USER_ID}.json").write_bytes(uploaded.getbuffer())
    st.success("Loaded")
else:
    st.stop()

col1, col2, col3 = st.columns(3)
with col1:
    if st.button("Old Gmail", type="primary"):
        c,e,s = auth("src")
        st.session_state.src_creds, st.session_state.src_email, st.session_state.src_service = c,e,s
        st.success(f"Source: {e}")
with col2:
    if st.button("New Gmail"):
        c,e,s = auth("dest")
        st.session_state.dst_creds, st.session_state.dst_email, st.session_state.dst_service = c,e,s
        st.success(f"Dest: {e}")
with col3:
    if st.button("Clear"):
        for f in TOKEN_DIR.glob("*"): f.unlink(missing_ok=True)
        for k in list(st.session_state.keys()):
            if k != "uid": del st.session_state[k]
        st.rerun()

if hasattr(st.session_state, "src_email"):
    st.info(f"**Source**: {st.session_state.src_email}")
if hasattr(st.session_state, "dst_email"):
    st.info(f"**Dest**: {st.session_state.dst_email}")

if not (hasattr(st.session_state, "src_service") and hasattr(st.session_state, "dst_service")):
    st.stop()

def api_call(fn, *a, **k):
    for _ in range(5):
        try:
            return fn(*a, **k).execute()
        except HttpError as e:
            if e.resp.status in (429,500,502,503,504):
                time.sleep(2**_ + random.random())
            else:
                raise
    raise

status = st.empty()
log = st.expander("Log", True)
stop = st.button("STOP", type="secondary")
if stop:
    st.session_state.stop_transfer = True

def share(src_svc, fid, email):
    try:
        api_call(src_svc.permissions().create, fileId=fid,
                 body={"type": "user", "role": "writer", "emailAddress": email},
                 sendNotificationEmail=False, supportsAllDrives=True)
    except: pass

def copy_item(src_id, dst_parent, path, src_svc, dst_svc, email):
    if st.session_state.get("stop_transfer"): return
    meta = api_call(src_svc.files().get, fileId=src_id, fields="id,name,mimeType", supportsAllDrives=True)
    name, mime = meta["name"], meta["mimeType"]
    cur = f"{path}/{name}" if path else name
    status.info(cur)
    share(src_svc, src_id, email)
    if mime.endswith("folder"):
        new_id = api_call(dst_svc.files().create,
                          body={"name": name, "mimeType": mime, "parents": [dst_parent]},
                          fields="id", supportsAllDrives=True)["id"]
        kids, pt = [], None
        while True:
            r = api_call(src_svc.files().list, q=f"'{src_id}' in parents and trashed=false",
                         fields="nextPageToken, files(id,name,mimeType)", pageSize=1000, pageToken=pt, supportsAllDrives=True)
            kids.extend(r.get("files", [])); pt = r.get("nextPageToken")
            if not pt: break
        for k in kids:
            copy_item(k["id"], new_id, cur, src_svc, dst_svc, email)
        log.success(f"Folder: {cur}")
    else:
        api_call(dst_svc.files().copy, fileId=src_id, body={"parents": [dst_parent]}, supportsAllDrives=True)
        log.info(f"File: {cur}")

if st.button("START TRANSFER", type="primary"):
    st.session_state.stop_transfer = False
    src, dst, email = st.session_state.src_service, st.session_state.dst_service, st.session_state.dst_email
    items = []
    pt = None
    while True:
        r = api_call(src.files().list, q="'root' in parents and trashed=false",
                     fields="nextPageToken, files(id,name,mimeType)", pageSize=1000, pageToken=pt, supportsAllDrives=True)
        items.extend(r.get("files", [])); pt = r.get("nextPageToken")
        if not pt: break
    for d in api_call(src.drives().list, fields="drives(id,name)").get("drives", []):
        items.append({"id": d["id"], "name": d["name"], "mimeType": "application/vnd.google-apps.folder"})
    prog = st.progress(0)
    for i, item in enumerate(items):
        if st.session_state.get("stop_transfer"): break
        copy_item(item["id"], "root", "", src, dst, email)
        prog.progress((i+1)/len(items))
        st.rerun()
    st.success("DONE!") if not st.session_state.get("stop_transfer") else st.warning("Stopped")
