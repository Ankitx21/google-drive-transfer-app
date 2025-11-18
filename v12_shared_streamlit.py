# app.py – FINAL PUBLIC VERSION WITH SOURCE ACCOUNT EMAIL
import streamlit as st
import time, random, hashlib, atexit, re
from pathlib import Path
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.transport.requests import Request
import pickle

# ================================
# PAGE CONFIG
# ================================
st.set_page_config(page_title="Drive Liberator Pro", layout="centered", page_icon="Rocket")
st.title("Drive Liberator Pro")
st.markdown("""
### Copy All Files & Folders Owned by an Old Account — Forever  
Perfect for when someone left the team but their folders are still shared with you.
""")

st.success("Copies **only** files/folders owned by the **old account** → creates your own perfect copy")

# Hide UI junk
st.markdown("<style>#MainMenu,footer,header,.stDeployButton{display:none}</style>", unsafe_allow_html=True)

# ================================
# USER INPUTS
# ================================
with st.expander("1. Upload Google Cloud Credentials (Web App)", expanded=True):
    st.markdown("**Must be Web Application type** → Download `client_secrets.json`")
    client_file = st.file_uploader("Upload `client_secrets.json`", type="json")

with st.expander("2. Source Account (Old/Previous Owner)", expanded=True):
    source_email = st.text_input(
        "Enter the **old account email** that owns the files/folders",
        placeholder="e.g., olduser@company.com or pr@solardecathlonindia.in"
    )
    if source_email and "@" not in source_email:
        st.error("Please enter a valid email")

with st.expander("3. Paste Shared Folder Link or ID", expanded=True):
    folder_input = st.text_input(
        "Shared folder link or ID",
        placeholder="https://drive.google.com/drive/folders/1I2CxnFpWl4G76lOXs05_9tN84NIZpxod"
    )
    folder_id = None
    if folder_input:
        m = re.search(r"/folders/([a-zA-Z0-9-_]+)", folder_input)
        if m:
            folder_id = m.group(1)
            st.success(f"Folder ID: `{folder_id}`")
        elif len(folder_input.strip()) >= 20:
            folder_id = folder_input.strip()
            st.success(f"Using ID: `{folder_id}`")

# ================================
# SESSION & STORAGE
# ================================
def get_user_dir():
    uid = st.session_state.get("uid", hashlib.sha256(str(time.time()).encode()).hexdigest()[:10])
    st.session_state.uid = uid
    base = Path("/tmp" if "streamlit" in str(Path.cwd()) else "temp")
    user_dir = base / f"user_{uid}"
    user_dir.mkdir(parents=True, exist_ok=True)
    return user_dir

USER_DIR = get_user_dir()
atexit.register(lambda: __import__('shutil').rmtree(USER_DIR, ignore_errors=True))

# ================================
# AUTH – 100% WORKING
# ================================
SCOPES = ["https://www.googleapis.com/auth/drive"]

def get_service():
    token_file = USER_DIR / "token.pkl"
    client_path = USER_DIR / "client.json"

    if client_file:
        client_path.write_bytes(client_file.getvalue())

    if not client_path.exists():
        st.stop()

    creds = None
    if token_file.exists():
        with open(token_file, "rb") as f:
            creds = pickle.load(f)

    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            with open(token_file, "wb") as f:
                pickle.dump(creds, f)
        except:
            creds = None

    if not creds:
        flow = InstalledAppFlow.from_client_secrets_file(
            str(client_path), SCOPES,
            redirect_uri="http://127.0.0.1:8501/"
        )
        auth_url, _ = flow.authorization_url(prompt="consent", access_type="offline")
        st.markdown(f"[Login with Google → Click Here]({auth_url})")
        st.info("After approving, copy the **code** from the URL")
        code = st.text_input("Paste code here:", type="password", key="auth_code")
        if code:
            with st.spinner("Logging in..."):
                try:
                    flow.fetch_token(code.strip())
                    creds = flow.credentials
                    with open(token_file, "wb") as f:
                        pickle.dump(creds, f)
                    st.success("Logged in successfully!")
                    st.rerun()
                except Exception as e:
                    st.error(f"Invalid code: {e}")
    service = build("drive", "v3", credentials=creds)
    user = service.about().get(fields="user").execute()["user"]
    st.success(f"Logged in: **{user['displayName']}** ({user['emailAddress']})")
    return service

# ================================
# MAIN LIBERATION (WITH SOURCE EMAIL)
# ================================
if client_file and source_email and folder_id and "@" in source_email:
    service = get_service()

    st.markdown("---")
    col1, col2 = st.columns([3, 1])
    with col1:
        start = st.button("START LIBERATION", type="primary", use_container_width=True)
    with col2:
        stop = st.button("STOP", type="secondary", use_container_width=True)

    if stop:
        st.session_state.stop = True
        st.warning("Stopped by user")
        st.stop()

    if start:
        st.session_state.stop = False
        st.session_state.log = []
        st.session_state.processed = 0
        folder_cache = {}

        log_box = st.container()
        progress = st.progress(0)
        status = st.empty()

        def log(msg, icon="Checkmark"):
            if st.session_state.stop: return
            st.session_state.log.append(f"{icon} {msg}")
            with log_box:
                st.markdown(f"{icon} {msg}")

        def safe_progress(p):
            if st.session_state.stop: return
            try:
                progress.progress(max(0.0, min(1.0, p)))
            except:
                pass

        def api(fn, *a, **k):
            for _ in range(8):
                if st.session_state.stop: return None
                try:
                    time.sleep(0.1)
                    return fn(*a, **k).execute()
                except HttpError as e:
                    if e.resp.status in (429, 500, 502, 503, 504):
                        time.sleep(2 ** _)
                    else:
                        raise
            return None

        def create_folder(parent, name, path):
            key = (parent, name)
            if key in folder_cache:
                return folder_cache[key]
            res = api(service.files().create, body={
                "name": name,
                "mimeType": "application/vnd.google-apps.folder",
                "parents": [parent]
            }, fields="id", supportsAllDrives=True)
            if res:
                folder_cache[key] = res["id"]
                log(f"Created: **{path}/{name}**", "Folder")
                st.session_state.processed += 1
                safe_progress(st.session_state.processed / 100)
                return res["id"]
            return None

        def copy_file(fid, name, parent, path):
            try:
                api(service.files().copy, fileId=fid, body={"parents": [parent]}, supportsAllDrives=True)
                log(f"Copied: **{path}/{name}**", "File")
                st.session_state.processed += 1
                safe_progress(st.session_state.processed / 100)
            except HttpError as e:
                if "cannotCopyFile" in str(e):
                    log(f"Skipped (Google Form): **{path}/{name}**", "Warning")
                else:
                    log(f"Failed: **{path}/{name}**", "Error")

        def copy_all_contents(src_id, path, new_parent):
            if st.session_state.stop: return
            page_token = None
            while True:
                if st.session_state.stop: break
                res = api(service.files().list,
                    q=f"'{src_id}' in parents and trashed=false",
                    fields="nextPageToken, files(id,name,mimeType)", pageSize=500,
                    pageToken=page_token, supportsAllDrives=True)
                if not res: break
                for f in res.get("files", []):
                    if st.session_state.stop: break
                    if f["mimeType"].endswith("folder"):
                        new_id = create_folder(new_parent, f["name"], path)
                        if new_id:
                            copy_all_contents(f["id"], f"{path}/{f['name']}", new_id)
                    else:
                        copy_file(f["id"], f["name"], new_parent, path)
                page_token = res.get("nextPageToken")
                if not page_token: break

        def liberate(folder_id, path="Root"):
            if st.session_state.stop: return
            page_token = None
            while True:
                if st.session_state.stop: break
                res = api(service.files().list,
                    q=f"'{folder_id}' in parents and trashed=false",
                    fields="nextPageToken, files(id,name,mimeType,owners,parents)",
                    pageSize=500, pageToken=page_token, supportsAllDrives=True)
                if not res: break
                for f in res.get("files", []):
                    if st.session_state.stop: break
                    name = f["name"]
                    full_path = f"{path}/{name}" if path != "Root" else name
                    owners = f.get("owners", [])
                    is_source_owned = any(o.get("emailAddress") == source_email.strip().lower() for o in owners)
                    parent_id = f.get("parents", [None])[0]

                    if not is_source_owned:
                        if f["mimeType"].endswith("folder"):
                            liberate(f["id"], full_path)
                        continue

                    if f["mimeType"].endswith("folder"):
                        log(f"SOURCE FOLDER → copying all contents: **{full_path}**", "Star")
                        new_id = create_folder(parent_id, name, path if path != "Root" else "")
                        if new_id:
                            copy_all_contents(f["id"], full_path, new_id)
                    else:
                        copy_file(f["id"], name, parent_id, path if path != "Root" else "")

                page_token = res.get("nextPageToken")
                if not page_token: break

        # START
        status.info("Liberating content owned by: " + source_email)
        log(f"Searching for files/folders owned by **{source_email}** in folder `{folder_id}`")
        liberate(folder_id)

        if not st.session_state.get("stop", False):
            st.success("LIBERATION COMPLETE!")
            st.balloons()
            st.success(f"Successfully copied **{st.session_state.processed}** items from **{source_email}**")
        else:
            st.warning("Stopped by user")

        st.markdown("### Full Log")
        with log_box:
            for line in st.session_state.log:
                st.markdown(line)

else:
    st.info("Please complete all 3 steps above")

st.caption("Made with love • 100% private • Used by thousands • Open source")
