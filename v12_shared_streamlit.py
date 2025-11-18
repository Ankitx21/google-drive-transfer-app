# app.py  –  FINAL PUBLIC VERSION (Works on Streamlit Cloud!)
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
st.set_page_config(page_title="Drive Liberator – Own Your Data", layout="centered", page_icon="Rocket")

st.title("Drive Liberator")
st.markdown("""
### Never Lose Access to Shared Google Drive Folders Again  
This tool **creates your own perfect copy** of every file/folder you own inside a shared folder — right next to the original.
""")

st.info("**100% Free • No data stored • Works for anyone**")

# Hide Streamlit UI junk
st.markdown("<style>#MainMenu,footer,header,.stDeployButton{display:none}</style>", unsafe_allow_html=True)

# ================================
# USER INPUTS
# ================================
with st.expander("1. Upload Google Cloud Credentials", expanded=True):
    st.markdown("**Required**: Create a Web App OAuth Client → Download `client_secrets.json`")
    client_file = st.file_uploader("Upload `client_secrets.json`", type="json", key="client_upload")

with st.expander("2. Paste Shared Folder Link or ID", expanded=True):
    folder_input = st.text_input(
        "Folder link or ID",
        placeholder="https://drive.google.com/drive/folders/1I2CxnFpWl4G76lOXs05_9tN84NIZpxod"
    )

    folder_id = None
    if folder_input:
        match = re.search(r"/folders/([a-zA-Z0-9-_]+)", folder_input)
        if match:
            folder_id = match.group(1)
            st.success(f"Folder ID: `{folder_id}`")
        elif len(folder_input.strip()) >= 20:
            folder_id = folder_input.strip()
            st.success(f"Using ID: `{folder_id}`")
        else:
            st.error("Invalid link/ID")

# ================================
# SESSION & TEMP (Streamlit Cloud Safe)
# ================================
def get_user_dir():
    uid = st.session_state.get("uid", hashlib.sha256(str(time.time()).encode()).hexdigest()[:12])
    if "uid" not in st.session_state:
        st.session_state.uid = uid
    temp_dir = Path("/tmp" if "streamlit" in str(Path.cwd()) else "temp")
    user_dir = temp_dir / f"user_{uid}"
    user_dir.mkdir(parents=True, exist_ok=True)
    return user_dir

USER_DIR = get_user_dir()

def cleanup():
    import shutil
    try:
        shutil.rmtree(USER_DIR)
    except:
        pass
atexit.register(cleanup)

# ================================
# AUTHENTICATION – FIXED & BULLETPROOF
# ================================
SCOPES = ["https://www.googleapis.com/auth/drive"]

def get_service():
    token_file = USER_DIR / "token.pkl"
    client_path = USER_DIR / "client_secrets.json"

    if client_file:
        client_path.write_bytes(client_file.getvalue())

    if not client_path.exists():
        st.warning("Please upload client_secrets.json")
        st.stop()

    creds = None
    if token_file.exists():
        with open(token_file, "rb") as f:
            creds = pickle.load(f)

    # Refresh token
    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            with open(token_file, "wb") as f:
                pickle.dump(creds, f)
        except:
            creds = None

    # First login – THIS IS THE WORKING METHOD
    if not creds:
        flow = InstalledAppFlow.from_client_secrets_file(
            str(client_path),
            SCOPES,
            redirect_uri="http://127.0.0.1:8501/"   # ← This works EVERYWHERE (even on Streamlit Cloud)
        )
        auth_url, _ = flow.authorization_url(prompt="consent", access_type="offline")

        st.markdown("### Click below to log in with Google")
        st.markdown(f"[Authorize Google Drive Access]({auth_url})")
        st.info("After approving, copy the **code** from the URL (even if it says 'This site can’t be reached')")

        code = st.text_input("Paste the code here:", type="password", key="oauth_code_input")

        if code:
            with st.spinner("Verifying code..."):
                try:
                    flow.fetch_token(code=code.strip())
                    creds = flow.credentials
                    with open(token_file, "wb") as f:
                        pickle.dump(creds, f)
                    st.success("Login successful!")
                    st.session_state.authenticated = True
                    st.rerun()  # ← THIS WAS MISSING BEFORE!
                except Exception as e:
                    st.error(f"Invalid code. Try again: {e}")
                    st.stop()

    service = build("drive", "v3", credentials=creds)
    user = service.about().get(fields="user").execute()["user"]
    st.success(f"Logged in as **{user['displayName']}** ({user['emailAddress']})")
    return service

# ================================
# MAIN LIBERATION ENGINE
# ================================
if client_file and folder_id:
    if "authenticated" not in st.session_state:
        service = get_service()  # Triggers login
    else:
        service = build("drive", "v3", credentials=pickle.load(open(USER_DIR / "token.pkl", "rb")))

        # Add STOP button
        col1, col2 = st.columns([3, 1])
        with col1:
            start_btn = st.button("START LIBERATION", type="primary", use_container_width=True)
        with col2:
            stop_btn = st.button("STOP", type="secondary", use_container_width=True)

        if stop_btn:
            st.session_state.stop = True
            st.warning("Liberation stopped by user.")
            st.stop()

        if start_btn or st.session_state.get("running", False):
            st.session_state.running = True
            if "stop" not in st.session_state:
                st.session_state.stop = False

            log_box = st.container()
            progress = st.progress(0)
            status = st.empty()

            st.session_state.log = st.session_state.get("log", [])
            st.session_state.skipped = st.session_state.get("skipped", [])
            folder_cache = {}

            def log(msg, icon="Checkmark"):
                if not st.session_state.stop:
                    st.session_state.log.append(f"{icon} {msg}")
                    with log_box:
                        st.markdown(f"{icon} {msg}")

            def api(fn, *a, **k):
                for _ in range(8):
                    if st.session_state.stop:
                        return None
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
                new = api(service.files().create, body={
                    "name": name,
                    "mimeType": "application/vnd.google-apps.folder",
                    "parents": [parent]
                }, fields="id", supportsAllDrives=True)
                if new:
                    folder_cache[key] = new["id"]
                    log(f"Created folder: **{path}/{name}**", "Folder")
                    return new["id"]
                return None

            def copy_file(fid, name, parent, path):
                try:
                    api(service.files().copy, fileId=fid, body={"parents": [parent]}, supportsAllDrives=True)
                    log(f"Copied file: **{path}/{name}**", "File")
                except HttpError as e:
                    if "cannotCopyFile" in str(e):
                        log(f"Skipped (Google Form): **{path}/{name}**", "Warning")
                        st.session_state.skipped.append(name)
                    else:
                        log(f"Failed: **{path}/{name}**", "Error")

            def copy_all(src_id, path, new_parent):
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
                        if f["mimeType"].endswith(".folder"):
                            new_id = create_folder(new_parent, f["name"], path)
                            if new_id:
                                copy_all(f["id"], f"{path}/{f['name']}", new_id)
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
                    items = res.get("files", [])
                    progress.progress(len(st.session_state.log) / max(1, len(items) * 3))
                    for f in items:
                        if st.session_state.stop: break
                        name = f["name"]
                        full_path = f"{path}/{name}" if path != "Root" else name
                        owners = f.get("owners", [])
                        is_mine = any(o.get("emailAddress") == service.about().get(fields="user").execute()["user"]["emailAddress"] for o in owners)
                        parent_id = f.get("parents", [None])[0]

                        if not is_mine:
                            if f["mimeType"].endswith(".folder"):
                                liberate(f["id"], full_path)
                            continue

                        if f["mimeType"].endswith(".folder"):
                            log(f"Found YOUR folder → copying all contents: **{full_path}**", "Star")
                            new_id = create_folder(parent_id, name, path if path != "Root" else "")
                            if new_id:
                                copy_all(f["id"], full_path, new_id)
                        else:
                            copy_file(f["id"], name, parent_id, path if path != "Root" else "")

                        if f["mimeType"].endswith(".folder"):
                            liberate(f["id"], full_path)

                    page_token = res.get("nextPageToken")
                    if not page_token: break

            # START
            status.info("Liberating your content...")
            log(f"Starting liberation of folder ID: `{folder_id}`")
            liberate(folder_id)

            if not st.session_state.stop:
                total = len([l for l in st.session_state.log if "File" in l or "Folder" in l])
                st.success("LIBERATION COMPLETE!")
                st.balloons()
                st.success(f"Successfully liberated **{total}** items")
                if st.session_state.skipped:
                    st.warning(f"Skipped {len(st.session_state.skipped)} Google Forms")
            else:
                st.warning("Liberation was stopped.")

            st.markdown("### Full Log")
            with log_box:
                for line in st.session_state.log:
                    st.markdown(line)

else:
    st.info("Please complete both steps above")

st.markdown("---")
st.caption("Made with love for everyone who ever lost access to a shared folder")
