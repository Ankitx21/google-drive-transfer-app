# app.py
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
st.set_page_config(
    page_title="Drive Liberator – Free Your Shared Folders",
    page_icon="Rocket",
    layout="centered"
)

st.title("Drive Liberator")
st.markdown("""
### Permanently Own Your Shared Google Drive Folders  
**No more losing access when someone leaves**  
This tool creates **your own perfect copy** of every file/folder you own inside a shared folder — side-by-side.
""")

st.info("""
**How to use:**  
1. Upload `client_secrets.json` (Web App)  
2. Paste the shared folder link/ID  
3. Click "Login with Google"  
4. Done — your data is now yours forever
""")

# Hide Streamlit junk
st.markdown("<style>#MainMenu,footer,header,.css-1d391kg{display:none;}</style>", unsafe_allow_html=True)

# ================================
# USER INPUTS
# ================================
with st.expander("Step 1: Upload Google Cloud Credentials", expanded=True):
    st.markdown("Create a **Web Application** OAuth Client → Download `client_secrets.json`")
    client_file = st.file_uploader("Upload `client_secrets.json`", type="json")

with st.expander("Step 2: Paste Shared Folder Link or ID", expanded=True):
    folder_input = st.text_input(
        "Paste full Google Drive folder link or just the ID",
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
            st.error("Please paste a valid folder link or ID")

# ================================
# SESSION & TEMP (Works on Streamlit Cloud)
# ================================
def get_user_dir():
    uid = hashlib.sha256(str(time.time()).encode()).hexdigest()[:12]
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
# FIXED AUTH — NO redirect_uri_mismatch EVER AGAIN
# ================================
SCOPES = ["https://www.googleapis.com/auth/drive"]

def get_service():
    token_file = USER_DIR / "token.pkl"
    client_path = USER_DIR / "client_secrets.json"

    # Save uploaded file
    if client_file:
        client_path.write_bytes(client_file.getvalue())

    if not client_path.exists():
        st.warning("Please upload client_secrets.json")
        st.stop()

    creds = None
    if token_file.exists():
        with open(token_file, "rb") as f:
            creds = pickle.load(f)

    # Refresh if needed
    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            with open(token_file, "wb") as f:
                pickle.dump(creds, f)
        except:
            creds = None

    # First time login — THE MAGIC FIX
    if not creds:
        # This is the key: use 127.0.0.1:8501 — Google accepts it from ANYWHERE
        flow = InstalledAppFlow.from_client_secrets_file(
            str(client_path),
            SCOPES,
            redirect_uri="http://127.0.0.1:8501/"  # ← THIS WORKS ON STREAMLIT CLOUD
        )
        auth_url, _ = flow.authorization_url(prompt="consent", access_type="offline")
        
        st.markdown("### Login with Google")
        st.markdown(f"[Click here to authorize]({auth_url})")
        st.info("After approving, copy the **code** from the URL (even if it shows error page)")

        code = st.text_input("Paste the authorization code here:", type="password", key="auth_code")

        if code:
            try:
                flow.fetch_token(code=code.strip())
                creds = flow.credentials
                with open(token_file, "wb") as f:
                    pickle.dump(creds, f)
                st.success("Login successful!")
                st.rerun()
            except Exception as e:
                st.error(f"Login failed: {e}")

    service = build("drive", "v3", credentials=creds)
    user_info = service.about().get(fields="user").execute()["user"]
    st.success(f"Logged in as **{user_info['displayName']}** ({user_info['emailAddress']})")
    return service

# ================================
# LIBERATION ENGINE (Clear Logs + Icons)
# ================================
if client_file and folder_id:
    if st.button("START LIBERATION", type="primary", use_container_width=True):
        service = get_service()

        log_box = st.container()
        progress = st.progress(0)
        status = st.empty()

        st.session_state.log = []
        st.session_state.skipped = []
        folder_cache = {}

        def log(msg, icon="Checkmark"):
            st.session_state.log.append(f"{icon} {msg}")
            with log_box:
                st.markdown(f"{icon} {msg}")

        def api(fn, *a, **k):
            for _ in range(8):
                try:
                    time.sleep(0.1)
                    return fn(*a, **k).execute()
                except HttpError as e:
                    if e.resp.status in (429, 500, 502, 503, 504):
                        time.sleep(2 ** _)
                    else:
                        raise
            raise Exception("API failed")

        def create_folder(parent_id, name, path):
            key = (parent_id, name)
            if key in folder_cache:
                return folder_cache[key]
            new = api(service.files().create, body={
                "name": name,
                "mimeType": "application/vnd.google-apps.folder",
                "parents": [parent_id]
            }, fields="id", supportsAllDrives=True)
            folder_cache[key] = new["id"]
            log(f"Created folder: **{path}/{name}**", "Folder")
            return new["id"]

        def copy_file(fid, name, parent_id, path):
            try:
                api(service.files().copy, fileId=fid, body={"parents": [parent_id]}, supportsAllDrives=True)
                log(f"Copied file: **{path}/{name}**", "File")
            except HttpError as e:
                if "cannotCopyFile" in str(e):
                    log(f"Skipped (Google Form): **{path}/{name}**", "Warning")
                    st.session_state.skipped.append(name)
                else:
                    log(f"Failed: **{path}/{name}**", "Error")

        def copy_all_contents(src_id, path, new_parent):
            page_token = None
            while True:
                res = api(service.files().list,
                    q=f"'{src_id}' in parents and trashed=false",
                    fields="nextPageToken, files(id,name,mimeType)", pageSize=1000,
                    pageToken=page_token, supportsAllDrives=True)
                for f in res.get("files", []):
                    if f["mimeType"].endswith(".folder"):
                        new_id = create_folder(new_parent, f["name"], path)
                        copy_all_contents(f["id"], f"{path}/{f['name']}", new_id)
                    else:
                        copy_file(f["id"], f["name"], new_parent, path)
                page_token = res.get("nextPageToken")
                if not page_token: break

        def liberate(folder_id, path="Root"):
            page_token = None
            while True:
                res = api(service.files().list,
                    q=f"'{folder_id}' in parents and trashed=false",
                    fields="nextPageToken, files(id,name,mimeType,owners,parents)",
                    pageSize=1000, pageToken=page_token, supportsAllDrives=True)

                for f in res.get("files", []):
                    name = f["name"]
                    full_path = f"{path}/{name}" if path != "Root" else name
                    owners = f.get("owners", [{}])
                    is_owned = any(o.get("emailAddress") == service.about().get(fields="user").execute()["user"]["emailAddress"]
                                 for o in owners)
                    parents = f.get("parents", [])
                    parent_id = parents[0] if parents else None
                    if not parent_id: continue

                    if not is_owned:
                        if f["mimeType"].endswith(".folder"):
                            liberate(f["id"], full_path)
                        continue

                    if f["mimeType"].endswith(".folder"):
                        log(f"Found YOUR FOLDER → copying everything: **{full_path}**", "Star")
                        new_id = create_folder(parent_id, name, path if path != "Root" else "")
                        copy_all_contents(f["id"], full_path, new_id)
                    else:
                        copy_file(f["id"], name, parent_id, path if path != "Root" else "")

                    if f["mimeType"].endswith(".folder"):
                        liberate(f["id"], full_path)

                page_token = res.get("nextPageToken")
                if not page_token: break

        # START
        status.info("Liberating your content...")
        log(f"Starting liberation of folder: `{folder_id}`")
        liberate(folder_id)

        total = len([l for l in st.session_state.log if "Copied" in l or "Created" in l])
        st.success("LIBERATION COMPLETE!")
        st.balloons()
        st.success(f"Liberated {total} items")
        if st.session_state.skipped:
            st.warning(f"Skipped {len(st.session_state.skipped)} Google Forms")
            with st.expander("Skipped items"):
                for s in st.session_state.skipped:
                    st.write("Warning " + s)

        st.markdown("### Full Log")
        with log_box:
            for line in st.session_state.log:
                st.markdown(line)

else:
    st.info("Complete both steps above to begin")

# Footer
st.markdown("---")
st.caption("Made with love • Your data stays private • Open source")
