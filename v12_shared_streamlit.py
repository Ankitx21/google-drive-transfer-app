# app.py
import streamlit as st
import time, random, hashlib, atexit
from pathlib import Path
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.transport.requests import Request
import pickle
import re

# ================================
# PAGE CONFIG & STYLE
# ================================
st.set_page_config(
    page_title="Drive Liberator – Free Your Shared Folders",
    page_icon="https://em-content.zobj.net/thumbs/120/google/350/rocket_1f680.png",
    layout="centered"
)

st.title("Drive Liberator")
st.markdown("""
### Free Your Shared Google Drive Folders Forever  
**If a folder was shared with you but owned by someone else** → this tool creates **your own perfect copy** (side-by-side) so you never lose access — even if the original owner leaves.
""")

st.info("""
**How it works:**  
1. Upload your Google Cloud `client_secrets.json`  
2. Paste the shared folder link or ID  
3. Log in with your Google account  
4. Click Start → Get full ownership of your data
""")

hide = """
<style>
    #MainMenu, footer, header {visibility: hidden;}
    .css-1d391kg {display: none;}
    .stDeployButton {display: none;}
</style>
"""
st.markdown(hide, unsafe_allow_html=True)

# ================================
# CONFIG (User Inputs)
# ================================
with st.expander("Step 1: Upload Google Cloud Credentials", expanded=True):
    st.markdown("**Required:** Create a [Google Cloud OAuth Client ID (Web Application)](https://console.cloud.google.com/apis/credentials)")
    client_file = st.file_uploader(
        "Upload `client_secrets.json` (Web App type)",
        type="json",
        help="Download from Google Cloud Console → Credentials → OAuth Client ID → Web Application"
    )

with st.expander("Step 2: Paste Shared Folder Link or ID", expanded=True):
    folder_input = st.text_input(
        "Paste Google Drive folder link or ID",
        placeholder="e.g., https://drive.google.com/drive/folders/1I2CxnFpWl4G76lOXs05_9tN84NIZpxod"
    )

    folder_id = None
    if folder_input:
        match = re.search(r"/folders/([a-zA-Z0-9-_]+)", folder_input)
        if match:
            folder_id = match.group(1)
            st.success(f"Folder ID detected: `{folder_id}`")
        elif len(folder_input) in (33, 28):
            folder_id = folder_input.strip()
            st.success(f"Valid Folder ID: `{folder_id}`")
        else:
            st.error("Invalid link or ID. Please paste a correct folder link or ID.")

# ================================
# SESSION & TEMP
# ================================
def uid():
    if "uid" not in st.session_state:
        st.session_state.uid = hashlib.sha256(str(time.time()).encode()).hexdigest()[:10]
    return st.session_state.uid

USER_ID = uid()
TEMP_DIR = Path("/tmp" if "streamlit" in __file__ else "temp")  # Works on Streamlit Cloud
TEMP_DIR.mkdir(exist_ok=True)

def cleanup():
    import shutil
    try:
        shutil.rmtree(TEMP_DIR / f"user_{USER_ID}")
    except:
        pass
atexit.register(cleanup)

USER_DIR = TEMP_DIR / f"user_{USER_ID}"
USER_DIR.mkdir(exist_ok=True)

# ================================
# AUTHENTICATION
# ================================
SCOPES = ["https://www.googleapis.com/auth/drive"]

def get_service():
    token_path = USER_DIR / "token.pkl"
    creds = None

    if token_path.exists():
        with open(token_path, "rb") as f:
            creds = pickle.load(f)

    client_path = USER_DIR / "client_secrets.json"
    if client_file:
        client_path.write_bytes(client_file.getvalue())

    if not client_path.exists():
        st.warning("Upload client_secrets.json to continue")
        st.stop()

    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            with open(token_path, "wb") as f:
                pickle.dump(creds, f)
        except:
            creds = None

    if not creds:
        flow = InstalledAppFlow.from_client_secrets_file(
            str(client_path), SCOPES,
            redirect_uri="https://" + st.secrets.get("STREAMLIT_URL", "localhost:8501") + "/"
        )
        auth_url, _ = flow.authorization_url(prompt="consent", access_type="offline")
        st.markdown(f"### Login Required")
        st.markdown(f"[Click here to authorize your Google Account]({auth_url})")
        st.info("After approving, copy the **code** from the redirect URL")
        code = st.text_input("Paste the authorization code here:", type="password")

        if code:
            try:
                flow.fetch_token(code=code.strip())
                creds = flow.credentials
                with open(token_path, "wb") as f:
                    pickle.dump(creds, f)
                st.success("Login successful!")
                st.rerun()
            except Exception as e:
                st.error(f"Login failed: {e}")

    service = build("drive", "v3", credentials=creds)
    user = service.about().get(fields="user").execute()["user"]
    st.success(f"Logged in as **{user['displayName']}** ({user['emailAddress']})")
    return service

# ================================
# MAIN LOGIC (Same GOD MODE + Better Logs)
# ================================
if client_file and folder_id:
    if st.button("Start Liberation", type="primary", use_container_width=True):
        service = get_service()

        log_container = st.container()
        progress_bar = st.progress(0)
        status_text = st.empty()

        st.session_state.log = []
        st.session_state.skipped = []
        duplicate_cache = {}

        def log(msg, icon="→"):
            st.session_state.log.append(f"{icon} {msg}")
            with log_container:
                st.markdown(f"{icon} {msg}")

        def api_call(fn, *args, **kwargs):
            for i in range(8):
                try:
                    time.sleep(0.1)
                    return fn(*args, **kwargs).execute()
                except HttpError as e:
                    if e.resp.status in (429, 500, 502, 503):
                        wait = 2 ** i
                        log(f"Rate limit... waiting {wait}s")
                        time.sleep(wait)
                    else:
                        raise
            raise Exception("Max retries")

        def create_folder(parent_id, name, path):
            key = (parent_id, name)
            if key in duplicate_cache:
                return duplicate_cache[key]
            new = api_call(service.files().create, body={
                "name": name,
                "mimeType": "application/vnd.google-apps.folder",
                "parents": [parent_id]
            }, fields="id", supportsAllDrives=True)
            nid = new["id"]
            duplicate_cache[key] = nid
            log(f"Created folder: **{path}/{name}**", "Folder")
            return nid

        def copy_file(fid, name, parent_id, path):
            try:
                api_call(service.files().copy, fileId=fid, body={"parents": [parent_id]}, supportsAllDrives=True)
                log(f"Copied file: **{path}/{name}**", "File")
            except HttpError as e:
                if "cannotCopyFile" in str(e):
                    log(f"Skipped (Google Form): **{path}/{name}**", "Skip")
                    st.session_state.skipped.append(f"{path}/{name}")
                else:
                    log(f"Failed: **{path}/{name}** → {e}", "Failed")

        def duplicate_all_contents(folder_id, path, new_parent_id):
            page_token = None
            while True:
                res = api_call(service.files().list, q=f"'{folder_id}' in parents and trashed = false",
                              fields="nextPageToken, files(id, name, mimeType)", pageSize=1000,
                              pageToken=page_token, supportsAllDrives=True)
                for f in res.get("files", []):
                    if f["mimeType"] == "application/vnd.google-apps.folder":
                        new_id = create_folder(new_parent_id, f["name"], path)
                        duplicate_all_contents(f["id"], f"{path}/{f['name']}", new_id)
                    else:
                        copy_file(f["id"], f["name"], new_parent_id, path)
                page_token = res.get("nextPageToken")
                if not page_token: break

        def deep_scan(folder_id, path=""):
            page_token = None
            while True:
                res = api_call(service.files().list, q=f"'{folder_id}' in parents and trashed = false",
                              fields="nextPageToken, files(id, name, mimeType, owners, parents)",
                              pageSize=1000, pageToken=page_token, supportsAllDrives=True)
                items = res.get("files", [])
                for i, f in enumerate(items):
                    progress_bar.progress((i + 1) / len(items) if items else 1)
                    name = f["name"]
                    full_path = f"{path}/{name}" if path else name
                    owners = f.get("owners", [{}])
                    is_source = any(o.get("emailAddress") == owners[0].get("emailAddress") for o in owners if o)
                    parents = f.get("parents", [])

                    if not is_source:
                        if f["mimeType"].endswith(".folder"):
                            deep_scan(f["id"], full_path)
                        continue

                    parent_id = parents[0] if parents else None
                    if not parent_id: continue

                    if f["mimeType"].endswith(".folder"):
                        log(f"Found YOUR FOLDER → copying everything inside: **{full_path}**", "Folder")
                        new_folder_id = create_folder(parent_id, name, path)
                        duplicate_all_contents(f["id"], full_path, new_folder_id)
                    else:
                        copy_file(f["id"], name, parent_id, path)

                    if f["mimeType"].endswith(".folder"):
                        deep_scan(f["id"], full_path)

                page_token = res.get("nextPageToken")
                if not page_token: break

        # START
        log(f"Starting liberation of folder ID: `{folder_id}`")
        status_text.info("Scanning and duplicating your content...")
        deep_scan(folder_id)

        total = len([l for l in st.session_state.log if "Copied" in l or "Created" in l])
        st.success("LIBERATION COMPLETE!")
        st.balloons()
        st.success(f"Total items liberated: **{total}**")
        if st.session_state.skipped:
            st.warning(f"Skipped {len(st.session_state.skipped)} uncopyable items (e.g. Google Forms)")
            with st.expander("View skipped"):
                for s in st.session_state.skipped:
                    st.write(s)

        st.markdown("### Full Log")
        with log_container:
            for line in st.session_state.log:
                st.markdown(line)

else:
    st.info("Please complete Step 1 and Step 2 to begin")

# Footer
st.markdown("---")
st.caption("Made with ❤️ for everyone who lost access to shared folders • Open Source • No data stored")