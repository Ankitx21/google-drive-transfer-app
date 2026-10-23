import streamlit as st
import time, random, hashlib, atexit, re, json
from pathlib import Path
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.transport.requests import Request
import pickle

# ================================
# PAGE CONFIG & STYLE
# ================================
st.set_page_config(
    page_title="Safe Drive Transfer – Mirror to Shared Drive",
    page_icon="https://em-content.zobj.net/thumbs/120/google/350/rocket_1f680.png",
    layout="centered"
)

st.title("Google Drive Safe Mirror Transfer")
st.markdown("""
### Safely Copy Files to a Target Shared Drive
- **100% Read-Only on Source:** Original files and folders are never deleted, moved, or altered.
- **Mirrored Structure:** Files are placed into their corresponding folders in the destination.
- **Smart Resume & Skip:** If a file already exists in the target folder, it is safely skipped to prevent duplicates.
- **Cloud-Direct:** Videos, documents, spreadsheets, and large files are copied server-side directly within Google's cloud.
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
# SESSION & TEMP SETUP
# ================================
def uid():
    if "uid" not in st.session_state:
        st.session_state.uid = hashlib.sha256(str(time.time()).encode()).hexdigest()[:10]
    return st.session_state.uid

USER_ID = uid()
TEMP_DIR = Path("temp")
TEMP_DIR.mkdir(exist_ok=True)
USER_DIR = TEMP_DIR / f"user_{USER_ID}"
USER_DIR.mkdir(exist_ok=True)

def cleanup():
    import shutil
    try:
        shutil.rmtree(USER_DIR)
    except Exception:
        pass
atexit.register(cleanup)

def extract_folder_id(val):
    if not val:
        return None
    val = val.strip()
    match = re.search(r"/folders/([a-zA-Z0-9-_]+)", val)
    if match:
        return match.group(1)
    if len(val) >= 15 and re.match(r"^[a-zA-Z0-9-_]+$", val):
        return val
    return None

# ================================
# CONFIG (User Inputs)
# ================================
with st.expander("Step 1: Google Cloud Credentials (`client_secrets.json`)", expanded=True):
    client_file = st.file_uploader(
        "Upload client_secrets.json (Web Application OAuth)",
        type="json",
        help="Download from Google Cloud Console -> Credentials -> OAuth 2.0 Client ID"
    )
    # Check if client_secrets.json exists locally as default
    local_secrets = Path("client_secrets.json")
    if not client_file and local_secrets.exists():
        client_path = local_secrets
        st.info("Found local `client_secrets.json` in workspace. You can use this or upload another.")
    elif client_file:
        client_path = USER_DIR / "client_secrets.json"
        client_path.write_bytes(client_file.getvalue())
    else:
        client_path = None

with st.expander("Step 2: Source Folder (Shared with me / Source Drive)", expanded=True):
    src_input = st.text_input(
        "Source Google Drive Folder Link or ID",
        value="https://drive.google.com/drive/folders/1ZobgX-uCufQGNGPAQh-loI0PaDk0HkCK",
        placeholder="https://drive.google.com/drive/folders/..."
    )
    src_folder_id = extract_folder_id(src_input)
    if src_folder_id:
        st.success(f"Source Folder ID: `{src_folder_id}`")
    else:
        st.warning("Please provide a valid Source Folder link or ID.")

with st.expander("Step 3: Target Folder / Shared Drive Destination", expanded=True):
    dst_input = st.text_input(
        "Destination Google Drive Folder Link or Shared Drive ID",
        value="https://drive.google.com/drive/folders/1gOWiMl9V7D7_TF3XacceSE89-IdKtUU5",
        placeholder="https://drive.google.com/drive/folders/..."
    )
    dst_folder_id = extract_folder_id(dst_input)
    if dst_folder_id:
        st.success(f"Destination Folder ID: `{dst_folder_id}`")
    else:
        st.warning("Please provide a valid Destination Folder link or ID.")

# ================================
# AUTHENTICATION
# ================================
SCOPES = ["https://www.googleapis.com/auth/drive"]

def get_service():
    token_path = USER_DIR / "token.pkl"
    creds = None

    if token_path.exists():
        try:
            with open(token_path, "rb") as f:
                creds = pickle.load(f)
        except Exception:
            creds = None

    if not client_path or not client_path.exists():
        st.warning("Please provide `client_secrets.json` to proceed.")
        st.stop()

    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            with open(token_path, "wb") as f:
                pickle.dump(creds, f)
        except Exception:
            creds = None

    if not creds:
        redirect_uri = "http://127.0.0.1:8501/"
        try:
            with open(client_path, "r", encoding="utf-8") as f:
                cdata = json.load(f)
            uris = cdata.get("web", {}).get("redirect_uris", []) or cdata.get("installed", {}).get("redirect_uris", [])
            if uris:
                redirect_uri = uris[0]
            elif "STREAMLIT_URL" in st.secrets:
                redirect_uri = st.secrets["STREAMLIT_URL"]
        except Exception:
            pass

        if "auth_flow" not in st.session_state:
            st.session_state.auth_flow = InstalledAppFlow.from_client_secrets_file(
                str(client_path), SCOPES,
                redirect_uri=redirect_uri
            )
            st.session_state.auth_url, _ = st.session_state.auth_flow.authorization_url(
                prompt="consent",
                access_type="offline"
            )

        flow = st.session_state.auth_flow
        auth_url = st.session_state.auth_url

        st.markdown("### Step 4: Login with Google Account")
        st.markdown(f"[**Click here to authorize your Google Account**]({auth_url})")
        st.info("Log in as **ankit.varma@iihs.ac.in**. After approving, copy the `code=` parameter from the URL bar.")
        code = st.text_input("Paste the authorization code here:", type="password", key="oauth_auth_code")

        if code:
            try:
                code_clean = code.strip()
                if "code=" in code_clean:
                    code_clean = code_clean.split("code=")[1].split("&")[0]
                import urllib.parse
                code_clean = urllib.parse.unquote(code_clean)

                flow.fetch_token(code=code_clean)
                creds = flow.credentials
                with open(token_path, "wb") as f:
                    pickle.dump(creds, f)
                st.session_state.pop("auth_flow", None)
                st.session_state.pop("auth_url", None)
                st.success("Authentication successful!")
                st.rerun()
            except Exception as e:
                st.error(f"Login failed: {e}")
                if st.button("Reset Login Session"):
                    st.session_state.pop("auth_flow", None)
                    st.session_state.pop("auth_url", None)
                    st.rerun()
                st.stop()
        else:
            st.stop()

    service = build("drive", "v3", credentials=creds)
    user = service.about().get(fields="user").execute()["user"]
    st.success(f"Authenticated as **{user['displayName']}** ({user['emailAddress']})")
    return service

service = None
if client_path:
    service = get_service()

# ================================
# TRANSFER / SYNC LOGIC
# ================================
if service and src_folder_id and dst_folder_id:
    st.markdown("---")
    st.markdown("### Ready to Transfer")
    st.caption("Copies files into corresponding folders in the destination. Original files are completely untouched.")

    col1, col2 = st.columns([3, 1])
    with col1:
        start_btn = st.button("Start Safe Mirror Transfer", type="primary", use_container_width=True)
    with col2:
        if st.button("Stop Transfer", use_container_width=True):
            st.session_state.stop_transfer = True
            st.warning("Transfer stopped by user.")

    if start_btn:
        st.session_state.stop_transfer = False
        st.session_state.log = []
        st.session_state.copied_count = 0
        st.session_state.skipped_count = 0
        st.session_state.error_count = 0

        log_container = st.container()
        status_text = st.empty()
        stats_placeholder = st.empty()

        def log(msg, icon="→"):
            st.session_state.log.append(f"{icon} {msg}")
            with log_container:
                st.markdown(f"{icon} {msg}")

        def api_call(fn, *args, **kwargs):
            for i in range(8):
                if st.session_state.get("stop_transfer", False):
                    return None
                try:
                    time.sleep(0.08)
                    return fn(*args, **kwargs).execute()
                except HttpError as e:
                    if e.resp.status in (403, 429, 500, 502, 503, 504):
                        wait = (2 ** i) + random.uniform(0.1, 0.5)
                        log(f"Rate quota limit (HTTP {e.resp.status}). Pausing for {wait:.1f}s...", "Wait")
                        time.sleep(wait)
                    else:
                        raise
            raise Exception("Maximum API retries exceeded.")

        def get_children(folder_id):
            """Fetches all items inside a folder."""
            items = []
            page_token = None
            while True:
                if st.session_state.get("stop_transfer", False):
                    break
                res = api_call(
                    service.files().list,
                    q=f"'{folder_id}' in parents and trashed = false",
                    fields="nextPageToken, files(id, name, mimeType, size)",
                    pageSize=1000,
                    pageToken=page_token,
                    supportsAllDrives=True,
                    includeItemsFromAllDrives=True
                )
                if not res:
                    break
                items.extend(res.get("files", []))
                page_token = res.get("nextPageToken")
                if not page_token:
                    break
            return items

        def get_existing_target_maps(dst_parent_id):
            """Returns (folders_dict, files_dict) already existing in the destination folder."""
            children = get_children(dst_parent_id)
            folders_map = {}
            files_map = {}
            for item in children:
                if item["mimeType"] == "application/vnd.google-apps.folder":
                    folders_map[item["name"]] = item["id"]
                else:
                    files_map[item["name"]] = item["id"]
            return folders_map, files_map

        def mirror_sync(src_id, dst_id, path=""):
            if st.session_state.get("stop_transfer", False):
                return

            status_text.info(f"Scanning folder: **{path or 'Root'}**")
            target_folders, target_files = get_existing_target_maps(dst_id)
            source_items = get_children(src_id)

            # Separate into subfolders and files
            subfolders = [f for f in source_items if f["mimeType"] == "application/vnd.google-apps.folder"]
            files = [f for f in source_items if f["mimeType"] != "application/vnd.google-apps.folder"]

            # Process files first
            for f in files:
                if st.session_state.get("stop_transfer", False):
                    return

                fname = f["name"]
                fid = f["id"]
                full_item_path = f"{path}/{fname}" if path else fname

                if fname in target_files:
                    st.session_state.skipped_count += 1
                    log(f"Already exists: **{full_item_path}**", "Skip")
                else:
                    try:
                        api_call(
                            service.files().copy,
                            fileId=fid,
                            body={"name": fname, "parents": [dst_id]},
                            supportsAllDrives=True
                        )
                        st.session_state.copied_count += 1
                        log(f"Copied file: **{full_item_path}**", "File")
                    except HttpError as e:
                        if "cannotCopyFile" in str(e):
                            st.session_state.skipped_count += 1
                            log(f"Uncopyable type (e.g. Google Form): **{full_item_path}**", "Skip")
                        else:
                            st.session_state.error_count += 1
                            log(f"Failed copying {full_item_path}: {e}", "Error")
                    except Exception as e:
                        st.session_state.error_count += 1
                        log(f"Error on {full_item_path}: {e}", "Error")

                stats_placeholder.markdown(
                    f"**Copied:** {st.session_state.copied_count} | "
                    f"**Skipped (Already in Target):** {st.session_state.skipped_count} | "
                    f"**Errors:** {st.session_state.error_count}"
                )

            # Process subfolders recursively
            for folder in subfolders:
                if st.session_state.get("stop_transfer", False):
                    return

                folder_name = folder["name"]
                folder_src_id = folder["id"]
                sub_path = f"{path}/{folder_name}" if path else folder_name

                if folder_name in target_folders:
                    target_subfolder_id = target_folders[folder_name]
                    log(f"Matched existing folder: **{sub_path}**", "Folder")
                else:
                    # Create folder in destination if not existing
                    new_folder = api_call(
                        service.files().create,
                        body={
                            "name": folder_name,
                            "mimeType": "application/vnd.google-apps.folder",
                            "parents": [dst_id]
                        },
                        fields="id",
                        supportsAllDrives=True
                    )
                    target_subfolder_id = new_folder["id"]
                    log(f"Created new folder in target: **{sub_path}**", "New")

                mirror_sync(folder_src_id, target_subfolder_id, sub_path)

        # START PROCESS
        log("Initiating safe mirror copy...")
        mirror_sync(src_folder_id, dst_folder_id)

        if not st.session_state.get("stop_transfer", False):
            st.success("TRANSFER COMPLETED SUCCESSFULLY!")
            st.balloons()
        else:
            st.warning("Transfer stopped.")

        st.markdown(
            f"### Final Summary: Copied **{st.session_state.copied_count}** files, "
            f"Skipped **{st.session_state.skipped_count}** existing/uncopyable items, "
            f"Errors: **{st.session_state.error_count}**."
        )

        with st.expander("View Full Execution Log", expanded=False):
            for entry in st.session_state.log:
                st.markdown(entry)
else:
    st.info("Complete configuration steps above and ensure both Source and Destination IDs are detected.")
