import streamlit as st
import time, random, hashlib, atexit, re, json, socket, ssl
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
- **Persistent Checkpoints:** Remembers all completed folders and files. Restarts instantly without re-checking from the start.
- **Mirrored Structure:** Files are placed into their corresponding folders in the destination.
- **Auto-Token Refresh & Reconnect:** Automatically refreshes credentials and recovers from network drops.
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
# SESSION, PATHS & CHECKPOINT
# ================================
def uid():
    if "uid" not in st.session_state:
        st.session_state.uid = hashlib.sha256(str(time.time()).encode()).hexdigest()[:10]
    return st.session_state.uid

USER_ID = uid()
SCRIPT_DIR = Path(__file__).resolve().parent
TEMP_DIR = SCRIPT_DIR / "temp"
TEMP_DIR.mkdir(exist_ok=True)
USER_DIR = TEMP_DIR / f"user_{USER_ID}"
USER_DIR.mkdir(exist_ok=True)

LOG_FILE = SCRIPT_DIR / "transfer_log.txt"
CHECKPOINT_FILE = SCRIPT_DIR / "checkpoint.json"

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

def load_checkpoint():
    if CHECKPOINT_FILE.exists():
        try:
            with open(CHECKPOINT_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return {
                    "completed_folders": set(data.get("completed_folders", [])),
                    "completed_files": set(data.get("completed_files", [])),
                    "folder_mappings": data.get("folder_mappings", {})
                }
        except Exception:
            pass
    return {"completed_folders": set(), "completed_files": set(), "folder_mappings": {}}

def save_checkpoint(ckpt):
    try:
        data = {
            "completed_folders": list(ckpt["completed_folders"]),
            "completed_files": list(ckpt["completed_files"]),
            "folder_mappings": ckpt["folder_mappings"],
            "last_updated": time.time()
        }
        with open(CHECKPOINT_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

# ================================
# CONFIG (User Inputs)
# ================================
with st.expander("Step 1: Google Cloud Credentials (`client_secrets.json`)", expanded=True):
    client_file = st.file_uploader(
        "Upload client_secrets.json (Web Application OAuth)",
        type="json",
        help="Download from Google Cloud Console -> Credentials -> OAuth 2.0 Client ID"
    )
    local_secrets = SCRIPT_DIR / "client_secrets.json"
    if not client_file and local_secrets.exists():
        client_path = local_secrets
        st.info("Using local `client_secrets.json` from workspace.")
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

# Checkpoint Summary in UI
checkpoint_data = load_checkpoint()
col_chk1, col_chk2 = st.columns([3, 1])
with col_chk1:
    use_checkpoint = st.checkbox(
        f"Enable Persistent Checkpoint ({len(checkpoint_data['completed_folders'])} folders, {len(checkpoint_data['completed_files'])} files already recorded)",
        value=True,
        help="Skips completed folders and files instantly in memory without re-querying Google Drive API."
    )
with col_chk2:
    if st.button("Reset Checkpoint", help="Clear saved progress to force full re-check"):
        if CHECKPOINT_FILE.exists():
            CHECKPOINT_FILE.unlink(missing_ok=True)
        st.success("Checkpoint cleared!")
        st.rerun()

# ================================
# AUTHENTICATION
# ================================
SCOPES = ["https://www.googleapis.com/auth/drive"]
token_path = USER_DIR / "token.pkl"

def get_service():
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
    return service, creds

service = None
creds = None
if client_path:
    service, creds = get_service()

# ================================
# TRANSFER / SYNC LOGIC
# ================================
if service and src_folder_id and dst_folder_id:
    st.markdown("---")
    st.markdown("### Safe Mirror Transfer Engine")
    st.caption("Copies files into corresponding folders in the destination. Original files are completely untouched.")

    is_running = st.session_state.get("is_running", False)

    col1, col2 = st.columns([3, 1])
    with col1:
        start_btn = st.button("Start Safe Mirror Transfer", type="primary", use_container_width=True, disabled=is_running)
    with col2:
        if st.button("Stop Transfer", use_container_width=True, disabled=not is_running):
            st.session_state.stop_transfer = True
            st.session_state.is_running = False
            st.warning("Transfer stopped by user.")

    if start_btn:
        st.session_state.is_running = True
        st.session_state.stop_transfer = False
        st.session_state.copied_count = 0
        st.session_state.skipped_count = 0
        st.session_state.error_count = 0
        st.session_state.recent_logs = []
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"\n--- Transfer Run Started: {time.ctime()} ---\n")
        st.rerun()

    if is_running:
        status_text = st.empty()
        stats_placeholder = st.empty()
        recent_log_placeholder = st.empty()

        ckpt = load_checkpoint()

        def ensure_valid_token():
            global creds, service
            if creds and (creds.expired or not creds.valid) and creds.refresh_token:
                try:
                    creds.refresh(Request())
                    with open(token_path, "wb") as f:
                        pickle.dump(creds, f)
                    service = build("drive", "v3", credentials=creds)
                except Exception:
                    pass

        def log_entry(msg, to_ui=True):
            ts = time.strftime("%H:%M:%S")
            line = f"[{ts}] {msg}"
            try:
                with open(LOG_FILE, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except Exception:
                pass

            if to_ui:
                if "recent_logs" not in st.session_state:
                    st.session_state.recent_logs = []
                st.session_state.recent_logs.append(line)
                if len(st.session_state.recent_logs) > 15:
                    st.session_state.recent_logs = st.session_state.recent_logs[-15:]
                recent_log_placeholder.code("\n".join(st.session_state.recent_logs))

        def api_call(fn, *args, **kwargs):
            global creds, service
            for attempt in range(10):
                if st.session_state.get("stop_transfer", False):
                    return None
                try:
                    ensure_valid_token()
                    time.sleep(0.04)
                    return fn(*args, **kwargs).execute()
                except HttpError as e:
                    if e.resp.status == 401:
                        log_entry("Token expired. Automatically refreshing credentials...")
                        ensure_valid_token()
                        time.sleep(1)
                        continue
                    elif e.resp.status in (403, 429, 500, 502, 503, 504):
                        wait = (2 ** min(attempt, 5)) + random.uniform(0.5, 1.5)
                        log_entry(f"Rate quota reached (HTTP {e.resp.status}). Pausing {wait:.1f}s...")
                        time.sleep(wait)
                    else:
                        raise
                except (socket.timeout, TimeoutError, ssl.SSLError, ConnectionError, OSError) as e:
                    wait = 2 + (2 ** min(attempt, 4))
                    log_entry(f"Connection hiccup ({type(e).__name__}). Retrying in {wait}s...")
                    time.sleep(wait)
            raise Exception("Maximum API retries exceeded.")

        def get_children(folder_id):
            items = []
            page_token = None
            while True:
                if st.session_state.get("stop_transfer", False):
                    break
                try:
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
                except Exception as e:
                    log_entry(f"Notice: could not list items in folder {folder_id}: {e}")
                    break
            return items

        def get_existing_target_maps(dst_parent_id):
            children = get_children(dst_parent_id)
            folders_map = {}
            files_map = {}
            for item in children:
                if item["mimeType"] == "application/vnd.google-apps.folder":
                    folders_map[item["name"]] = item["id"]
                else:
                    files_map[item["name"]] = item["id"]
            return folders_map, files_map

        def update_stats():
            stats_placeholder.markdown(
                f"**Copied:** {st.session_state.copied_count} | "
                f"**Skipped (Already in Target):** {st.session_state.skipped_count} | "
                f"**Errors:** {st.session_state.error_count}"
            )

        def mirror_sync(src_id, dst_id, path=""):
            if st.session_state.get("stop_transfer", False):
                return False

            # Checkpoint fast-skip: entire folder already 100% completed
            if use_checkpoint and src_id in ckpt["completed_folders"]:
                log_entry(f"Instant Skip (Folder completed in checkpoint): {path or 'Root'}", to_ui=False)
                return True

            status_text.info(f"Scanning folder: **{path or 'Root'}**")
            target_folders, target_files = get_existing_target_maps(dst_id)
            source_items = get_children(src_id)

            subfolders = [f for f in source_items if f["mimeType"] == "application/vnd.google-apps.folder"]
            files = [f for f in source_items if f["mimeType"] != "application/vnd.google-apps.folder"]

            folder_all_ok = True
            unflushed_file_saves = 0

            # 1. Process files in current folder
            for f in files:
                if st.session_state.get("stop_transfer", False):
                    return False

                fname = f["name"]
                fid = f["id"]
                full_item_path = f"{path}/{fname}" if path else fname

                # Fast skip if file was recorded in checkpoint
                if use_checkpoint and fid in ckpt["completed_files"]:
                    st.session_state.skipped_count += 1
                    continue

                if fname in target_files:
                    st.session_state.skipped_count += 1
                    ckpt["completed_files"].add(fid)
                    unflushed_file_saves += 1
                    log_entry(f"Skip (Already exists): {full_item_path}", to_ui=(st.session_state.skipped_count % 30 == 0))
                else:
                    try:
                        api_call(
                            service.files().copy,
                            fileId=fid,
                            body={"name": fname, "parents": [dst_id]},
                            supportsAllDrives=True
                        )
                        st.session_state.copied_count += 1
                        ckpt["completed_files"].add(fid)
                        unflushed_file_saves += 1
                        log_entry(f"Copied file: {full_item_path}")
                    except HttpError as e:
                        if "cannotCopyFile" in str(e):
                            st.session_state.skipped_count += 1
                            ckpt["completed_files"].add(fid)
                            unflushed_file_saves += 1
                            log_entry(f"Skip uncopyable: {full_item_path}")
                        else:
                            st.session_state.error_count += 1
                            folder_all_ok = False
                            log_entry(f"Failed copying {full_item_path}: {e}")
                    except Exception as e:
                        st.session_state.error_count += 1
                        folder_all_ok = False
                        log_entry(f"Error copying {full_item_path}: {e}")

                if unflushed_file_saves >= 15:
                    save_checkpoint(ckpt)
                    unflushed_file_saves = 0

                update_stats()

            if unflushed_file_saves > 0:
                save_checkpoint(ckpt)

            # 2. Process subfolders recursively
            for folder in subfolders:
                if st.session_state.get("stop_transfer", False):
                    return False

                folder_name = folder["name"]
                folder_src_id = folder["id"]
                sub_path = f"{path}/{folder_name}" if path else folder_name

                # Checkpoint fast-skip for subfolder
                if use_checkpoint and folder_src_id in ckpt["completed_folders"]:
                    log_entry(f"Instant Skip (Folder completed in checkpoint): {sub_path}", to_ui=False)
                    continue

                # Use cached mapping or match/create in destination
                if folder_src_id in ckpt["folder_mappings"]:
                    target_subfolder_id = ckpt["folder_mappings"][folder_src_id]
                elif folder_name in target_folders:
                    target_subfolder_id = target_folders[folder_name]
                    ckpt["folder_mappings"][folder_src_id] = target_subfolder_id
                    log_entry(f"Matched folder: {sub_path}")
                else:
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
                    ckpt["folder_mappings"][folder_src_id] = target_subfolder_id
                    log_entry(f"Created folder in target: {sub_path}")

                subfolder_ok = mirror_sync(folder_src_id, target_subfolder_id, sub_path)
                if not subfolder_ok:
                    folder_all_ok = False

            # Mark folder completed only if all files and subfolders finished cleanly
            if folder_all_ok and not st.session_state.get("stop_transfer", False):
                ckpt["completed_folders"].add(src_id)
                save_checkpoint(ckpt)
                log_entry(f"Folder 100% completed & checkpointed: {path or 'Root'}")
                return True

            return False

        # Run Sync
        log_entry("Initiating mirror sync with checkpoint resume...")
        try:
            mirror_sync(src_folder_id, dst_folder_id)
        except Exception as e:
            log_entry(f"Fatal error during sync: {e}")
        finally:
            st.session_state.is_running = False

        if not st.session_state.get("stop_transfer", False):
            st.success("TRANSFER COMPLETED SUCCESSFULLY!")
            st.balloons()
        else:
            st.warning("Transfer stopped.")

        st.markdown(
            f"### Final Summary: Copied **{st.session_state.copied_count}** files, "
            f"Skipped **{st.session_state.skipped_count}** existing items, "
            f"Errors: **{st.session_state.error_count}**."
        )

        st.info("Full transfer log written to `transfer_log.txt` and progress saved in `checkpoint.json`.")
else:
    st.info("Complete configuration steps above and ensure both Source and Destination IDs are detected.")
