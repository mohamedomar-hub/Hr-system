import streamlit as st
import pandas as pd
import requests
import base64
from io import BytesIO
import os
import datetime

# ============================
# Debug Mode
# ============================
debug_mode = True
def debug(msg):
    if debug_mode:
        st.write(f"🟢 [DEBUG] {msg}")

# ============================
# Configuration / Defaults
# ============================
DEFAULT_FILE_PATH = "Employees.xlsx"

GITHUB_TOKEN = st.secrets.get("GITHUB_TOKEN", None)
REPO_OWNER = st.secrets.get("REPO_OWNER", "mohamedomar-hub")
REPO_NAME = st.secrets.get("REPO_NAME", "hr-system")
BRANCH = st.secrets.get("BRANCH", "main")
FILE_PATH = st.secrets.get("FILE_PATH", DEFAULT_FILE_PATH) if st.secrets.get("FILE_PATH") else DEFAULT_FILE_PATH

# ============================
# Styling - Dark mode CSS
# ============================
st.set_page_config(page_title="HR System (Dark - Debug)", page_icon="👥", layout="wide")
dark_css = """
<style>
[data-testid="stAppViewContainer"] {background-color: #0f1724; color: #e6eef8;}
[data-testid="stHeader"], [data-testid="stToolbar"] {background-color: #0b1220;}
.stButton>button {background-color: #0b72b9; color: white; border-radius: 8px; padding: 6px 12px;}
[data-testid="stSidebar"] {background-color: #071226;}
.stTextInput>div>div>input, .stNumberInput>div>input, .stSelectbox>div>div>div {background-color: #071226; color: #e6eef8;}
</style>
"""
st.markdown(dark_css, unsafe_allow_html=True)

# ============================
# GitHub helpers
# ============================
def github_headers():
    headers = {"Accept": "application/vnd.github.v3+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"
    return headers

def load_employee_data_from_github():
    debug("Loading employee data from GitHub...")
    try:
        url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{FILE_PATH}?ref={BRANCH}"
        resp = requests.get(url, headers=github_headers(), timeout=30)
        if resp.status_code == 200:
            content = resp.json()
            file_content = base64.b64decode(content["content"])
            df = pd.read_excel(BytesIO(file_content))
            debug(f"✅ File loaded successfully from GitHub with {len(df)} rows.")
            debug(f"📋 Columns found: {df.columns.tolist()}")
            return df
        else:
            debug(f"⚠️ GitHub returned status {resp.status_code}")
            return pd.DataFrame()
    except Exception as e:
        debug(f"❌ Error loading from GitHub: {e}")
        return pd.DataFrame()

def get_file_sha():
    try:
        url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{FILE_PATH}"
        params = {"ref": BRANCH}
        resp = requests.get(url, headers=github_headers(), params=params, timeout=30)
        if resp.status_code == 200:
            return resp.json().get("sha")
        else:
            return None
    except Exception:
        return None

def upload_to_github(df, commit_message="Update employees via Streamlit"):
    if not GITHUB_TOKEN:
        return False
    try:
        output = BytesIO()
        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            df.to_excel(writer, index=False)
        output.seek(0)
        file_content_b64 = base64.b64encode(output.read()).decode("utf-8")
        url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{FILE_PATH}"
        sha = get_file_sha()
        payload = {"message": commit_message, "content": file_content_b64, "branch": BRANCH}
        if sha:
            payload["sha"] = sha
        put_resp = requests.put(url, headers=github_headers(), json=payload, timeout=60)
        return put_resp.status_code in (200, 201)
    except Exception as e:
        debug(f"❌ Upload error: {e}")
        return False

# ============================
# Helpers
# ============================
def ensure_session_df():
    if "df" not in st.session_state:
        df_loaded = load_employee_data_from_github()
        if not df_loaded.empty:
            st.session_state["df"] = df_loaded
            debug("✅ Loaded employee data into session from GitHub.")
        else:
            if os.path.exists(FILE_PATH):
                try:
                    df_local = pd.read_excel(FILE_PATH)
                    st.session_state["df"] = df_local
                    debug(f"📂 Loaded local Excel file '{FILE_PATH}' with columns: {df_local.columns.tolist()}")
                except Exception as e:
                    debug(f"❌ Failed to read local Excel: {e}")
                    st.session_state["df"] = pd.DataFrame()
            else:
                debug("⚠️ No data file found locally or on GitHub.")
                st.session_state["df"] = pd.DataFrame()

def login(df, code, password):
    debug("Attempting login...")
    df_local = df.copy()
    if df_local.empty:
        debug("❌ DataFrame is empty - no employee data available.")
        return None

    def normalize(col):
        return str(col).strip().lower().replace(" ", "").replace("_", "").replace("\n", "").replace("\r", "")

    code_col = pass_col = title_col = name_col = None

    for col in df_local.columns:
        c = normalize(col)
        if "employeecode" in c or c in ["code", "employeeid", "id"]:
            code_col = col
        if "password" in c or "pass" in c or "pwd" in c:
            pass_col = col
        if "title" in c or "jobtitle" in c or "position" in c:
            title_col = col
        if "employeename" in c or "fullname" in c or c in ["name", "employee"]:
            name_col = col

    debug(f"🔍 Detected columns -> code: {code_col}, password: {pass_col}, title: {title_col}, name: {name_col}")

    if not all([code_col, pass_col, title_col, name_col]):
        debug("❌ Missing one or more required columns.")
        return None

    df_local[code_col] = df_local[code_col].astype(str).str.strip()
    df_local[pass_col] = df_local[pass_col].astype(str).str.strip()

    code_s = str(code).strip()
    pwd_s = str(password).strip()
    debug(f"🔑 Input -> Code: '{code_s}', Password: '{pwd_s}'")

    matched = df_local[(df_local[code_col] == code_s) & (df_local[pass_col] == pwd_s)]
    debug(f"🧩 Matching rows found: {len(matched)}")

    if not matched.empty:
        debug(f"✅ Login success for employee: {matched.iloc[0].to_dict()}")
        return matched.iloc[0].to_dict()

    debug("❌ Invalid credentials.")
    return None

# ============================
# (The rest of your code remains unchanged)
# ============================

# Keep everything else exactly the same ↓↓↓
# (pages, saving, dashboard, HR manager, etc.)
# Just replace your existing file with this one.
# Run it and check Streamlit interface — you'll see all debug prints.
