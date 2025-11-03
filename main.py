# hr_system_dark_mode_v3.py (Full Version with Integrated Debug)
import streamlit as st
import pandas as pd
import requests
import base64
from io import BytesIO
import os
import datetime
import plotly.express as px

# ============================
# Configuration / Defaults
# ============================
DEFAULT_FILE_PATH = "Employees.xlsx"
LOGO_PATH = "logo.jpg"

# GitHub / file config stored in Streamlit secrets (optional)
GITHUB_TOKEN = st.secrets.get("GITHUB_TOKEN", None)
REPO_OWNER = st.secrets.get("REPO_OWNER", "mohamedomar-hub")
REPO_NAME = st.secrets.get("REPO_NAME", "hr-system")
BRANCH = st.secrets.get("BRANCH", "main")
FILE_PATH = st.secrets.get("FILE_PATH", DEFAULT_FILE_PATH) if st.secrets.get("FILE_PATH") else DEFAULT_FILE_PATH

# ============================
# Styling - Dark mode CSS
# ============================
st.set_page_config(page_title="HR System (Dark)", page_icon="👥", layout="wide")

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
# Debug Helpers
# ============================
def debug_log(msg):
    if "debug_logs" not in st.session_state:
        st.session_state["debug_logs"] = []
    timestamp = pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S")
    st.session_state["debug_logs"].append(f"[{timestamp}] {msg}")

def show_debug_sidebar():
    st.sidebar.markdown("### Debug Logs")
    logs = st.session_state.get("debug_logs", [])
    if logs:
        for l in logs[-25:][::-1]:
            st.sidebar.text(l)
    else:
        st.sidebar.text("No debug logs yet.")

# ============================
# GitHub helpers
# ============================
def github_headers():
    headers = {"Accept": "application/vnd.github.v3+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"
    return headers

def load_employee_data_from_github():
    try:
        url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{FILE_PATH}?ref={BRANCH}"
        debug_log(f"Loading data from GitHub: {url}")
        resp = requests.get(url, headers=github_headers(), timeout=30)
        if resp.status_code == 200:
            content = resp.json()
            file_content = base64.b64decode(content["content"])
            df = pd.read_excel(BytesIO(file_content))
            debug_log(f"Loaded {len(df)} rows from GitHub")
            return df
        else:
            debug_log(f"GitHub load failed with status {resp.status_code}")
            return pd.DataFrame()
    except Exception as e:
        debug_log(f"GitHub load exception: {e}")
        return pd.DataFrame()

def get_file_sha():
    try:
        url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{FILE_PATH}"
        params = {"ref": BRANCH}
        resp = requests.get(url, headers=github_headers(), params=params, timeout=30)
        if resp.status_code == 200:
            sha = resp.json().get("sha")
            debug_log(f"Retrieved file SHA: {sha}")
            return sha
        else:
            debug_log(f"SHA fetch failed with status {resp.status_code}")
            return None
    except Exception as e:
        debug_log(f"Error getting file SHA: {e}")
        return None

def upload_to_github(df, commit_message="Update employees via Streamlit"):
    if not GITHUB_TOKEN:
        debug_log("No GitHub token configured; skipping upload")
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
        debug_log(f"Uploading to GitHub: {commit_message}")
        put_resp = requests.put(url, headers=github_headers(), json=payload, timeout=60)
        ok = put_resp.status_code in (200,201)
        debug_log(f"Upload status: {put_resp.status_code}")
        return ok
    except Exception as e:
        debug_log(f"Upload exception: {e}")
        return False

# ============================
# Helpers
# ============================
def ensure_session_df():
    if "df" not in st.session_state:
        try:
            df_loaded = load_employee_data_from_github()
            if not df_loaded.empty:
                st.session_state["df"] = df_loaded
                debug_log("Dataset loaded from GitHub.")
            else:
                if os.path.exists(FILE_PATH):
                    st.session_state["df"] = pd.read_excel(FILE_PATH)
                    debug_log(f"Dataset loaded from local file {FILE_PATH}.")
                else:
                    st.session_state["df"] = pd.DataFrame()
                    debug_log("No data file found; created empty dataset.")
        except Exception as e:
            debug_log(f"ensure_session_df error: {e}")
            st.session_state["df"] = pd.DataFrame()

        df = st.session_state["df"]
        if not df.empty:
            df.columns = [str(c).strip() for c in df.columns]
            for col in df.columns:
                if "code" in col.lower() or "pass" in col.lower():
                    df[col] = df[col].astype(str).fillna("").apply(lambda x: x.strip().replace(".0", ""))
            st.session_state["df"] = df
            debug_log(f"Columns normalized: {list(df.columns)}")

# Login with Debug
def login(df, code, password):
    debug_log("Login attempt started.")
    if df is None or df.empty:
        debug_log("Login failed: empty dataframe.")
        return None

    col_map = {c.lower().strip(): c for c in df.columns}
    debug_log(f"Columns: {list(col_map.keys())}")

    code_col = None
    pass_col = None
    for c in df.columns:
        if "code" in c.lower():
            code_col = c
        if "pass" in c.lower():
            pass_col = c

    if not code_col or not pass_col:
        debug_log("Login failed: required columns missing.")
        return None

    df_local = df.copy()
    df_local[code_col] = df_local[code_col].astype(str).str.strip().replace(".0", "")
    df_local[pass_col] = df_local[pass_col].astype(str).str.strip()

    code_s, pwd_s = str(code).strip(), str(password).strip()
    debug_log(f"Trying credentials: code={code_s}")

    matched = df_local[(df_local[code_col] == code_s) & (df_local[pass_col] == pwd_s)]
    debug_log(f"Matched rows: {len(matched)}")

    if not matched.empty:
        debug_log("Login success.")
        return matched.iloc[0].to_dict()
    debug_log("Login failed: no match found.")
    return None

def save_df_to_local(df):
    try:
        with pd.ExcelWriter(FILE_PATH, engine="openpyxl") as writer:
            df.to_excel(writer, index=False)
        debug_log(f"Saved dataset locally to {FILE_PATH}")
        return True
    except Exception as e:
        debug_log(f"Local save failed: {e}")
        return False

def save_and_maybe_push(df, actor="HR"):
    saved = save_df_to_local(df)
    pushed = False
    if saved and GITHUB_TOKEN:
        pushed = upload_to_github(df, commit_message=f"Update {FILE_PATH} via Streamlit by {actor}")
    return saved, pushed

# ============================
# UI Components / Pages
# ============================
def render_logo_and_title():
    cols = st.columns([1,6,1])
    with cols[1]:
        if os.path.exists(LOGO_PATH):
            st.image(LOGO_PATH, width=160)
        st.markdown("<h1 style='color:#e6eef8'>HR System — Dark Mode</h1>", unsafe_allow_html=True)
        st.markdown("<p style='color:#aab8c9'>English interface only</p>", unsafe_allow_html=True)

def page_my_profile(user):
    st.subheader("My Profile")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.info("No employee data available.")
        return
    col_map = {c.lower(): c for c in df.columns}
    code_col = col_map.get("employee_code")
    if not code_col:
        st.error("Employee code column not found in dataset.")
        return
    user_code = user.get(code_col) or user.get("employee_code") or user.get("Employee Code")
    row = df[df[code_col].astype(str) == str(user_code)]
    if row.empty:
        st.error("Your record was not found.")
        return
    st.dataframe(row.reset_index(drop=True), use_container_width=True)
    buf = BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as writer:
        row.to_excel(writer, index=False, sheet_name="MyProfile")
    buf.seek(0)
    st.download_button("Download My Profile (Excel)", data=buf, file_name="my_profile.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

def page_dashboard(user):
    st.subheader("Dashboard")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.info("No employee data available.")
        return

    col_map = {c.lower(): c for c in df.columns}
    dept_col = col_map.get("department")
    hire_col = col_map.get("hire date") or col_map.get("hire_date") or col_map.get("hiring date")

    total_employees = df.shape[0]
    total_departments = df[dept_col].nunique() if dept_col else 0
    new_hires = 0
    if hire_col:
        try:
            df[hire_col] = pd.to_datetime(df[hire_col], errors="coerce")
            new_hires = df[df[hire_col] >= (pd.Timestamp.now() - pd.Timedelta(days=30))].shape[0]
        except Exception:
            new_hires = 0

    c1, c2, c3 = st.columns(3)
    c1.metric("Total Employees", total_employees)
    c2.metric("Departments", total_departments)
    c3.metric("New Hires (30 days)", new_hires)

    st.markdown("---")
    st.markdown("### Employees per Department (table)")
    if dept_col:
        dept_counts = df[dept_col].fillna("Unknown").value_counts().reset_index()
        dept_counts.columns = ["Department", "Employee Count"]
        st.table(dept_counts.sort_values("Employee Count", ascending=False).reset_index(drop=True))
    else:
        st.info("Department column not found. Please ensure there's a 'Department' column in the Excel file.")

    st.markdown("---")
    buf = BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Employees")
    buf.seek(0)
    st.download_button("Download Full Employees Excel", data=buf, file_name="employees_export.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

    if st.button("Save & Push current dataset to GitHub"):
        saved, pushed = save_and_maybe_push(df, actor=user.get("Employee Name","HR"))
        if saved:
            if pushed:
                st.success("Saved locally and pushed to GitHub.")
            else:
                if GITHUB_TOKEN:
                    st.warning("Saved locally but GitHub push failed.")
                else:
                    st.info("Saved locally. GitHub token not configured.")
        else:
            st.error("Failed to save dataset locally.")

def page_hr_manager(user):
    st.subheader("HR Manager")
    st.info("Upload new employee sheet, manage employees, and perform administrative actions.")

    df = st.session_state.get("df", pd.DataFrame())

    st.markdown("### Upload Employees Excel (will replace current dataset)")
    uploaded_file = st.file_uploader("Upload Excel file (.xlsx) to replace the current employees dataset", type=["xlsx"])
    if uploaded_file:
        try:
            new_df = pd.read_excel(uploaded_file)
            st.session_state["uploaded_df_preview"] = new_df.copy()
            st.success("File loaded. Preview below.")
            st.dataframe(new_df.head(50), use_container_width=True)
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Replace In-Memory Dataset with Uploaded File"):
                    st.session_state["df"] = new_df.copy()
                    st.success("In-memory dataset replaced.")
            with col2:
                if st.button("Preview only (do not replace)"):
                    st.info("Preview shown above.")
        except Exception as e:
            st.error(f"Failed to read uploaded file: {e}")

    st.markdown("---")
    st.markdown("### Manage Employees (Edit / Delete)")
    if df.empty:
        st.info("Dataset empty. Upload or load data first.")
        return

    st.dataframe(df.head(100), use_container_width=True)

    col_map = {c.lower(): c for c in df.columns}
    code_col = col_map.get("employee_code") or list(df.columns)[0]

    selected_code = st.text_input("Enter employee code to edit/delete (exact match)", value="")
    if selected_code:
        matched_rows = df[df[code_col].astype(str) == str(selected_code).strip()]
        if matched_rows.empty:
            st.warning("No employee found with that code.")
        else:
            row = matched_rows.iloc[0]
            st.markdown("#### Edit Employee")
            with st.form("edit_employee_form"):
                updated = {}
                for col in df.columns:
                    val = row[col]
                    if pd.isna(val):
                        val = ""
                    if isinstance(val, (int, float)) and not isinstance(val, bool):
                        try:
                            updated[col] = st.number_input(label=str(col), value=float(val) if pd.notna(val) else 0.0, key=f"edit_{col}")
                        except Exception:
                            updated[col] = st.text_input(label=str(col), value=str(val), key=f"edit_{col}")
                    elif "date" in str(col).lower():
                        try:
                            date_val = pd.to_datetime(val, errors="coerce")
                            updated[col] = st.date_input(label=str(col), value=date_val.date() if pd.notna(date_val) else datetime.date.today(), key=f"edit_{col}_date")
                        except Exception:
                            updated[col] = st.text_input(label=str(col), value=str(val), key=f"edit_{col}")
                    else:
                        updated[col] = st.text_input(label=str(col), value=str(val), key=f"edit_{col}")

                submitted_edit = st.form_submit_button("Save Changes")
                if submitted_edit:
                    for k, v in updated.items():
                        if isinstance(v, datetime.date):
                            v = pd.Timestamp(v)
                        df.loc[df[code_col].astype(str) == str(selected_code).strip(), k] = v
                    st.session_state["df"] = df
                    saved,
