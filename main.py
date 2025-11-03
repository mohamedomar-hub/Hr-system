# hr_system_dark_mode_v3.py
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
/* App & layout */
[data-testid="stAppViewContainer"] {background-color: #0f1724; color: #e6eef8;}
[data-testid="stHeader"], [data-testid="stToolbar"] {background-color: #0b1220;}
.stButton>button {background-color: #0b72b9; color: white; border-radius: 8px; padding: 6px 12px;}
[data-testid="stSidebar"] {background-color: #071226;}
.stTextInput>div>div>input, .stNumberInput>div>input, .stSelectbox>div>div>div {background-color: #071226; color: #e6eef8;}
</style>
"""
st.markdown(dark_css, unsafe_allow_html=True)

# ============================
# Debug Helpers (added)
# ============================
def debug_log(msg):
    """Append a timestamped message to session debug logs."""
    try:
        if "debug_logs" not in st.session_state:
            st.session_state["debug_logs"] = []
        timestamp = pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S")
        st.session_state["debug_logs"].append(f"[{timestamp}] {msg}")
    except Exception:
        # fail silently to avoid breaking app UI
        pass

def show_debug_sidebar():
    """Display recent debug logs in the sidebar (call this in main flow)."""
    st.sidebar.markdown("### Debug Logs")
    logs = st.session_state.get("debug_logs", [])
    if logs:
        # show last 25 logs, newest first
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
        debug_log(f"Attempting to load from GitHub: {url}")
        resp = requests.get(url, headers=github_headers(), timeout=30)
        if resp.status_code == 200:
            content = resp.json()
            file_content = base64.b64decode(content["content"])
            df = pd.read_excel(BytesIO(file_content))
            debug_log(f"Loaded {len(df)} rows from GitHub.")
            return df
        else:
            debug_log(f"GitHub request returned status {resp.status_code}")
            return pd.DataFrame()
    except Exception as e:
        debug_log(f"Exception loading from GitHub: {e}")
        return pd.DataFrame()

def get_file_sha():
    try:
        url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{FILE_PATH}"
        params = {"ref": BRANCH}
        resp = requests.get(url, headers=github_headers(), params=params, timeout=30)
        if resp.status_code == 200:
            sha = resp.json().get("sha")
            debug_log(f"Got file SHA from GitHub: {sha}")
            return sha
        else:
            debug_log(f"Failed to get SHA. status: {resp.status_code}")
            return None
    except Exception as e:
        debug_log(f"Exception in get_file_sha: {e}")
        return None

def upload_to_github(df, commit_message="Update employees via Streamlit"):
    if not GITHUB_TOKEN:
        debug_log("No GITHUB_TOKEN set; skipping upload_to_github.")
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
        debug_log(f"Upload response status: {put_resp.status_code}")
        return ok
    except Exception as e:
        debug_log(f"Exception during upload_to_github: {e}")
        return False

# ============================
# Helpers
# ============================
def ensure_session_df():
    if "df" not in st.session_state:
        debug_log("ensure_session_df: 'df' not in session_state, attempting to load.")
        df_loaded = load_employee_data_from_github()
        if not df_loaded.empty:
            st.session_state["df"] = df_loaded
            debug_log(f"ensure_session_df: loaded df from GitHub with {len(df_loaded)} rows.")
        else:
            if os.path.exists(FILE_PATH):
                try:
                    st.session_state["df"] = pd.read_excel(FILE_PATH)
                    debug_log(f"ensure_session_df: loaded df from local file {FILE_PATH} with {len(st.session_state['df'])} rows.")
                except Exception as e:
                    st.session_state["df"] = pd.DataFrame()
                    debug_log(f"ensure_session_df: failed reading local file: {e}")
            else:
                st.session_state["df"] = pd.DataFrame()
                debug_log("ensure_session_df: no local file found, initialized empty DataFrame.")

    # post-load normalization (trim column names and clean code/password-like columns)
    try:
        df = st.session_state.get("df", pd.DataFrame())
        if not df.empty:
            # strip column names
            df.columns = [str(c).strip() for c in df.columns]
            # normalize likely code/password columns to strings (remove .0 from numeric import)
            for col in df.columns:
                low = col.lower()
                if "code" in low or "pass" in low or "pwd" in low:
                    try:
                        df[col] = df[col].astype(str).fillna("").apply(lambda x: x.strip().replace(".0",""))
                    except Exception as e:
                        debug_log(f"ensure_session_df: warning cleaning column {col}: {e}")
            st.session_state["df"] = df
            debug_log(f"ensure_session_df: columns normalized: {list(df.columns)}")
    except Exception as e:
        debug_log(f"ensure_session_df: normalization error: {e}")

def login(df, code, password):
    # improved/fault-tolerant login with debug logging; DOES NOT remove required functionality
    debug_log("login: called")
    if df is None or df.empty:
        debug_log("login: dataframe empty or None.")
        return None

    # map lowercase -> original names
    col_map = {c.lower().strip(): c for c in df.columns}
    debug_log(f"login: available columns - {list(df.columns)}")

    # try common column names (case-insensitive)
    code_col = col_map.get("employee_code", None) or col_map.get("employee code", None) or col_map.get("code", None)
    pass_col = col_map.get("password", None) or col_map.get("pass", None) or col_map.get("pwd", None)
    title_col = col_map.get("title", None) or col_map.get("job title", None)
    name_col = col_map.get("employee name", None) or col_map.get("name", None)

    debug_log(f"login: detected cols -> code_col={code_col}, pass_col={pass_col}, title_col={title_col}, name_col={name_col}")

    # Fallback: try to find partial matches if exact not found
    if not code_col or not pass_col:
        for orig in df.columns:
            low = orig.lower()
            if not code_col and ("code" in low or ("id" in low and "emp" in low)):
                code_col = orig
            if not pass_col and ("pass" in low or "pwd" in low):
                pass_col = orig
    debug_log(f"login: after fallback -> code_col={code_col}, pass_col={pass_col}")

    # If essential columns missing, cannot login
    if not code_col or not pass_col:
        debug_log("login: required columns missing, aborting login.")
        return None

    try:
        df_local = df.copy()
        # normalize stored values and user input
        df_local[code_col] = df_local[code_col].astype(str).fillna("").apply(lambda x: x.strip().replace(".0",""))
        df_local[pass_col] = df_local[pass_col].astype(str).fillna("").apply(lambda x: x.strip())
    except Exception as e:
        debug_log(f"login: error normalizing df columns: {e}")
        return None

    code_s, pwd_s = str(code).strip(), str(password).strip()
    debug_log(f"login: attempting match for code='{code_s}'")

    matched = df_local[(df_local[code_col] == code_s) & (df_local[pass_col] == pwd_s)]
    debug_log(f"login: matched rows count = {len(matched)}")
    if not matched.empty:
        debug_log("login: success")
        return matched.iloc[0].to_dict()
    debug_log("login: failed - no matching credentials")
    return None

def save_df_to_local(df):
    try:
        with pd.ExcelWriter(FILE_PATH, engine="openpyxl") as writer:
            df.to_excel(writer, index=False)
        debug_log(f"save_df_to_local: saved to {FILE_PATH}")
        return True
    except Exception as e:
        debug_log(f"save_df_to_local: exception {e}")
        return False

def save_and_maybe_push(df, actor="HR"):
    saved = save_df_to_local(df)
    pushed = False
    if saved and GITHUB_TOKEN:
        pushed = upload_to_github(df, commit_message=f"Update {FILE_PATH} via Streamlit by {actor}")
    debug_log(f"save_and_maybe_push: saved={saved}, pushed={pushed}")
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
    # Find the matching row by code (user dict may include original column name)
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

    # Normalize column names
    col_map = {c.lower(): c for c in df.columns}
    dept_col = col_map.get("department")
    hire_col = col_map.get("hire date") or col_map.get("hire_date") or col_map.get("hiring date")
    # salary_col left if needed later
    # salary_col = col_map.get("monthly_salary") or col_map.get("monthly salary") or col_map.get("salary")

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
        # Show numeric table only (as requested)
        st.table(dept_counts.sort_values("Employee Count", ascending=False).reset_index(drop=True))
    else:
        st.info("Department column not found. Please ensure there's a 'Department' column in the Excel file.")

    st.markdown("---")
    # Export and Save actions
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
                    st.info("Saved locally. GitHub token not configured, so no push performed.")
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
            st.markdown("**Note:** Uploading will replace the current dataset in-memory. You must Save to persist changes locally and optionally push to GitHub.")
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
                    saved, pushed = save_and_maybe_push(df, actor=user.get("Employee Name","HR"))
                    if saved:
                        st.success("Employee updated and saved locally.")
                        if pushed:
                            st.success("Changes pushed to GitHub.")
                        else:
                            if GITHUB_TOKEN:
                                st.warning("Saved locally but GitHub push failed.")
                            else:
                                st.info("Saved locally. GitHub not configured, so no push performed.")
                    else:
                        st.error("Failed to save changes locally.")

            st.markdown("#### Delete Employee")
            if st.button("Initiate Delete"):
                st.session_state["delete_target"] = str(selected_code).strip()

            if st.session_state.get("delete_target") == str(selected_code).strip():
                st.warning(f"You are about to delete employee with code: {selected_code}. This action is irreversible.")
                col_del1, col_del2 = st.columns(2)
                with col_del1:
                    if st.button("Confirm Delete"):
                        st.session_state["df"] = df[df[code_col].astype(str) != str(selected_code).strip()].reset_index(drop=True)
                        saved, pushed = save_and_maybe_push(st.session_state["df"], actor=user.get("Employee Name","HR"))
                        st.session_state["delete_target"] = None
                        if saved:
                            st.success("Employee deleted and dataset saved locally.")
                            if pushed:
                                st.success("Deletion pushed to GitHub.")
                            else:
                                if GITHUB_TOKEN:
                                    st.warning("Saved locally but GitHub push failed.")
                                else:
                                    st.info("Saved locally. GitHub not configured, so no push performed.")
                        else:
                            st.error("Failed to save after deletion.")
                with col_del2:
                    if st.button("Cancel Delete"):
                        st.session_state["delete_target"] = None
                        st.info("Deletion cancelled.")

    st.markdown("---")
    st.markdown("### Save / Push Dataset")
    if st.button("Save current in-memory dataset locally and optionally push to GitHub"):
        df_current = st.session_state.get("df", pd.DataFrame())
        saved, pushed = save_and_maybe_push(df_current, actor=user.get("Employee Name","HR"))
        if saved:
            if pushed:
                st.success("Saved locally and pushed to GitHub.")
            else:
                if GITHUB_TOKEN:
                    st.warning("Saved locally but GitHub push failed.")
                else:
                    st.info("Saved locally. GitHub not configured, so no push performed.")
        else:
            st.error("Failed to save dataset locally.")

def page_reports(user):
    st.subheader("Reports (Placeholder)")
    st.info("Reports section - ready to be expanded with ready reports. Current placeholder shows basic info.")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.info("No data to report.")
        return
    st.markdown("Basic preview of dataset:")
    st.dataframe(df.head(200), use_container_width=True)
    buf = BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Employees")
    buf.seek(0)
    st.download_button("Export Report Data (Excel)", data=buf, file_name="report_employees.xlsx", mime="application/vnd.openxmlformats-officedocument-spreadsheetml.sheet")

# ============================
# Main App Flow
# ============================
ensure_session_df()
render_logo_and_title()

# show debug logs in sidebar (non-intrusive)
show_debug_sidebar()

st.sidebar.title("Menu")
if "logged_in_user" not in st.session_state:
    st.session_state["logged_in_user"] = None

# Login UI
if not st.session_state["logged_in_user"]:
    st.sidebar.subheader("Login")
    with st.sidebar.form("login_form"):
        uid = st.text_input("Employee Code")
        pwd = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Sign in")
    if submitted:
        df = st.session_state.get("df", pd.DataFrame())
        debug_log(f"Login form submitted. uid='{uid}'")
        user = login(df, uid, pwd)
        if user is None:
            st.sidebar.error("Invalid credentials or required columns missing.")
            debug_log("Login failed or required columns missing after submission.")
        else:
            st.session_state["logged_in_user"] = user
            debug_log(f"User logged in: {user.get('Employee Name') or user.get('employee name') or user.get('name','')}")
            st.experimental_rerun()
else:
    user = st.session_state["logged_in_user"]
    title_val = str(user.get("Title") or user.get("title") or "").strip().lower()
    is_hr = title_val == "hr" or "hr" in title_val
    st.sidebar.write(f"👋 Welcome, {user.get('Employee Name') or user.get('employee name') or user.get('name','')}")
    st.sidebar.markdown("---")
    if is_hr:
        page = st.sidebar.radio("Pages", ("Dashboard","Reports","HR Manager","Logout"))
        if page == "Dashboard":
            page_dashboard(user)
        elif page == "Reports":
            page_reports(user)
        elif page == "HR Manager":
            page_hr_manager(user)
        elif page == "Logout":
            st.session_state["logged_in_user"] = None
            st.experimental_rerun()
    else:
        page = st.sidebar.radio("Pages", ("My Profile","Logout"))
        if page == "My Profile":
            page_my_profile(user)
        elif page == "Logout":
            st.session_state["logged_in_user"] = None
            st.experimental_rerun()
