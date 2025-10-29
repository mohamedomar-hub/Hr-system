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
[data-testid="stAppViewContainer"] {background-color: #0f1724;color: #e6eef8;}
[data-testid="stHeader"], [data-testid="stToolbar"] {background-color: #0b1220;}
.stButton>button {background-color: #0b72b9;color: white;border-radius: 8px;padding: 6px 12px;}
[data-testid="stSidebar"] {background-color: #071226;}
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
    try:
        url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{FILE_PATH}?ref={BRANCH}"
        resp = requests.get(url, headers=github_headers(), timeout=30)
        if resp.status_code == 200:
            content = resp.json()
            file_content = base64.b64decode(content["content"])
            df = pd.read_excel(BytesIO(file_content))
            return df
        else:
            return pd.DataFrame()
    except Exception:
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
        return put_resp.status_code in (200,201)
    except Exception:
        return False

# ============================
# Helpers
# ============================
def ensure_session_df():
    if "df" not in st.session_state:
        df_loaded = load_employee_data_from_github()
        if not df_loaded.empty:
            st.session_state["df"] = df_loaded
        else:
            if os.path.exists(FILE_PATH):
                try:
                    st.session_state["df"] = pd.read_excel(FILE_PATH)
                except Exception:
                    st.session_state["df"] = pd.DataFrame()
            else:
                st.session_state["df"] = pd.DataFrame()

def login(df, code, password):
    code_col = "employee_code"
    pass_col = "password"
    title_col = "Title"
    name_col = "Employee Name"

    if any(c not in df.columns for c in [code_col, pass_col, title_col, name_col]):
        return None

    df_local = df.copy()
    df_local[code_col] = df_local[code_col].astype(str).str.strip()
    df_local[pass_col] = df_local[pass_col].astype(str).str.strip()

    code_s, pwd_s = str(code).strip(), str(password).strip()
    matched = df_local[(df_local[code_col] == code_s) & (df_local[pass_col] == pwd_s)]
    if not matched.empty:
        return matched.iloc[0].to_dict()
    return None

def save_df_to_local(df):
    try:
        with pd.ExcelWriter(FILE_PATH, engine="openpyxl") as writer:
            df.to_excel(writer, index=False)
        return True
    except Exception:
        return False

def save_and_maybe_push(df, actor="HR"):
    saved = save_df_to_local(df)
    pushed = False
    if saved and GITHUB_TOKEN:
        pushed = upload_to_github(df, commit_message=f"Update {FILE_PATH} via Streamlit by {actor}")
    return saved, pushed

# ============================
# UI: Pages
# ============================
def render_logo_and_title():
    cols = st.columns([1,6,1])
    with cols[1]:
        if os.path.exists(LOGO_PATH):
            st.image(LOGO_PATH, width=200)
        st.markdown("<h1 style='color:#e6eef8'>HR System — Dark Mode</h1>", unsafe_allow_html=True)

def page_my_profile(user):
    st.subheader("📋 My Profile")
    df = st.session_state.get("df", pd.DataFrame())
    row = df[df["employee_code"].astype(str) == str(user["employee_code"])]
    if row.empty:
        st.error("Your profile data was not found.")
    else:
        cols = ["employee_code","Employee Name","password","Mobile","Hiring Date","annual_leave_balance","monthly_salary","Title"]
        existing_cols = [c for c in cols if c in row.columns]
        st.dataframe(row[existing_cols], use_container_width=True)

def page_dashboard(user):
    st.subheader("📊 Dashboard")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.info("No employee data available.")
        return
    total = len(df)
    departments = df["Department"].nunique() if "Department" in df.columns else 0
    new_hires = 0
    if "Hire Date" in df.columns:
        try:
            df["Hire Date"] = pd.to_datetime(df["Hire Date"], errors="coerce")
            new_hires = df[df["Hire Date"] >= pd.Timestamp.now() - pd.Timedelta(days=30)].shape[0]
        except Exception:
            pass
    c1, c2, c3 = st.columns(3)
    c1.metric("👥 Total Employees", total)
    c2.metric("🏷️ Departments", departments)
    c3.metric("✨ New Hires (30 days)", new_hires)
    if "Department" in df.columns:
        dept_counts = df["Department"].fillna("Unknown").value_counts().reset_index()
        dept_counts.columns = ["Department","Count"]
        fig = px.pie(dept_counts, values="Count", names="Department", title="Employees by Department")
        st.plotly_chart(fig, use_container_width=True)

def page_edit_employees():
    st.subheader("✏️ Edit Employees")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.warning("No employee data available.")
        return
    edited_df = st.data_editor(df, num_rows="dynamic", use_container_width=True)
    if st.button("💾 Save Changes"):
        saved, pushed = save_and_maybe_push(edited_df, actor="HR")
        if saved:
            st.success("Changes saved locally.")
            if pushed:
                st.info("Changes pushed to GitHub.")
            st.session_state["df"] = edited_df
        else:
            st.error("Failed to save changes.")

def page_delete_employee():
    st.subheader("🗑️ Delete Employee")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.warning("No employee data available.")
        return
    selected_code = st.selectbox("Select employee code to delete", df["employee_code"].astype(str))
    if st.button("Delete"):
        confirm = st.checkbox("Confirm deletion")
        if confirm:
            df = df[df["employee_code"].astype(str) != selected_code]
            saved, pushed = save_and_maybe_push(df, actor="HR")
            if saved:
                st.success("Employee deleted.")
                if pushed:
                    st.info("Changes pushed to GitHub.")
                st.session_state["df"] = df
            else:
                st.error
