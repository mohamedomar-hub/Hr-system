import streamlit as st
import pandas as pd
import requests
import base64
from io import BytesIO
import os
import datetime

# ============================
# Configuration / Defaults
# ============================
DEFAULT_FILE_PATH = "Employees.xlsx"

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
        return put_resp.status_code in (200, 201)
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
    df_local = df.copy()
    if df_local.empty:
        return None

    def normalize(col):
        return str(col).strip().lower().replace(" ", "").replace("_", "").replace("\n", "").replace("\r", "")

    code_col = None
    pass_col = None
    title_col = None

    for col in df_local.columns:
        c = normalize(col)
        if "employeecode" in c or c in ["code", "employeeid", "id"]:
            code_col = col
        if "password" in c or "pass" in c or "pwd" in c:
            pass_col = col
        if "title" in c or "jobtitle" in c or "position" in c:
            title_col = col

    if not all([code_col, pass_col, title_col]):
        return None

    # تحويل الأعمدة لنص + إزالة المسافات الزائدة
    df_local[code_col] = df_local[code_col].astype(str).str.strip()
    df_local[pass_col] = df_local[pass_col].astype(str).str.strip()

    code_s = str(code).strip()
    pwd_s = str(password).strip()

    matched = df_local[(df_local[code_col] == code_s) & (df_local[pass_col] == pwd_s)]
    if not matched.empty:
        user = matched.iloc[0].to_dict()
        # إضافة اسم افتراضي لو مش موجود
        if "Employee Name" not in user and "employee name" not in user and "name" not in user:
            user["Employee Name"] = f"User {code_s}"
        return user
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
# UI Components / Pages
# ============================
def render_logo_and_title():
    cols = st.columns([1, 6, 1])
    with cols[1]:
        st.markdown("<h1 style='color:#e6eef8;text-align:center;'>HR System — Dark Mode</h1>", unsafe_allow_html=True)
        st.markdown("<p style='color:#aab8c9;text-align:center;'>English interface only</p>", unsafe_allow_html=True)

def page_my_profile(user):
    st.subheader("My Profile")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.info("No employee data available.")
        return

    def normalize(col):
        return str(col).strip().lower().replace(" ", "").replace("_", "")
    col_map = {normalize(c): c for c in df.columns}
    code_col = next((col for col in df.columns if normalize(col) in ["employeecode", "code", "employeeid"]), None)
    if not code_col:
        st.error("Employee code column not found.")
        return

    user_code = str(user.get(code_col) or user.get("employee_code") or "").strip()
    row = df[df[code_col].astype(str) == user_code]
    if row.empty:
        st.error("Your record was not found.")
        return

    row_display = row.copy()
    row_display[code_col] = row_display[code_col].astype(str).str.strip()
    st.dataframe(row_display.reset_index(drop=True), use_container_width=True)

def page_dashboard(user):
    st.subheader("HR Dashboard")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.info("No employee data available.")
        return

    def normalize(col):
        return str(col).strip().lower().replace(" ", "").replace("_", "")
    col_map = {normalize(c): c for c in df.columns}
    dept_col = col_map.get("department")
    hire_col = None
    for key in ["hiringdate", "hiredate", "hiring_date", "hire_date", "dateofhire"]:
        if key in col_map:
            hire_col = col_map[key]
            break

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
    if dept_col:
        dept_counts = df[dept_col].fillna("Unknown").value_counts().reset_index()
        dept_counts.columns = ["Department", "Employee Count"]
        st.table(dept_counts.sort_values("Employee Count", ascending=False).reset_index(drop=True))
    else:
        st.info("Department column not found.")

def page_hr_manager(user):
    st.subheader("HR Manager")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.info("No data. Upload or load employees first.")
        return

    uploaded_file = st.file_uploader("Upload new Employees.xlsx (replaces current data)", type=["xlsx"])
    if uploaded_file:
        try:
            new_df = pd.read_excel(uploaded_file)
            st.success("File loaded successfully.")
            st.dataframe(new_df.head(50), use_container_width=True)
            if st.button("✅ Replace Current Dataset"):
                st.session_state["df"] = new_df
                save_and_maybe_push(new_df, actor=user.get("Employee Name", "HR"))
                st.success("Dataset replaced and saved!")
                st.rerun()
        except Exception as e:
            st.error(f"Error reading file: {e}")

    st.markdown("---")
    st.write("Current Employees (first 100 rows):")
    st.dataframe(df.head(100), use_container_width=True)

    def normalize(col):
        return str(col).strip().lower().replace(" ", "").replace("_", "")
    col_map = {normalize(c): c for c in df.columns}
    code_col = next((col for col in df.columns if normalize(col) in ["employeecode", "code", "employeeid"]), None)
    if not code_col:
        st.error("Employee code column not found for editing.")
        return

    emp_code = st.text_input("Enter Employee Code to Edit/Delete")
    if emp_code:
        matched_rows = df[df[code_col].astype(str) == emp_code.strip()]
        if matched_rows.empty:
            st.warning("No employee found with that code.")
        else:
            row = matched_rows.iloc[0]
            st.markdown("#### Edit Employee")
            with st.form("edit_form"):
                updates = {}
                for col in df.columns:
                    val = row[col]
                    if pd.isna(val):
                        val = ""
                    if isinstance(val, (int, float)) and not isinstance(val, bool):
                        updates[col] = st.number_input(str(col), value=float(val) if pd.notna(val) else 0.0, key=f"edit_{col}")
                    elif "date" in str(col).lower():
                        try:
                            d_val = pd.to_datetime(val, errors="coerce")
                            updates[col] = st.date_input(str(col), value=d_val.date() if pd.notna(d_val) else datetime.date.today(), key=f"date_{col}")
                        except:
                            updates[col] = st.text_input(str(col), value=str(val), key=f"text_{col}")
                    else:
                        updates[col] = st.text_input(str(col), value=str(val), key=f"str_{col}")
                if st.form_submit_button("Save Changes"):
                    for k, v in updates.items():
                        if isinstance(v, datetime.date):
                            v = pd.Timestamp(v)
                        df.loc[df[code_col].astype(str) == emp_code.strip(), k] = v
                    st.session_state["df"] = df
                    save_and_maybe_push(df, actor=user.get("Employee Name", "HR"))
                    st.success("Employee updated!")
                    st.rerun()

            st.markdown("#### Delete Employee")
            if st.button("🗑️ Delete This Employee"):
                st.session_state["df"] = df[df[code_col].astype(str) != emp_code.strip()].reset_index(drop=True)
                save_and_maybe_push(st.session_state["df"], actor=user.get("Employee Name", "HR"))
                st.success("Employee deleted.")
                st.rerun()

def page_reports(user):
    st.subheader("Reports")
    st.info("Basic employee data export.")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.info("No data to report.")
        return
    st.dataframe(df, use_container_width=True)

# ============================
# Main App Flow
# ============================
ensure_session_df()
render_logo_and_title()
# --- DEBUG: عرض شكل البيانات ---
st.sidebar.write("📊 Data shape:", st.session_state["df"].shape)
if not st.session_state["df"].empty:
    st.sidebar.write("📋 Columns:", list(st.session_state["df"].columns))
else:
    st.sidebar.error("⚠️ No data loaded! Check GitHub file.")
# --------------------------------
if "logged_in_user" not in st.session_state:
    st.session_state["logged_in_user"] = None

# Login Screen
if not st.session_state["logged_in_user"]:
    st.sidebar.subheader("🔐 Login")
    with st.sidebar.form("login_form"):
        uid = st.text_input("Employee Code")
        pwd = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Sign in")
    if submitted:
        df = st.session_state.get("df", pd.DataFrame())
        user = login(df, uid, pwd)
        if user is None:
            st.sidebar.error("❌ Invalid credentials or missing columns.")
        else:
            st.session_state["logged_in_user"] = user
            st.rerun()

# Logged-in View
else:
    user = st.session_state["logged_in_user"]
    title_val = str(user.get("Title", "")).strip().lower()
    is_hr = "hr" in title_val

    st.sidebar.write(f"👋 Welcome, {user.get('Employee Name', 'User')}")
    st.sidebar.markdown("---")

    if is_hr:
        page = st.sidebar.radio("Navigation", ["Dashboard", "HR Manager", "Reports", "Logout"])
        if page == "Dashboard":
            page_dashboard(user)
        elif page == "HR Manager":
            page_hr_manager(user)
        elif page == "Reports":
            page_reports(user)
        elif page == "Logout":
            st.session_state["logged_in_user"] = None
            st.rerun()
    else:
        page = st.sidebar.radio("Navigation", ["My Profile", "Logout"])
        if page == "My Profile":
            page_my_profile(user)
        elif page == "Logout":
            st.session_state["logged_in_user"] = None
            st.rerun()
