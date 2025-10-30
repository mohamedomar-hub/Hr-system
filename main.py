# hr_system_dark_mode_v6.py
import streamlit as st
import pandas as pd
import requests
import base64
from io import BytesIO
import os
import datetime
from dateutil.relativedelta import relativedelta

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

    # Initialize leave requests and history if not exists
    if "leave_requests" not in st.session_state:
        st.session_state["leave_requests"] = []
    if "approved_leave_history" not in st.session_state:
        st.session_state["approved_leave_history"] = []

def login(df, code, password):
    df_local = df.copy()
    col_map = {c.lower(): c for c in df_local.columns}
    code_col = col_map.get("employee_code", None)
    pass_col = col_map.get("password", None)
    title_col = col_map.get("title", None)
    name_col = col_map.get("employee name", None) or col_map.get("name", None)
    if not code_col or not pass_col or not title_col or not name_col:
        return None
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
# UI Components / Pages
# ============================
def render_logo_and_title():
    cols = st.columns([1,6,1])
    with cols[1]:
        if os.path.exists(LOGO_PATH):
            st.image(LOGO_PATH, width=160)
        st.markdown("<h1 style='color:#e6eef8'>HR System — Dark Mode</h1>", unsafe_allow_html=True)
        st.markdown("<p style='color:#aab8c9'>English interface only</p>", unsafe_allow_html=True)

def generate_salary_history(hire_date, monthly_salary):
    if pd.isna(hire_date) or pd.isna(monthly_salary):
        return pd.DataFrame()
    try:
        start = pd.to_datetime(hire_date).replace(day=1)
        end = pd.Timestamp.today().replace(day=1)
        months = []
        current = start
        while current <= end:
            months.append({
                "Month": current.strftime("%B %Y"),
                "Date": current,
                "Salary": monthly_salary
            })
            current += relativedelta(months=1)
        return pd.DataFrame(months)
    except Exception:
        return pd.DataFrame()

def process_leave_approval(request_index, approve=True):
    """Approve or reject a leave request and update the employee's leave balance."""
    df = st.session_state["df"]
    req = st.session_state["leave_requests"][request_index]
    col_map = {c.lower(): c for c in df.columns}
    code_col = col_map.get("employee_code")
    leave_col = col_map.get("annual_leave_balance") or col_map.get("leave balance") or col_map.get("annual leave")

    if not code_col or not leave_col:
        st.error("Required columns missing for leave processing.")
        return False

    if approve:
        # Find employee and deduct leave
        emp_row = df[df[code_col].astype(str) == req["employee_code"]]
        if emp_row.empty:
            st.error("Employee not found.")
            return False
        current_balance = emp_row.iloc[0][leave_col]
        if pd.isna(current_balance) or current_balance < req["days_requested"]:
            st.error("Insufficient leave balance.")
            return False
        new_balance = current_balance - req["days_requested"]
        df.loc[df[code_col].astype(str) == req["employee_code"], leave_col] = new_balance
        st.session_state["df"] = df

        # Add to approved history
        approved_record = {
            "employee_code": req["employee_code"],
            "employee_name": req["employee_name"],
            "days_approved": req["days_requested"],
            "reason": req["reason"],
            "date_approved": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
            "status": "Approved"
        }
        st.session_state["approved_leave_history"].append(approved_record)

    # Remove request
    st.session_state["leave_requests"].pop(request_index)
    return True

def page_my_profile(user):
    st.subheader("My Profile")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.info("No employee data available.")
        return

    col_map = {c.lower(): c for c in df.columns}
    code_col = col_map.get("employee_code")
    if not code_col:
        st.error("Employee code column not found.")
        return

    user_code = user.get(code_col) or user.get("employee_code") or user.get("Employee Code")
    row = df[df[code_col].astype(str) == str(user_code)]
    if row.empty:
        st.error("Your record was not found.")
        return

    st.markdown("### Basic Information")
    st.dataframe(row.reset_index(drop=True), use_container_width=True)

    buf = BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as writer:
        row.to_excel(writer, index=False, sheet_name="MyProfile")
    buf.seek(0)
    st.download_button("Download My Profile (Excel)", data=buf, file_name="my_profile.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

    st.markdown("---")

    # Salary Details
    st.markdown("### 💰 Monthly Salary Details")
    salary_col = col_map.get("monthly_salary") or col_map.get("monthly salary") or col_map.get("salary")
    if salary_col and salary_col in row.columns:
        salary_val = row.iloc[0][salary_col]
        if pd.notna(salary_val):
            st.metric("Current Monthly Salary", f"${salary_val:,.0f}")
        else:
            st.warning("Salary not available.")
    else:
        st.warning("No 'Monthly Salary' column found.")

    st.markdown("---")

    # Salary History
    st.markdown("### 📊 View Salary History")
    hire_col = col_map.get("hiring date") or col_map.get("hire date") or col_map.get("hire_date")
    if hire_col and salary_col and hire_col in row.columns and salary_col in row.columns:
        hire_date = row.iloc[0][hire_col]
        salary_val = row.iloc[0][salary_col]
        salary_history_df = generate_salary_history(hire_date, salary_val)
        if not salary_history_df.empty:
            st.dataframe(salary_history_df[["Month", "Salary"]].sort_values("Month", ascending=False).reset_index(drop=True), use_container_width=True)
        else:
            st.info("No salary history available.")
    else:
        st.warning("Hiring date or salary missing.")

    st.markdown("---")

    # Leave Balance
    st.markdown("### 📅 Annual Leave Balance")
    leave_col = col_map.get("annual_leave_balance") or col_map.get("leave balance") or col_map.get("annual leave")
    if leave_col and leave_col in row.columns:
        leave_val = row.iloc[0][leave_col]
        if pd.notna(leave_val):
            total_annual_leave = 30
            used_leave = total_annual_leave - leave_val
            st.metric("Remaining Leave Days", int(leave_val))
            st.metric("Used Leave Days", int(used_leave))
            st.progress(max(0, min(1, leave_val / total_annual_leave)))
        else:
            st.warning("Leave balance not available.")
    else:
        st.warning("No 'Annual Leave Balance' column found.")

    st.markdown("---")

    # Request Leave (with approval)
    st.markdown("### 📝 Request Leave (Pending HR Approval)")
    if leave_col and leave_col in row.columns:
        current_balance = row.iloc[0][leave_col]
        if pd.isna(current_balance):
            st.error("Leave balance not set.")
        else:
            with st.form("request_leave_form"):
                days_requested = st.number_input("Number of leave days to request", min_value=1, max_value=int(current_balance), value=1)
                reason = st.text_input("Reason (optional)")
                submitted = st.form_submit_button("Submit Leave Request")
                if submitted:
                    if days_requested > current_balance:
                        st.error("Cannot request more than your balance.")
                    else:
                        # Create pending request
                        new_request = {
                            "employee_code": str(user_code),
                            "employee_name": user.get("Employee Name") or user.get("employee name") or "Unknown",
                            "days_requested": days_requested,
                            "reason": reason,
                            "date_requested": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
                            "status": "Pending"
                        }
                        st.session_state["leave_requests"].append(new_request)
                        st.success("✅ Leave request submitted! Awaiting HR approval.")
    else:
        st.info("Leave requests not available.")

    st.markdown("---")

    # Approved Leave History for Employee
    st.markdown("### ✅ Approved Leave History")
    approved_history = [r for r in st.session_state["approved_leave_history"] if r["employee_code"] == str(user_code)]
    if approved_history:
        history_df = pd.DataFrame(approved_history)
        st.dataframe(history_df[["date_approved", "days_approved", "reason"]].sort_values("date_approved", ascending=False).reset_index(drop=True), use_container_width=True)
    else:
        st.info("No approved leave history yet.")

def page_hr_manager(user):
    st.subheader("HR Manager")
    st.info("Upload new employee sheet, manage employees, and perform administrative actions.")

    # ======== NEW: Pending Leave Requests ========
    if "leave_requests" in st.session_state and st.session_state["leave_requests"]:
        st.markdown("### 📬 Pending Leave Requests")
        pending = [r for r in st.session_state["leave_requests"] if r["status"] == "Pending"]
        if pending:
            for i, req in enumerate(pending):
                st.markdown(f"**Employee:** {req['employee_name']} (`{req['employee_code']}`)")
                st.markdown(f"**Days:** {req['days_requested']}")
                st.markdown(f"**Reason:** {req['reason'] or '—'}")
                st.markdown(f"**Requested at:** {req['date_requested']}")
                col1, col2 = st.columns(2)
                with col1:
                    if st.button("✅ Approve", key=f"approve_{i}"):
                        success = process_leave_approval(i, approve=True)
                        if success:
                            saved, pushed = save_and_maybe_push(st.session_state["df"], actor=user.get("Employee Name","HR"))
                            if saved:
                                st.success("Leave approved and balance updated.")
                            else:
                                st.error("Failed to save after approval.")
                        st.experimental_rerun()
                with col2:
                    if st.button("❌ Reject", key=f"reject_{i}"):
                        st.session_state["leave_requests"].pop(i)
                        st.success("Request rejected.")
                        st.experimental_rerun()
                st.markdown("---")
        else:
            st.info("No pending leave requests.")
    else:
        st.markdown("### 📬 Pending Leave Requests")
        st.info("No pending leave requests.")

    st.markdown("---")

    # ======== NEW: Approved Leave History ========
    st.markdown("### ✅ Approved Leave History (All Employees)")
    if "approved_leave_history" in st.session_state and st.session_state["approved_leave_history"]:
        approved_df = pd.DataFrame(st.session_state["approved_leave_history"])
        st.dataframe(approved_df.sort_values("date_approved", ascending=False).reset_index(drop=True), use_container_width=True)
    else:
        st.info("No approved leave records yet.")

    st.markdown("---")

    # ======== Existing HR Functions ========
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

def page_dashboard(user):
    st.subheader("Dashboard")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.info("No employee data available.")
        return

    col_map = {c.lower(): c for c in df.columns}
    dept_possible_names = ["department", "dept", "الإدارة", "إدارة", "department name", "dept name", "section", "division"]
    dept_col = None
    for name in dept_possible_names:
        if name in col_map:
            dept_col = col_map[name]
            break
    if not dept_col:
        st.warning("No recognized 'Department' column found. Using 'Unknown'.")
        df['Department'] = 'Unknown'
        dept_col = 'Department'

    hire_col = col_map.get("hire date") or col_map.get("hire_date") or col_map.get("hiring date")

    total_employees = df.shape[0]
    total_departments = df[dept_col].nunique()
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
        st.info("Department column not found.")

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
                    st.info("Saved locally. GitHub token not configured, so no push performed.")
        else:
            st.error("Failed to save dataset locally.")

def page_reports(user):
    st.subheader("Reports (Placeholder)")
    st.info("Reports section - ready to be expanded.")
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
    st.download_button("Export Report Data (Excel)", data=buf, file_name="report_employees.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

# ============================
# Main App Flow
# ============================
ensure_session_df()
render_logo_and_title()
st.sidebar.title("Menu")
if "logged_in_user" not in st.session_state:
    st.session_state["logged_in_user"] = None

if not st.session_state["logged_in_user"]:
    st.sidebar.subheader("Login")
    with st.sidebar.form("login_form"):
        uid = st.text_input("Employee Code")
        pwd = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Sign in")
    if submitted:
        df = st.session_state.get("df", pd.DataFrame())
        user = login(df, uid, pwd)
        if user is None:
            st.sidebar.error("Invalid credentials or required columns missing.")
        else:
            st.session_state["logged_in_user"] = user
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
