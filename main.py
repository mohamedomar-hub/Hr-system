# hr_system_delegation_v1.py
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
.stTextInput>div>div>input, .stNumberInput>div>input, .stDateInput>div>input {background-color: #071226; color: #e6eef8;}
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

def load_excel_from_github():
    try:
        url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{FILE_PATH}?ref={BRANCH}"
        resp = requests.get(url, headers=github_headers(), timeout=30)
        if resp.status_code == 200:
            content = resp.json()
            file_content = base64.b64decode(content["content"])
            return file_content
        else:
            return None
    except Exception:
        return None

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

def upload_to_github(file_content, commit_message="Update employees via Streamlit"):
    if not GITHUB_TOKEN:
        return False
    try:
        file_content_b64 = base64.b64encode(file_content).decode("utf-8")
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
# Excel I/O with LeaveRequests sheet
# ============================
def load_dataframes():
    employees_df = pd.DataFrame()
    leave_requests_df = pd.DataFrame()

    if GITHUB_TOKEN:
        file_content = load_excel_from_github()
        if file_content:
            excel_file = BytesIO(file_content)
            sheets = pd.read_excel(excel_file, sheet_name=None)
            employees_df = sheets.get("Employees", pd.DataFrame())
            leave_requests_df = sheets.get("LeaveRequests", pd.DataFrame())
        else:
            if os.path.exists(FILE_PATH):
                try:
                    sheets = pd.read_excel(FILE_PATH, sheet_name=None)
                    employees_df = sheets.get("Employees", pd.DataFrame())
                    leave_requests_df = sheets.get("LeaveRequests", pd.DataFrame())
                except Exception:
                    pass
    else:
        if os.path.exists(FILE_PATH):
            try:
                sheets = pd.read_excel(FILE_PATH, sheet_name=None)
                employees_df = sheets.get("Employees", pd.DataFrame())
                leave_requests_df = sheets.get("LeaveRequests", pd.DataFrame())
            except Exception:
                pass

    # Ensure required columns in LeaveRequests
    required_leave_cols = [
        "request_id", "employee_code", "employee_name", "manager_code",
        "start_date", "end_date", "days_requested", "reason",
        "status", "date_submitted", "date_resolved"
    ]
    if leave_requests_df.empty:
        leave_requests_df = pd.DataFrame(columns=required_leave_cols)
    else:
        for col in required_leave_cols:
            if col not in leave_requests_df.columns:
                leave_requests_df[col] = None

    return employees_df, leave_requests_df

def save_dataframes(employees_df, leave_requests_df, actor="System"):
    try:
        output = BytesIO()
        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            employees_df.to_excel(writer, index=False, sheet_name="Employees")
            leave_requests_df.to_excel(writer, index=False, sheet_name="LeaveRequests")
        output.seek(0)
        file_bytes = output.getvalue()

        # Save locally
        with open(FILE_PATH, "wb") as f:
            f.write(file_bytes)

        # Push to GitHub
        if GITHUB_TOKEN:
            upload_to_github(file_bytes, commit_message=f"Update by {actor}")

        return True
    except Exception as e:
        st.error(f"Save error: {e}")
        return False

# ============================
# Helpers
# ============================
def ensure_session_data():
    if "employees_df" not in st.session_state or "leave_requests_df" not in st.session_state:
        emp_df, lr_df = load_dataframes()
        st.session_state["employees_df"] = emp_df
        st.session_state["leave_requests_df"] = lr_df

def login(df, code, password):
    df_local = df.copy()
    col_map = {c.lower(): c for c in df_local.columns}
    code_col = col_map.get("employee_code", None)
    pass_col = col_map.get("password", None)
    title_col = col_map.get("title", None)
    name_col = col_map.get("employee name", None)
    if not all([code_col, pass_col, title_col, name_col]):
        return None
    df_local[code_col] = df_local[code_col].astype(str).str.strip()
    df_local[pass_col] = df_local[pass_col].astype(str).str.strip()
    code_s, pwd_s = str(code).strip(), str(password).strip()
    matched = df_local[(df_local[code_col] == code_s) & (df_local[pass_col] == pwd_s)]
    if not matched.empty:
        return matched.iloc[0].to_dict()
    return None

def calculate_leave_days(start_date, end_date):
    if pd.isna(start_date) or pd.isna(end_date):
        return 0
    return (end_date - start_date).days + 1

def is_manager_of(user_code, employee_row, col_map):
    manager_code_col = col_map.get("manager code")
    if manager_code_col and manager_code_col in employee_row:
        return str(employee_row[manager_code_col]) == str(user_code)
    return False

# ============================
# UI Components
# ============================
def render_logo_and_title():
    cols = st.columns([1,6,1])
    with cols[1]:
        if os.path.exists(LOGO_PATH):
            st.image(LOGO_PATH, width=160)
        st.markdown("<h1 style='color:#e6eef8'>HR System — Delegation Mode</h1>", unsafe_allow_html=True)

def format_date_display(dt):
    if pd.isna(dt):
        return ""
    return dt.strftime("%d-%m-%Y")

def page_my_profile(user):
    st.subheader("My Profile")
    df = st.session_state.get("employees_df", pd.DataFrame())
    if df.empty:
        st.info("No employee data.")
        return

    col_map = {c.lower(): c for c in df.columns}
    code_col = col_map.get("employee_code")
    if not code_col:
        st.error("Employee code column missing.")
        return

    user_code = user.get(code_col) or user.get("employee_code") or user.get("Employee Code")
    row = df[df[code_col].astype(str) == str(user_code)]
    if row.empty:
        st.error("Record not found.")
        return

    # Display profile
    st.markdown("### Basic Information")
    st.dataframe(row.reset_index(drop=True), use_container_width=True)

    buf = BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as writer:
        row.to_excel(writer, index=False, sheet_name="MyProfile")
    buf.seek(0)
    st.download_button("Download My Profile", data=buf, file_name="my_profile.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

    st.markdown("---")

    # Leave Balance (formatted as integer)
    st.markdown("### 📅 Annual Leave Balance")
    leave_col = col_map.get("annual_leave_balance")
    if leave_col and leave_col in row.columns:
        balance = row.iloc[0][leave_col]
        if pd.notna(balance):
            balance_int = int(round(balance))
            total = 30
            used = total - balance_int
            st.metric("Remaining Days", balance_int)
            st.metric("Used Days", used)
            st.progress(max(0, min(1, balance_int / total)))
        else:
            st.warning("Leave balance not set.")
    else:
        st.warning("Leave balance column not found.")

    st.markdown("---")

    # Request Leave Form
    st.markdown("### 📝 Request Leave (Sent to Your Manager)")
    if leave_col and leave_col in row.columns:
        balance = row.iloc[0][leave_col]
        if pd.isna(balance):
            st.error("Leave balance not set.")
        else:
            balance_int = int(round(balance))
            with st.form("leave_request_form"):
                start_date = st.date_input("Start Date", value=datetime.date.today())
                end_date = st.date_input("End Date", value=datetime.date.today())
                reason = st.text_input("Reason (optional)")
                submitted = st.form_submit_button("Submit Leave Request")
                if submitted:
                    if end_date < start_date:
                        st.error("End date cannot be before start date.")
                    else:
                        days = calculate_leave_days(pd.Timestamp(start_date), pd.Timestamp(end_date))
                        if days > balance_int:
                            st.error(f"Requested {days} days, but you only have {balance_int} days available.")
                        else:
                            # Add to leave_requests_df
                            lr_df = st.session_state["leave_requests_df"]
                            new_id = lr_df["request_id"].max() + 1 if not lr_df.empty else 1
                            new_row = {
                                "request_id": new_id,
                                "employee_code": str(user_code),
                                "employee_name": user.get("Employee Name", "Unknown"),
                                "manager_code": row.iloc[0].get(col_map.get("manager code"), None),
                                "start_date": pd.Timestamp(start_date),
                                "end_date": pd.Timestamp(end_date),
                                "days_requested": days,
                                "reason": reason,
                                "status": "Pending",
                                "date_submitted": datetime.datetime.now(),
                                "date_resolved": None
                            }
                            st.session_state["leave_requests_df"] = pd.concat(
                                [lr_df, pd.DataFrame([new_row])], ignore_index=True
                            )
                            if save_dataframes(st.session_state["employees_df"], st.session_state["leave_requests_df"], actor=user.get("Employee Name", "Employee")):
                                st.success("✅ Leave request sent to your manager!")
                            else:
                                st.error("Failed to save request.")
                            st.experimental_rerun()
    else:
        st.info("Leave requests not available.")

    st.markdown("---")

    # My Leave History
    st.markdown("### ✅ My Leave History")
    lr_df = st.session_state["leave_requests_df"]
    my_requests = lr_df[lr_df["employee_code"] == str(user_code)]
    if not my_requests.empty:
        display_df = my_requests.copy()
        display_df["start_date"] = display_df["start_date"].apply(format_date_display)
        display_df["end_date"] = display_df["end_date"].apply(format_date_display)
        display_df["date_submitted"] = pd.to_datetime(display_df["date_submitted"]).dt.strftime("%d-%m-%Y %H:%M")
        st.dataframe(
            display_df[["start_date", "end_date", "days_requested", "reason", "status", "date_submitted"]],
            use_container_width=True
        )
    else:
        st.info("No leave requests yet.")

def page_manager_approvals(user):
    st.subheader("📁 Leave Requests to Approve")
    emp_df = st.session_state["employees_df"]
    lr_df = st.session_state["leave_requests_df"]
    col_map = {c.lower(): c for c in emp_df.columns}
    user_code = user.get(col_map.get("employee_code"))

    pending = lr_df[(lr_df["manager_code"] == str(user_code)) & (lr_df["status"] == "Pending")]
    if pending.empty:
        st.info("No pending leave requests.")
        return

    for idx, req in pending.iterrows():
        st.markdown(f"**Employee:** {req['employee_name']} (`{req['employee_code']}`)")
        st.markdown(f"**Period:** {format_date_display(req['start_date'])} → {format_date_display(req['end_date'])}")
        st.markdown(f"**Days:** {int(req['days_requested'])}")
        st.markdown(f"**Reason:** {req['reason'] or '—'}")
        st.markdown(f"**Submitted:** {req['date_submitted'].strftime('%d-%m-%Y %H:%M') if pd.notna(req['date_submitted']) else '—'}")

        col1, col2 = st.columns(2)
        with col1:
            if st.button("✅ Approve", key=f"app_{req['request_id']}"):
                # Deduct leave
                emp_row = emp_df[emp_df[col_map["employee_code"]].astype(str) == str(req["employee_code"])]
                if not emp_row.empty:
                    current_balance = emp_row.iloc[0][col_map["annual_leave_balance"]]
                    if pd.notna(current_balance) and current_balance >= req["days_requested"]:
                        emp_df.loc[emp_df[col_map["employee_code"]].astype(str) == str(req["employee_code"]), col_map["annual_leave_balance"]] = current_balance - req["days_requested"]
                        lr_df.loc[idx, "status"] = "Approved"
                        lr_df.loc[idx, "date_resolved"] = datetime.datetime.now()
                        st.session_state["employees_df"] = emp_df
                        st.session_state["leave_requests_df"] = lr_df
                        if save_dataframes(emp_df, lr_df, actor=user.get("Employee Name", "Manager")):
                            st.success("Leave approved and balance updated.")
                        else:
                            st.error("Failed to save approval.")
                        st.experimental_rerun()
                    else:
                        st.error("Insufficient leave balance.")
                else:
                    st.error("Employee not found.")
        with col2:
            if st.button("❌ Reject", key=f"rej_{req['request_id']}"):
                lr_df.loc[idx, "status"] = "Rejected"
                lr_df.loc[idx, "date_resolved"] = datetime.datetime.now()
                st.session_state["leave_requests_df"] = lr_df
                if save_dataframes(st.session_state["employees_df"], lr_df, actor=user.get("Employee Name", "Manager")):
                    st.success("Request rejected.")
                else:
                    st.error("Failed to save rejection.")
                st.experimental_rerun()
        st.markdown("---")

def page_hr_manager(user):
    st.subheader("HR Manager")
    lr_df = st.session_state["leave_requests_df"]
    if lr_df.empty:
        st.info("No leave requests recorded.")
    else:
        display_df = lr_df.copy()
        display_df["start_date"] = display_df["start_date"].apply(format_date_display)
        display_df["end_date"] = display_df["end_date"].apply(format_date_display)
        display_df["date_submitted"] = pd.to_datetime(display_df["date_submitted"]).dt.strftime("%d-%m-%Y %H:%M")
        display_df["date_resolved"] = pd.to_datetime(display_df["date_resolved"]).dt.strftime("%d-%m-%Y %H:%M")
        st.dataframe(display_df, use_container_width=True)

    st.markdown("---")
    # Existing HR functions (upload, edit, etc.) can be added below if needed

def page_dashboard(user):
    df = st.session_state.get("employees_df", pd.DataFrame())
    if df.empty:
        st.info("No data.")
        return
    col_map = {c.lower(): c for c in df.columns}
    dept_col = col_map.get("department")
    total_employees = df.shape[0]
    total_departments = df[dept_col].nunique() if dept_col else 0
    c1, c2 = st.columns(2)
    c1.metric("Total Employees", total_employees)
    c2.metric("Departments", total_departments)

# ============================
# Main App
# ============================
ensure_session_data()
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
        df = st.session_state.get("employees_df", pd.DataFrame())
        user = login(df, uid, pwd)
        if user is None:
            st.sidebar.error("Invalid credentials.")
        else:
            st.session_state["logged_in_user"] = user
            st.experimental_rerun()
else:
    user = st.session_state["logged_in_user"]
    emp_df = st.session_state["employees_df"]
    col_map = {c.lower(): c for c in emp_df.columns}
    title_val = str(user.get("Title") or "").strip().lower()
    user_code = user.get(col_map.get("employee_code"))

    is_hr = "hr" in title_val
    is_manager = False
    if not is_hr:
        # Check if this user is a manager of anyone
        manager_code_col = col_map.get("manager code")
        if manager_code_col and emp_df[emp_df[manager_code_col].astype(str) == str(user_code)].shape[0] > 0:
            is_manager = True

    st.sidebar.write(f"👋 Welcome, {user.get('Employee Name', '')}")
    st.sidebar.markdown("---")

    if is_hr:
        page = st.sidebar.radio("Pages", ("Dashboard", "HR Manager", "Logout"))
        if page == "Dashboard":
            page_dashboard(user)
        elif page == "HR Manager":
            page_hr_manager(user)
        elif page == "Logout":
            st.session_state["logged_in_user"] = None
            st.experimental_rerun()
    elif is_manager:
        page = st.sidebar.radio("Pages", ("My Profile", "Approve Leaves", "Logout"))
        if page == "My Profile":
            page_my_profile(user)
        elif page == "Approve Leaves":
            page_manager_approvals(user)
        elif page == "Logout":
            st.session_state["logged_in_user"] = None
            st.experimental_rerun()
    else:
        page = st.sidebar.radio("Pages", ("My Profile", "Logout"))
        if page == "My Profile":
            page_my_profile(user)
        elif page == "Logout":
            st.session_state["logged_in_user"] = None
            st.experimental_rerun()
