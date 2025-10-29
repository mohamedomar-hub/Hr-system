# hr_system_dark_mode_v2_full.py
import streamlit as st
import pandas as pd
import requests
import base64
from io import BytesIO
import os
import datetime
import plotly.express as px
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

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

# SMTP configuration for notifications (optional)
SMTP_HOST = st.secrets.get("SMTP_HOST", None)
SMTP_PORT = st.secrets.get("SMTP_PORT", None)
SMTP_USER = st.secrets.get("SMTP_USER", None)
SMTP_PASS = st.secrets.get("SMTP_PASS", None)
FROM_EMAIL = st.secrets.get("FROM_EMAIL", SMTP_USER)

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
.stTextInput>div>div>input {background-color: #071226; color: #e6eef8;}
.stNumberInput>div>input {background-color: #071226; color: #e6eef8;}
.stSelectbox>div>div>div {background-color: #071226; color: #e6eef8;}
.streamlit-expanderHeader {color: #e6eef8;}
.css-1v0mbdj { color: #e6eef8; }
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
    # Expected column names
    # We accept flexible columns: 'employee_code' & 'password' may have different casing
    df_local = df.copy()
    # Normalize column names for matching
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
# Email notification helper
# ============================
def send_salary_notification(to_email, employee_name, salary_amount, details_url=None):
    """
    Send a simple salary notification email. Uses SMTP config from secrets.
    Returns True/False.
    """
    if not SMTP_HOST or not SMTP_PORT or not SMTP_USER or not SMTP_PASS or not FROM_EMAIL:
        return False, "SMTP not configured"
    try:
        subject = "Salary Paid Notification"
        body = f"""Hello {employee_name},

This is to notify you that your salary for this month has been deposited.

Details:
- Employee: {employee_name}
- Amount: {salary_amount}
- Date: {datetime.datetime.now().strftime('%Y-%m-%d')}

You can view more details in the HR portal. {f'Details: {details_url}' if details_url else ''}

Best regards,
HR Team
"""
        msg = MIMEMultipart()
        msg["From"] = FROM_EMAIL
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        server = smtplib.SMTP(SMTP_HOST, int(SMTP_PORT), timeout=20)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(FROM_EMAIL, to_email, msg.as_string())
        server.quit()
        return True, "Sent"
    except Exception as e:
        return False, str(e)

def notify_all_salaries(df, actor="HR"):
    """
    Iterate over rows with 'email' and 'monthly_salary' and send notifications.
    Returns a summary dict.
    """
    summary = {"attempted": 0, "sent": 0, "failed": 0, "errors": []}
    if "email" not in [c.lower() for c in df.columns]:
        return summary
    # find actual column names
    col_map = {c.lower(): c for c in df.columns}
    email_col = col_map.get("email")
    salary_col = col_map.get("monthly_salary") or col_map.get("monthly salary") or col_map.get("salary")
    name_col = col_map.get("employee name") or col_map.get("name")
    for idx, row in df.iterrows():
        email = str(row.get(email_col, "")).strip()
        if not email or email.lower() in ("nan","none"):
            continue
        salary_amt = row.get(salary_col, "N/A") if salary_col else "N/A"
        emp_name = row.get(name_col, "") if name_col else ""
        summary["attempted"] += 1
        ok, info = send_salary_notification(email, emp_name, salary_amt)
        if ok:
            summary["sent"] += 1
        else:
            summary["failed"] += 1
            summary["errors"].append({"email": email, "error": info})
    return summary

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
    # Get employee code column name (case-insensitive)
    col_map = {c.lower(): c for c in df.columns}
    code_col = col_map.get("employee_code")
    if not code_col:
        st.error("Employee code column not found in dataset.")
        return
    row = df[df[code_col].astype(str) == str(user.get(code_col) or user.get("employee_code") or user.get("Employee Code", ""))]
    if row.empty:
        st.error("Your record was not found.")
        return
    # Show all columns for this row
    st.dataframe(row.reset_index(drop=True), use_container_width=True)
    # Optionally allow employee to download their record
    to_download = row.copy()
    buf = BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as writer:
        to_download.to_excel(writer, index=False, sheet_name="MyProfile")
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
    salary_col = col_map.get("monthly_salary") or col_map.get("monthly salary") or col_map.get("salary")
    email_col = col_map.get("email")
    name_col = col_map.get("employee name") or col_map.get("name")

    total_employees = df.shape[0]
    total_departments = df[dept_col].nunique() if dept_col else "N/A"
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

    # Department distribution
    if dept_col:
        dept_counts = df[dept_col].fillna("Unknown").value_counts().reset_index()
        dept_counts.columns = ["Department", "Count"]
        fig = px.pie(dept_counts, names="Department", values="Count", title="Employees by Department")
        st.plotly_chart(fig, use_container_width=True)

    # Salary distribution and stats
    if salary_col:
        try:
            df[salary_col] = pd.to_numeric(df[salary_col], errors="coerce")
            salary_stats = df[salary_col].describe().to_frame().reset_index()
            st.subheader("Salary Statistics")
            st.table(salary_stats)
            fig2 = px.histogram(df, x=salary_col, nbins=30, title="Salary Distribution")
            st.plotly_chart(fig2, use_container_width=True)
        except Exception:
            st.info("Unable to compute salary statistics.")

    # Quick actions
    st.markdown("---")
    st.markdown("### Quick Actions")
    st.write("You can export the full employees data or trigger salary notifications (emails) if SMTP is configured.")
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

    if st.button("Send Salary Notifications (emails)"):
        if not SMTP_HOST or not SMTP_PORT:
            st.error("SMTP not configured. Please set SMTP settings in Streamlit secrets.")
        else:
            with st.spinner("Sending emails..."):
                result = notify_all_salaries(df, actor=user.get("Employee Name","HR"))
            st.write(result)

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

    # Show table with selection for editing
    display_df = df.copy()
    # show preview
    st.dataframe(display_df.head(100), use_container_width=True)

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
                # Dynamically create inputs for all columns
                updated = {}
                for col in df.columns:
                    val = row[col]
                    if pd.isna(val):
                        val = ""
                    if isinstance(val, (int, float)) and not isinstance(val, bool):
                        updated[col] = st.number_input(label=str(col), value=float(val) if pd.notna(val) else 0.0, key=f"edit_{col}")
                    elif pd.api.types.is_datetime64_any_dtype(type(val)) or "date" in str(col).lower():
                        try:
                            date_val = pd.to_datetime(val, errors="coerce")
                            updated[col] = st.date_input(label=str(col), value=date_val.date() if pd.notna(date_val) else datetime.date.today(), key=f"edit_{col}_date")
                        except Exception:
                            updated[col] = st.text_input(label=str(col), value=str(val), key=f"edit_{col}")
                    else:
                        updated[col] = st.text_input(label=str(col), value=str(val), key=f"edit_{col}")

                submitted_edit = st.form_submit_button("Save Changes")
                if submitted_edit:
                    # Apply updates to dataframe
                    for k, v in updated.items():
                        # convert date inputs back to datetime if needed
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
                        # perform deletion
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

    # Option to send salary notification for specific uploaded file presence
    st.markdown("---")
    st.markdown("### Salary Notification Trigger")
    if st.button("Trigger Salary Notifications for all employees with email"):
        if not SMTP_HOST or not SMTP_PORT:
            st.error("SMTP not configured. Please configure SMTP in Streamlit secrets to send notifications.")
        else:
            with st.spinner("Sending notifications..."):
                summary = notify_all_salaries(st.session_state.get("df", pd.DataFrame()), actor=user.get("Employee Name","HR"))
            st.write(summary)

def page_reports(user):
    st.subheader("Reports")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.info("No data to report.")
        return
    col_map = {c.lower(): c for c in df.columns}
    dept_col = col_map.get("department")
    salary_col = col_map.get("monthly_salary") or col_map.get("monthly salary") or col_map.get("salary")
    hire_col = col_map.get("hire date") or col_map.get("hire_date") or col_map.get("hiring date")
    # Basic ready reports:
    st.markdown("### 1) Headcount by Department")
    if dept_col:
        dept_counts = df[dept_col].fillna("Unknown").value_counts().reset_index()
        dept_counts.columns = ["Department", "Count"]
        st.dataframe(dept_counts)
        fig = px.bar(dept_counts, x="Department", y="Count", title="Headcount by Department")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Department column not found.")

    st.markdown("### 2) Salary Summary")
    if salary_col:
        try:
            df[salary_col] = pd.to_numeric(df[salary_col], errors="coerce")
            salary_summary = df.groupby(dept_col)[salary_col].agg(["count","mean","median","sum"]).reset_index() if dept_col else df[salary_col].describe().to_frame().reset_index()
            st.dataframe(salary_summary)
            fig2 = px.box(df, y=salary_col, title="Salary Boxplot")
            st.plotly_chart(fig2, use_container_width=True)
        except Exception:
            st.info("Failed to compute salary summary.")
    else:
        st.info("Salary column not found.")

    st.markdown("### 3) New Hires Over Time")
    if hire_col:
        try:
            df[hire_col] = pd.to_datetime(df[hire_col], errors="coerce")
            hires = df.dropna(subset=[hire_col])
            hires["hire_month"] = hires[hire_col].dt.to_period("M").astype(str)
            hires_counts = hires["hire_month"].value_counts().sort_index().reset_index()
            hires_counts.columns = ["Month","Hires"]
            st.dataframe(hires_counts)
            fig3 = px.line(hires_counts, x="Month", y="Hires", title="Hires Over Time")
            st.plotly_chart(fig3, use_container_width=True)
        except Exception:
            st.info("Failed to compute hires over time.")
    else:
        st.info("Hire Date column not found.")

    st.markdown("---")
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

# Login UI
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
            # normalize returned user dict keys to lower-case keys
            st.session_state["logged_in_user"] = user
            st.experimental_rerun()
else:
    user = st.session_state["logged_in_user"]
    # determine HR role: check Title column value
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
