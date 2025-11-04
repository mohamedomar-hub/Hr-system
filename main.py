# hr_system_dark_mode_v4_with_notifications.py
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
LEAVES_FILE_PATH = "Leaves.xlsx"
NOTIFICATIONS_FILE_PATH = "Notifications.xlsx"
LOGO_PATH = "logo.jpg"
GITHUB_TOKEN = st.secrets.get("GITHUB_TOKEN", None)
REPO_OWNER = st.secrets.get("REPO_OWNER", "mohamedomar-hub")
REPO_NAME = st.secrets.get("REPO_NAME", "hr-system")
BRANCH = st.secrets.get("BRANCH", "main")
FILE_PATH = st.secrets.get("FILE_PATH", DEFAULT_FILE_PATH) if st.secrets.get("FILE_PATH") else DEFAULT_FILE_PATH

# ============================
# Styling - Dark mode CSS (improved)
# ============================
st.set_page_config(page_title="HR System (Dark)", page_icon="👥", layout="wide")
# dark mode + improved typography + hover
dark_css = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');

/* App & layout */
[data-testid="stAppViewContainer"] {background-color: #0f1724; color: #e6eef8; font-family: 'Inter', system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial;}
[data-testid="stHeader"], [data-testid="stToolbar"] {background-color: #0b1220;}
[data-testid="stSidebar"] {background-color: #071226;}

/* Buttons */
.stButton>button {background-color: #0b72b9; color: white; border-radius: 8px; padding: 6px 12px; transition: transform .08s ease-in-out, box-shadow .08s ease-in-out;}
.stButton>button:hover{transform: translateY(-2px); box-shadow: 0 6px 18px rgba(11,114,185,0.18);}

/* Inputs */
.stTextInput>div>div>input, .stNumberInput>div>input, .stSelectbox>div>div>div, textarea {background-color: #071226; color: #e6eef8; border-radius:6px;}

/* Table rows */
[data-testid="stDataFrame"] tbody tr:nth-child(odd) {background: rgba(255,255,255,0.02);} 

/* Notification bell */
.notification-bell {font-size:22px; cursor:pointer;}
.notification-badge {background:#ef4444; color:white; border-radius:50%; padding:2px 8px; font-weight:600; margin-left:8px;}

/* small tweaks */
h1,h2,h3,h4,h5 {color:#e6eef8}
</style>
"""
st.markdown(dark_css, unsafe_allow_html=True)

# ============================
# GitHub helpers (unchanged logic)
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
# Helpers (kept intact and extended)
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

# Login function moved earlier to ensure it's defined before use in the main flow
def login(df, code, password):
    if df is None or df.empty:
        return None
    col_map = {c.lower().strip(): c for c in df.columns}
    code_col = col_map.get("employee_code") or col_map.get("employee code")
    pass_col = col_map.get("password")
    if not code_col or not pass_col:
        return None
    df_local = df.copy()
    df_local[code_col] = df_local[code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
    df_local[pass_col] = df_local[pass_col].astype(str).str.strip()
    code_s, pwd_s = str(code).strip(), str(password).strip()
    matched = df_local[(df_local[code_col] == code_s) & (df_local[pass_col] == pwd_s)]
    if not matched.empty:
        return matched.iloc[0].to_dict()
    return None

    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.error("Employee data not loaded.")
        return

    hierarchy = build_team_hierarchy(df, user_code, manager_title=role)

    if not hierarchy["Team"]:
        st.info(f"No team members found under your supervision.")
        return

    st.markdown(f"### 👤 {hierarchy['Manager']}")

    if role == "AM":
        for member in hierarchy["Team"]:
            addr = f" — {member['Address']}" if member['Address'] else ""
            st.markdown(f"#### 🧑‍💼 {member['Name']}{addr} — DM")
            if member["Subordinates"]:
                for mr in member["Subordinates"]:
                    mr_addr = f" ({mr['Address']})" if mr['Address'] else ""
                    st.markdown(f"- 👤 {mr['Name']}{mr_addr}")
            else:
                st.markdown("_No MRs under this DM._")
            st.markdown("---")
    elif role == "DM":
        for mr in hierarchy["Team"]:
            mr_addr = f" ({mr['Address']})" if mr['Address'] else ""
            st.markdown(f"- 👤 {mr['Name']}{mr_addr}")

# ============================
# UI Components / Pages (mostly unchanged but extended)
# ============================

def render_logo_and_title():
    cols = st.columns([1,6,1])
    with cols[1]:
        if os.path.exists(LOGO_PATH):
            st.image(LOGO_PATH, width=160)
        st.markdown("<h1 style='color:#e6eef8'>HR System — Dark Mode</h1>", unsafe_allow_html=True)
        st.markdown("<p style='color:#aab8c9'>English interface only</p>", unsafe_allow_html=True)

# Add a top-right bell when user is logged in
def render_notification_bell(user):
    if not user:
        return
    # compute unread count
    user_notifs = get_user_notifications(user)
    if user_notifs.empty:
        unread = 0
    else:
        unread = int(user_notifs[user_notifs["Is_Read"] == False].shape[0])
    # place in a small column at top-right
    cols = st.columns([6,1])
    with cols[1]:
        if unread > 0:
            if st.button(f"🔔  ", key="bell_btn"):
                st.session_state["show_notifications"] = True
        else:
            if st.button("🔔", key="bell_btn2"):
                st.session_state["show_notifications"] = True
        if unread > 0:
            st.markdown(f"<div style='text-align:right; margin-top:-28px; font-weight:600;'><span class='notification-badge'>{unread}</span></div>", unsafe_allow_html=True)


def page_my_profile(user):
    st.subheader("My Profile")
    st.markdown(f"### 👋 Welcome, {user.get('Employee Name', 'User')}")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.info("No employee data available.")
        return
    col_map = {c.lower().strip(): c for c in df.columns}
    code_col = col_map.get("employee_code") or col_map.get("employee code")
    if not code_col:
        st.error("Employee code column not found in dataset.")
        return
    user_code = None
    for key in user.keys():
        if key.lower().replace(" ", "").replace("_", "") in ["employeecode", "employee_code"]:
            val = str(user[key]).strip()
            if val.endswith('.0'):
                val = val[:-2]
            user_code = val
            break
    if user_code is None:
        st.error("Your Employee Code not found in session.")
        return
    df[code_col] = df[code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
    row = df[df[code_col] == user_code]
    if row.empty:
        st.error("Your record was not found.")
        return
    st.dataframe(row.reset_index(drop=True), use_container_width=True)
    buf = BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as writer:
        row.to_excel(writer, index=False, sheet_name="MyProfile")
    buf.seek(0)
    st.download_button("Download My Profile (Excel)", data=buf, file_name="my_profile.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


def page_leave_request(user):
    st.subheader("Request Leave")
    df_emp = st.session_state.get("df", pd.DataFrame())
    if df_emp.empty:
        st.error("Employee data not loaded.")
        return
    user_code = None
    for key, val in user.items():
        if key.lower().replace(" ", "").replace("_", "") in ["employeecode", "employee_code"]:
            user_code = str(val).strip()
            if user_code.endswith('.0'):
                user_code = user_code[:-2]
            break
    if not user_code:
        st.error("Your Employee Code not found.")
        return
    col_map = {c.lower().strip(): c for c in df_emp.columns}
    emp_code_col = col_map.get("employee_code") or col_map.get("employee code")
    mgr_code_col = col_map.get("manager_code") or col_map.get("manager code")
    if not mgr_code_col:
        st.error("Column 'Manager Code' is missing in employee sheet.")
        return
    emp_row = df_emp[df_emp[emp_code_col].astype(str).str.replace('.0', '', regex=False) == user_code]
    if emp_row.empty:
        st.error("Your record not found in employee sheet.")
        return
    manager_code = emp_row.iloc[0][mgr_code_col]
    if pd.isna(manager_code) or str(manager_code).strip() == "":
        st.warning("You have no manager assigned. Contact HR.")
        return
    manager_code = str(manager_code).strip()
    if manager_code.endswith('.0'):
        manager_code = manager_code[:-2]
    leaves_df = load_leaves_data()
    with st.form("leave_form"):
        start_date = st.date_input("Start Date")
        end_date = st.date_input("End Date")
        leave_type = st.selectbox("Leave Type", ["Annual", "Sick", "Emergency", "Unpaid"])
        reason = st.text_area("Reason")
        submitted = st.form_submit_button("Submit Leave Request")
    if submitted:
        if end_date < start_date:
            st.error("End date cannot be before start date.")
        else:
            new_row = pd.DataFrame([{
                "Employee Code": user_code,
                "Manager Code": manager_code,
                "Start Date": pd.Timestamp(start_date),
                "End Date": pd.Timestamp(end_date),
                "Leave Type": leave_type,
                "Reason": reason,
                "Status": "Pending",
                "Decision Date": None,
                "Comment": ""
            }])
            leaves_df = pd.concat([leaves_df, new_row], ignore_index=True)
            if save_leaves_data(leaves_df):
                st.success("✅ Leave request submitted successfully to your manager.")
                st.balloons()
                # Notify manager of new leave request
                create_notification(
                    title="New Leave Request",
                    message=f"Employee {user_code} submitted a leave request ({start_date} → {end_date}).",
                    target_title="DM",
                    target_code="-"
                )
            else:
                st.error("❌ Failed to save leave request.")
    st.markdown("### Your Leave Requests")
    if not leaves_df.empty:
        user_leaves = leaves_df[leaves_df["Employee Code"].astype(str) == user_code].copy()
        if not user_leaves.empty:
            user_leaves["Start Date"] = pd.to_datetime(user_leaves["Start Date"]).dt.strftime("%d-%m-%Y")
            user_leaves["End Date"] = pd.to_datetime(user_leaves["End Date"]).dt.strftime("%d-%m-%Y")
            st.dataframe(user_leaves[[
                "Start Date", "End Date", "Leave Type", "Status", "Comment"
            ]], use_container_width=True)
        else:
            st.info("You haven't submitted any leave requests yet.")
    else:
        st.info("No leave requests found.")


def page_manager_leaves(user):
    st.subheader("Leave Requests from Your Team")
    manager_code = None
    for key, val in user.items():
        if key.lower().replace(" ", "").replace("_", "") in ["employeecode", "employee_code"]:
            manager_code = str(val).strip()
            if manager_code.endswith('.0'):
                manager_code = manager_code[:-2]
            break
    if not manager_code:
        st.error("Your Employee Code not found.")
        return
    leaves_df = load_leaves_data()
    if leaves_df.empty:
        st.info("No leave requests found.")
        return
    team_leaves = leaves_df[leaves_df["Manager Code"].astype(str) == manager_code].copy()
    if team_leaves.empty:
        st.info("No leave requests from your team.")
        return
    # Merge with employee names
    df_emp = st.session_state.get("df", pd.DataFrame())
    name_col_to_use = "Employee Code"
    if not df_emp.empty:
        col_map = {c.lower().strip(): c for c in df_emp.columns}
        emp_code_col = col_map.get("employee_code") or col_map.get("employee code")
        emp_name_col = col_map.get("employee_name") or col_map.get("employee name") or col_map.get("name")
        if emp_code_col and emp_name_col:
            df_emp[emp_code_col] = df_emp[emp_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
            team_leaves["Employee Code"] = team_leaves["Employee Code"].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
            team_leaves = team_leaves.merge(
                df_emp[[emp_code_col, emp_name_col]],
                left_on="Employee Code",
                right_on=emp_code_col,
                how="left"
            )
            name_col_to_use = emp_name_col
    pending_leaves = team_leaves[team_leaves["Status"] == "Pending"].reset_index(drop=True)
    all_leaves = team_leaves.copy()
    st.markdown("### 🟡 Pending Requests")
    if not pending_leaves.empty:
        for idx, row in pending_leaves.iterrows():
            emp_name = row.get(name_col_to_use, "") if name_col_to_use in row else ""
            emp_display = f"{emp_name} ({row['Employee Code']})" if emp_name else row['Employee Code']
            st.markdown(f"**Employee**: {emp_display} | **Dates**: {row['Start Date'].strftime('%d-%m-%Y')} → {row['End Date'].strftime('%d-%m-%Y')} | **Type**: {row['Leave Type']}")
            st.write(f"**Reason**: {row['Reason']}")
            col1, col2 = st.columns(2)
            with col1:
            if st.button("✅ Approve", key=f"app_{idx}_{row['Employee Code']}"):
                leaves_df.at[row.name, "Status"] = "Approved"
                leaves_df.at[row.name, "Decision Date"] = pd.Timestamp.now()
                save_leaves_data(leaves_df)
                # reload leaves and recompute pending after save
                leaves_df = load_leaves_data()
                pending_leaves = leaves_df[(leaves_df["Manager Code"].astype(str) == manager_code) & (leaves_df["Status"] == "Pending")].copy()
                # ADD NOTIFICATION
                add_notification(row['Employee Code'], "", "Your leave request has been approved!")
                st.success("Approved!")
                st.experimental_rerun()
        with col2:
            if st.button("❌ Reject", key=f"rej_{idx}_{row['Employee Code']}"):
                comment = st.text_input("Comment (optional)", key=f"com_{idx}_{row['Employee Code']}")
                leaves_df.at[row.name, "Status"] = "Rejected"
                leaves_df.at[row.name, "Decision Date"] = pd.Timestamp.now()
                leaves_df.at[row.name, "Comment"] = comment
                save_leaves_data(leaves_df)
                # reload leaves and recompute pending after save
                leaves_df = load_leaves_data()
                pending_leaves = leaves_df[(leaves_df["Manager Code"].astype(str) == manager_code) & (leaves_df["Status"] == "Pending")].copy()
                # ADD NOTIFICATION
                msg = f"Your leave request was rejected. Comment: {comment}" if comment else "Your leave request was rejected."
                add_notification(row['Employee Code'], "", msg)
                st.success("Rejected!")
                st.experimental_rerun()
        st.markdown("---")
    else:
        st.info("No pending requests.")
    st.markdown("### 📋 All Team Leave History")
    if not all_leaves.empty:
        if name_col_to_use in all_leaves.columns:
            all_leaves["Employee Name"] = all_leaves[name_col_to_use]
        else:
            all_leaves["Employee Name"] = all_leaves["Employee Code"]
        all_leaves["Start Date"] = pd.to_datetime(all_leaves["Start Date"]).dt.strftime("%d-%m-%Y")
        all_leaves["End Date"] = pd.to_datetime(all_leaves["End Date"]).dt.strftime("%d-%m-%Y")
        st.dataframe(all_leaves[[
            "Employee Name", "Start Date", "End Date", "Leave Type", "Status", "Comment"
        ]], use_container_width=True)
    else:
        st.info("No leave history for your team.")


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
            # create notification that dataset saved (for AM/DM/MR)
            create_notification(
                title="Dataset Updated",
                message="The employee dataset was updated. Please review any changes (salaries, assignments, etc.).",
                target_title="ALL",
                target_code="-"
            )
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
            st.markdown("**Note:** Uploading will replace the current dataset in-memory.")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Replace In-Memory Dataset with Uploaded File"):
                    st.session_state["df"] = new_df.copy()
                    st.success("In-memory dataset replaced.")
                    # create notification to all AM/DM/MR about salaries or dataset update
                    create_notification(
                        title="Salaries / Dataset Updated",
                        message="HR replaced the employees dataset — please review salary and assignment changes.",
                        target_title="ALL",
                        target_code="-"
                    )
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
                        except Exception:
                            date_val = None
                        try:
                            updated[col] = st.date_input(label=str(col), value=date_val.date() if date_val is not None and pd.notna(date_val) else datetime.date.today(), key=f"edit_{col}_date")
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
                                st.info("Saved locally. GitHub not configured.")
                    else:
                        st.error("Failed to save changes locally.")
            st.markdown("#### Delete Employee")
            if st.button("Initiate Delete"):
                st.session_state["delete_target"] = str(selected_code).strip()
            if st.session_state.get("delete_target") == str(selected_code).strip():
                st.warning(f"You are about to delete employee with code: {selected_code}.")
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
                                    st.info("Saved locally. GitHub not configured.")
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
            # also notify all AM/DM/MR about dataset changes
            create_notification(
                title="Dataset Saved",
                message="HR saved the in-memory dataset. Please review changes.",
                target_title="ALL",
                target_code="-"
            )
            if pushed:
                st.success("Saved locally and pushed to GitHub.")
            else:
                if GITHUB_TOKEN:
                    st.warning("Saved locally but GitHub push failed.")
                else:
                    st.info("Saved locally. GitHub not configured.")
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
# ensure notifications file exists in case it's missing
ensure_notifications_file_exists()
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
            st.success("Login successful! Redirecting...")
            st.stop()
else:
    user = st.session_state["logged_in_user"]
    # render top-right bell
    try:
        render_notification_bell(user)
    except Exception:
        pass

    title_val = str(user.get("Title") or user.get("title") or "").strip().upper()
    is_hr = "HR" in title_val
    is_am = title_val == "AM"
    is_dm = title_val == "DM"

    st.sidebar.write(f"👋 Welcome, {user.get('Employee Name') or user.get('employee name') or user.get('name','')}")
    st.sidebar.markdown("---")

    # make Notifications page accessible for everyone with bell
    common_pages = ["My Profile", "Notifications", "Leave Request", "Logout"]
    if is_hr:
        page = st.sidebar.radio("Pages", ("Dashboard", "Reports", "HR Manager", "Notifications", "Logout"))
        if page == "Dashboard":
            page_dashboard(user)
        elif page == "Reports":
            page_reports(user)
        elif page == "HR Manager":
            page_hr_manager(user)
        elif page == "Notifications":
            page_notifications(user)
        elif page == "Logout":
            st.session_state["logged_in_user"] = None
            st.success("You have been logged out successfully.")
            st.stop()

    elif is_am:
        page = st.sidebar.radio("Pages", ("My Profile", "Team Structure", "Team Leaves", "Leave Request", "Notifications", "Logout"))
        if page == "My Profile":
            page_my_profile(user)
        elif page == "Team Structure":
            page_my_team(user, role="AM")
        elif page == "Team Leaves":
            page_manager_leaves(user)
        elif page == "Leave Request":
            page_leave_request(user)
        elif page == "Notifications":
            page_notifications(user)
        elif page == "Logout":
            st.session_state["logged_in_user"] = None
            st.success("You have been logged out successfully.")
            st.stop()

    elif is_dm:
        page = st.sidebar.radio("Pages", ("My Profile", "My Team", "Team Leaves", "Leave Request", "Notifications", "Logout"))
        if page == "My Profile":
            page_my_profile(user)
        elif page == "My Team":
            page_my_team(user, role="DM")
        elif page == "Team Leaves":
            page_manager_leaves(user)
        elif page == "Leave Request":
            page_leave_request(user)
        elif page == "Notifications":
            page_notifications(user)
        elif page == "Logout":
            st.session_state["logged_in_user"] = None
            st.success("You have been logged out successfully.")
            st.stop()

    else:  # MR
        page = st.sidebar.radio("Pages", ("My Profile", "Leave Request", "Notifications", "Logout"))
        if page == "My Profile":
            page_my_profile(user)
        elif page == "Leave Request":
            page_leave_request(user)
        elif page == "Notifications":
            page_notifications(user)
        elif page == "Logout":
            st.session_state["logged_in_user"] = None
            st.success("You have been logged out successfully.")
            st.stop()

# ============================
# Notifications Page (UI)
# ============================

def page_notifications(user):
    st.subheader("Notifications")
    df = get_user_notifications(user)
    if df.empty:
        st.markdown("🎉 You are all caught up!")
        return
    # show mark all as read
    col1, col2 = st.columns([1,1])
    with col1:
        if st.button("Mark all as read"):
            mark_notifications_as_read_for_user(user)
            st.experimental_rerun()
    with col2:
        if st.button("Refresh"):
            st.experimental_rerun()

    # display notifications with mark-as-read buttons
    for idx, row in df.iterrows():
        is_read = bool(row.get("Is_Read", False))
        ts = row.get("Timestamp")
        try:
            ts_disp = pd.to_datetime(ts).strftime('%d-%m-%Y %H:%M')
        except Exception:
            ts_disp = str(ts)
        st.markdown(f"**{row.get('Title','(No title)')}**  —  _{ts_disp}_")
        st.write(row.get('Message',''))
        if not is_read:
            if st.button(f"Mark as read", key=f"mark_{idx}"):
                # mark that single notification as read (use dataframe index)
                # We'll find the absolute index in the notifications file
                notif_df = load_notifications_data()
                # find the matching row by Timestamp & Title & Message (best-effort)
                try:
                    mask = (notif_df['Timestamp'].astype(str) == str(row['Timestamp'])) & (notif_df['Title'] == row['Title']) & (notif_df['Message'] == row['Message'])
                    notif_idxs = notif_df[mask].index.tolist()
                    if notif_idxs:
                        notif_idx = notif_idxs[0]
                        notif_df.loc[notif_idx, 'Is_Read'] = True
                        save_notifications_data(notif_df)
                except Exception:
                    pass
                st.experimental_rerun()
        st.markdown('---')

# ============================
# Retained functions from original file that were referenced earlier
# (login, save_df_to_local, save_and_maybe_push, load_leaves_data, save_leaves_data)
# These are included below unchanged to preserve original behavior.
# ============================

def login(df, code, password):
    if df is None or df.empty:
        return None
    col_map = {c.lower().strip(): c for c in df.columns}
    code_col = col_map.get("employee_code") or col_map.get("employee code")
    pass_col = col_map.get("password")
    if not code_col or not pass_col:
        return None
    df_local = df.copy()
    df_local[code_col] = df_local[code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
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


def load_leaves_data():
    if os.path.exists(LEAVES_FILE_PATH):
        try:
            df = pd.read_excel(LEAVES_FILE_PATH)
            if "Decision Date" in df.columns:
                df["Decision Date"] = pd.to_datetime(df["Decision Date"], errors="coerce")
            return df
        except Exception:
            return pd.DataFrame()
    else:
        return pd.DataFrame(columns=[
            "Employee Code", "Manager Code", "Start Date", "End Date",
            "Leave Type", "Reason", "Status", "Decision Date", "Comment"
        ])


def save_leaves_data(df):
    try:
        with pd.ExcelWriter(LEAVES_FILE_PATH, engine="openpyxl") as writer:
            df.to_excel(writer, index=False)
        return True
    except Exception:
        return False
