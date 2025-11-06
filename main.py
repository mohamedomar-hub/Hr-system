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
HR_QUERIES_FILE_PATH = "HR_Queries.xlsx"
LOGO_PATH = "logo.jpg"
GITHUB_TOKEN = st.secrets.get("GITHUB_TOKEN", None)
REPO_OWNER = st.secrets.get("REPO_OWNER", "mohamedomar-hub")
REPO_NAME = st.secrets.get("REPO_NAME", "hr-system")
BRANCH = st.secrets.get("BRANCH", "main")
FILE_PATH = st.secrets.get("FILE_PATH", DEFAULT_FILE_PATH) if st.secrets.get("FILE_PATH") else DEFAULT_FILE_PATH

# ============================
# Styling - Enhanced Dark Mode CSS with Bell & Fonts
# ============================
st.set_page_config(page_title="HR System (Dark)", page_icon="👥", layout="wide")

enhanced_dark_css = """
<style>
/* Fonts */
body, h1, h2, h3, h4, h5, p, div, span, li {
    font-family: 'Segoe UI', 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
}
/* App background */
[data-testid="stAppViewContainer"] {
    background-color: #0f1724;
    color: #e6eef8;
}
/* Header & Toolbar */
[data-testid="stHeader"], [data-testid="stToolbar"] {
    background-color: #0b1220;
}
/* Sidebar */
[data-testid="stSidebar"] {
    background-color: #071226;
}
/* Inputs */
.stTextInput>div>div>input,
.stNumberInput>div>input,
.stSelectbox>div>div>div {
    background-color: #071226;
    color: #e6eef8;
    border: 1px solid #1e293b;
}
/* Buttons */
.stButton>button {
    background-color: #0b72b9;
    color: white;
    border-radius: 8px;
    padding: 8px 16px;
    border: none;
    transition: all 0.2s ease;
}
.stButton>button:hover {
    background-color: #0a5aa0;
    transform: translateY(-1px);
    box-shadow: 0 4px 8px rgba(0,0,0,0.2);
}
/* Dataframes */
.stDataFrame > div > div {
    background-color: #111827 !important;
    border-radius: 8px;
}
.stDataFrame table {
    color: #e6eef8 !important;
}
.stDataFrame tr:nth-child(even) {
    background-color: #182133 !important;
}
.stDataFrame tr:hover {
    background-color: #1e293b !important;
}
/* Notification Bell */
.notification-bell {
    position: fixed;
    top: 16px;
    right: 20px;
    background: #0b72b9;
    color: white;
    border-radius: 50%;
    width: 32px;
    height: 32px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: bold;
    cursor: pointer;
    box-shadow: 0 2px 6px rgba(0,0,0,0.3);
    z-index: 1000;
}
.notification-bell:hover {
    background: #0a5aa0;
    transform: scale(1.1);
}
.notification-badge {
    position: absolute;
    top: -2px;
    right: -2px;
    background: #ff6b6b;
    color: white;
    border-radius: 50%;
    width: 20px;
    height: 20px;
    font-size: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: bold;
}
</style>
"""
st.markdown(enhanced_dark_css, unsafe_allow_html=True)

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

# ============================
# Notifications System
# ============================
def load_notifications():
    if os.path.exists(NOTIFICATIONS_FILE_PATH):
        try:
            df = pd.read_excel(NOTIFICATIONS_FILE_PATH)
            if "Timestamp" in df.columns:
                df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
            return df
        except Exception:
            return pd.DataFrame()
    else:
        return pd.DataFrame(columns=[
            "Recipient Code", "Recipient Title", "Message", "Timestamp", "Is Read"
        ])

def save_notifications(df):
    try:
        with pd.ExcelWriter(NOTIFICATIONS_FILE_PATH, engine="openpyxl") as writer:
            df.to_excel(writer, index=False)
        return True
    except Exception:
        return False

def add_notification(recipient_code, recipient_title, message):
    notifications = load_notifications()
    new_row = pd.DataFrame([{
        "Recipient Code": str(recipient_code),
        "Recipient Title": str(recipient_title),
        "Message": message,
        "Timestamp": pd.Timestamp.now(),
        "Is Read": False
    }])
    notifications = pd.concat([notifications, new_row], ignore_index=True)
    save_notifications(notifications)

def get_unread_count(user):
    notifications = load_notifications()
    if notifications.empty:
        return 0
    user_code = None
    user_title = None
    for key, val in user.items():
        if key == "Employee Code":
            user_code = str(val).strip().replace(".0", "")
        if key == "Title":
            user_title = str(val).strip().upper()
    if not user_code and not user_title:
        return 0
    mask = (
        (notifications["Recipient Code"].astype(str) == user_code) |
        (notifications["Recipient Title"].astype(str).str.upper() == user_title)
    )
    unread = notifications[mask & (~notifications["Is Read"])]
    return len(unread)

def mark_all_as_read(user):
    notifications = load_notifications()
    if notifications.empty:
        return
    user_code = None
    user_title = None
    for key, val in user.items():
        if key == "Employee Code":
            user_code = str(val).strip().replace(".0", "")
        if key == "Title":
            user_title = str(val).strip().upper()
    mask = (
        (notifications["Recipient Code"].astype(str) == user_code) |
        (notifications["Recipient Title"].astype(str).str.upper() == user_title)
    )
    notifications.loc[mask, "Is Read"] = True
    save_notifications(notifications)

def page_notifications(user):
    st.subheader("🔔 Notifications")
    notifications = load_notifications()
    if notifications.empty:
        st.info("No notifications.")
        return

    user_code = None
    user_title = None
    for key, val in user.items():
        if key == "Employee Code":
            user_code = str(val).strip().replace(".0", "")
        if key == "Title":
            user_title = str(val).strip().upper()

    # Filter notifications for this user
    user_notifs = notifications[
        (notifications["Recipient Code"].astype(str) == user_code) |
        (notifications["Recipient Title"].astype(str).str.upper() == user_title)
    ].copy()

    if user_notifs.empty:
        st.info("No notifications for you.")
        return

    # Sort by timestamp (newest first)
    user_notifs = user_notifs.sort_values("Timestamp", ascending=False).reset_index(drop=True)

    col1, col2 = st.columns([4,1])
    with col2:
        if st.button("Mark all as read"):
            mark_all_as_read(user)
            st.success("All notifications marked as read.")
            st.rerun()

    for idx, row in user_notifs.iterrows():
        status = "✅" if row["Is Read"] else "🆕"
        time_str = row["Timestamp"].strftime("%d-%m-%Y %H:%M") if pd.notna(row["Timestamp"]) else "N/A"
        icon = "✅" if "approved" in row["Message"].lower() else "❌" if "rejected" in row["Message"].lower() else "📝"
        st.markdown(f"{icon} **{status} {row['Message']}**")
        st.caption(f"• {time_str}")
        st.markdown("---")

# ============================
# HR Queries (Ask HR) - Excel storage
# ============================
def load_hr_queries():
    if os.path.exists(HR_QUERIES_FILE_PATH):
        try:
            df = pd.read_excel(HR_QUERIES_FILE_PATH)
            return df
        except Exception:
            return pd.DataFrame()
    else:
        # create empty dataframe with required columns
        df = pd.DataFrame(columns=[
            "ID", "Employee Code", "Employee Name", "Subject", "Message",
            "Reply", "Status", "Date Sent", "Date Replied"
        ])
        try:
            with pd.ExcelWriter(HR_QUERIES_FILE_PATH, engine="openpyxl") as writer:
                df.to_excel(writer, index=False)
        except Exception:
            pass
        return df

def save_hr_queries(df):
    try:
        # ensure ID exists and is integer incremental (if new entries added without ID)
        if "ID" in df.columns:
            df = df.copy()
            df["ID"] = pd.to_numeric(df["ID"], errors="coerce")
            # fill missing IDs
            if df["ID"].isna().any():
                existing_max = int(df["ID"].max(skipna=True)) if not df["ID"].isna().all() else 0
                for idx in df[df["ID"].isna()].index:
                    existing_max += 1
                    df.at[idx, "ID"] = existing_max
            df["ID"] = df["ID"].astype(int)
        with pd.ExcelWriter(HR_QUERIES_FILE_PATH, engine="openpyxl") as writer:
            df.to_excel(writer, index=False)
        return True
    except Exception:
        return False

# ============================
# Team Hierarchy
# ============================
def build_team_hierarchy(df, manager_code, manager_title="AM"):
    emp_code_col = "Employee Code"
    emp_name_col = "Employee Name"
    mgr_code_col = "Manager Code"
    title_col = "Title"
    addr_col = "Address as 702 bricks"
    required_cols = [emp_code_col, emp_name_col, mgr_code_col, title_col]
    if not all(col in df.columns for col in required_cols):
        missing = [col for col in required_cols if col not in df.columns]
        st.warning(f"Missing required columns: {missing}")
        return {}
    df = df.copy()
    df[emp_code_col] = df[emp_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
    df[mgr_code_col] = df[mgr_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
    df[title_col] = df[title_col].astype(str).str.strip().str.upper()
    hierarchy = {"Manager": None, "Team": []}
    mgr_row = df[df[emp_code_col] == str(manager_code)]
    if not mgr_row.empty:
        mgr_name = mgr_row.iloc[0][emp_name_col]
        hierarchy["Manager"] = f"{mgr_name} ({manager_title})"
    if manager_title == "AM":
        dms = df[(df[mgr_code_col] == str(manager_code)) & (df[title_col] == "DM")]
        for _, dm_row in dms.iterrows():
            dm_code = dm_row[emp_code_col]
            dm_name = dm_row[emp_name_col]
            dm_addr = dm_row.get(addr_col, "") if addr_col in df.columns else ""
            mrs = df[(df[mgr_code_col] == dm_code) & (df[title_col] == "MR")]
            mr_list = []
            for _, mr_row in mrs.iterrows():
                mr_list.append({
                    "Code": mr_row[emp_code_col],
                    "Name": mr_row[emp_name_col],
                    "Address": mr_row.get(addr_col, "") if addr_col in df.columns else ""
                })
            hierarchy["Team"].append({
                "Type": "DM",
                "Code": dm_code,
                "Name": dm_name,
                "Address": dm_addr,
                "Subordinates": mr_list
            })
    elif manager_title == "DM":
        mrs = df[(df[mgr_code_col] == str(manager_code)) & (df[title_col] == "MR")]
        for _, mr_row in mrs.iterrows():
            hierarchy["Team"].append({
                "Type": "MR",
                "Code": mr_row[emp_code_col],
                "Name": mr_row[emp_name_col],
                "Address": mr_row.get(addr_col, "") if addr_col in df.columns else ""
            })
    return hierarchy

def page_my_team(user, role="AM"):
    st.subheader("My Team")
    user_code = None
    for key, val in user.items():
        if key == "Employee Code":
            user_code = str(val).strip().replace(".0", "")
            break
    if not user_code:
        st.error("Your Employee Code not found.")
        return
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
# UI Components / Pages
# ============================
def render_logo_and_title():
    cols = st.columns([1,6,1])
    with cols[1]:
        if os.path.exists(LOGO_PATH):
            st.image(LOGO_PATH, width=160)
        st.markdown("<h1 style='color:#e6eef8'>HR System — Dark Mode</h1>", unsafe_allow_html=True)
        st.markdown("<p style='color:#aab8c9'>English interface only</p>", unsafe_allow_html=True)
    # Add notification bell
    user = st.session_state.get("logged_in_user")
    if user:
        unread = get_unread_count(user)
        if unread > 0:
            st.markdown(f'<div class="notification-bell">{unread}<div class="notification-badge">{unread}</div></div>', unsafe_allow_html=True)

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
                add_notification(manager_code, "", f"New leave request from {user_code}")
                st.balloons()
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

# ============================
# <<-- REPLACED FUNCTION: page_manager_leaves -->> 
# This is the updated, indentation-safe, name-display version requested.
def page_manager_leaves(user):
    st.subheader("Leave Requests from Your Team")

    # --- Get Manager Code ---
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

    # --- Load Leave Data ---
    leaves_df = load_leaves_data()
    if leaves_df is None or leaves_df.empty:
        st.info("No leave requests found.")
        return

    # --- Ensure columns exist and clean codes ---
    if "Manager Code" not in leaves_df.columns or "Employee Code" not in leaves_df.columns:
        st.error("Leaves dataset missing required columns ('Manager Code' or 'Employee Code').")
        return
    leaves_df["Manager Code"] = leaves_df["Manager Code"].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
    leaves_df["Employee Code"] = leaves_df["Employee Code"].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
    if "Status" not in leaves_df.columns:
        leaves_df["Status"] = "Pending"
    leaves_df["Status"] = leaves_df["Status"].astype(str).str.strip()

    # --- Filter only PENDING requests for this manager ---
    pending_leaves = leaves_df[
        (leaves_df["Manager Code"] == manager_code) &
        (leaves_df["Status"].str.lower() == "pending")
    ].copy()

    # keep original index reference so updates map to leaves_df correctly
    pending_leaves["_orig_index"] = pending_leaves.index

    # --- Merge employee names from employee sheet (if available) ---
    df_emp = st.session_state.get("df", pd.DataFrame())
    emp_code_col = None
    emp_name_col = None
    if not df_emp.empty:
        col_map = {c.lower().strip(): c for c in df_emp.columns}
        emp_code_col = col_map.get("employee_code") or col_map.get("employee code")
        emp_name_col = col_map.get("employee_name") or col_map.get("employee name") or col_map.get("name")
        if emp_code_col and emp_name_col:
            df_emp[emp_code_col] = df_emp[emp_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
            pending_leaves = pending_leaves.merge(
                df_emp[[emp_code_col, emp_name_col]],
                left_on="Employee Code",
                right_on=emp_code_col,
                how="left"
            )

    # --- Display Pending Requests ---
    if pending_leaves.empty:
        st.info("No pending requests from your team.")

    st.markdown("### 🟡 Pending Requests")

    for i, row in pending_leaves.iterrows():
        orig_idx = row.get("_orig_index", None)
        emp_name = ""
        if emp_name_col and emp_name_col in row:
            emp_name = row.get(emp_name_col) or ""
        emp_display = emp_name if emp_name else row.get("Employee Code", "")

        try:
            start_display = pd.to_datetime(row.get("Start Date")).strftime("%d-%m-%Y")
        except Exception:
            start_display = str(row.get("Start Date", ""))
        try:
            end_display = pd.to_datetime(row.get("End Date")).strftime("%d-%m-%Y")
        except Exception:
            end_display = str(row.get("End Date", ""))

        st.markdown(
            f"**Employee**: {emp_display} | "
            f"**Dates**: {start_display} → {end_display} | "
            f"**Type**: {row.get('Leave Type','')}"
        )
        st.write(f"**Reason**: {row.get('Reason','')}")

        col1, col2 = st.columns(2)
        with col1:
            if st.button("✅ Approve", key=f"app_{manager_code}_{orig_idx}"):
                if orig_idx is not None and int(orig_idx) in leaves_df.index:
                    leaves_df.at[int(orig_idx), "Status"] = "Approved"
                    leaves_df.at[int(orig_idx), "Decision Date"] = pd.Timestamp.now()
                    save_leaves_data(leaves_df)
                    add_notification(row.get("Employee Code", ""), "", "Your leave request has been approved!")
                    st.success("Approved successfully!")
                    st.rerun()
                else:
                    st.error("Unable to locate the leave record to approve.")

        with col2:
            if st.button("❌ Reject", key=f"rej_{manager_code}_{orig_idx}"):
                comment_key = f"com_{manager_code}_{orig_idx}"
                comment = st.text_input("Comment (optional)", key=comment_key)
                if st.button("Confirm Reject", key=f"confirm_rej_{manager_code}_{orig_idx}"):
                    if orig_idx is not None and int(orig_idx) in leaves_df.index:
                        leaves_df.at[int(orig_idx), "Status"] = "Rejected"
                        leaves_df.at[int(orig_idx), "Decision Date"] = pd.Timestamp.now()
                        leaves_df.at[int(orig_idx), "Comment"] = comment
                        save_leaves_data(leaves_df)
                        msg = f"Your leave request was rejected. Comment: {comment}" if comment else "Your leave request was rejected."
                        add_notification(row.get("Employee Code", ""), "", msg)
                        st.success("Rejected.")
                        st.rerun()
                    else:
                        st.error("Unable to locate the leave record to reject.")

        st.markdown("---")

    # --- Show Team Leave History (Approved/Rejected) ---
    st.markdown("### 📋 Team Leave History")
    all_leaves = leaves_df[leaves_df["Manager Code"] == manager_code].copy()

    if all_leaves.empty:
        st.info("No leave history for your team.")
        return

    if not df_emp.empty and emp_code_col and emp_name_col and emp_code_col in df_emp.columns:
        df_emp[emp_code_col] = df_emp[emp_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
        all_leaves = all_leaves.merge(
            df_emp[[emp_code_col, emp_name_col]],
            left_on="Employee Code",
            right_on=emp_code_col,
            how="left"
        )
        all_leaves["Employee Name"] = all_leaves[emp_name_col].fillna(all_leaves["Employee Code"])
    else:
        all_leaves["Employee Name"] = all_leaves["Employee Code"]

    all_leaves["Start Date"] = pd.to_datetime(all_leaves["Start Date"], errors="coerce").dt.strftime("%d-%m-%Y")
    all_leaves["End Date"] = pd.to_datetime(all_leaves["End Date"], errors="coerce").dt.strftime("%d-%m-%Y")
    # Filter by status
    status_filter = st.selectbox("Filter by Status", ["All", "Approved", "Rejected", "Pending"])
    if status_filter != "All":
        all_leaves = all_leaves[all_leaves["Status"] == status_filter]

    st.dataframe(all_leaves[[
        "Employee Name", "Start Date", "End Date", "Leave Type", "Status", "Comment"
    ]], use_container_width=True)

    if "Decision Date" in all_leaves.columns:
        try:
            all_leaves["Decision Date_tmp"] = pd.to_datetime(all_leaves["Decision Date"], errors="coerce")
            all_leaves = all_leaves.sort_values("Decision Date_tmp", ascending=False).drop(columns=["Decision Date_tmp"])
        except Exception:
            pass

# ============================
# New: Ask HR (Employee) & HR Inbox (HR)
# ============================
def page_ask_hr(user):
    st.subheader("📩 Ask HR")
    st.markdown("Send a question or request to HR. HR will reply and you'll see the reply here.")

    # identify employee code and name
    emp_code = None
    emp_name = ""
    for k, v in user.items():
        if k.lower().replace(" ", "").replace("_", "") in ["employeecode", "employee_code"]:
            emp_code = str(v).strip()
            if emp_code.endswith('.0'):
                emp_code = emp_code[:-2]
        if k.lower().replace(" ", "").replace("_", "") in ["employeename", "employee_name", "name"]:
            emp_name = str(v).strip()
    if emp_code is None:
        st.error("Your Employee Code not found.")
        return

    hr_df = load_hr_queries()

    # Show form to submit question
    with st.form("ask_hr_form"):
        subject = st.text_input("Subject")
        message = st.text_area("Message")
        submitted = st.form_submit_button("Send Message")
    if submitted:
        if not subject.strip() or not message.strip():
            st.warning("Please provide both subject and message.")
        else:
            new_row = {
                "ID": None,
                "Employee Code": emp_code,
                "Employee Name": emp_name,
                "Subject": subject.strip(),
                "Message": message.strip(),
                "Reply": "",
                "Status": "Pending",
                "Date Sent": pd.Timestamp.now(),
                "Date Replied": ""
            }
            hr_df = pd.concat([hr_df, pd.DataFrame([new_row])], ignore_index=True)
            saved = save_hr_queries(hr_df)
            if saved:
                st.success("Your message has been sent to HR.")
                # Notify HR role (use recipient title "HR")
                add_notification("", "HR", f"New Ask HR message from {emp_code}")
            else:
                st.error("Failed to save your message. Try again.")

    st.markdown("---")
    st.markdown("### Your Messages")
    # filter to this employee
    if not hr_df.empty:
        my_msgs = hr_df[hr_df["Employee Code"].astype(str) == emp_code].copy()
        if my_msgs.empty:
            st.info("You have not sent any messages yet.")
            return
        # order newest first
        try:
            my_msgs["Date Sent_dt"] = pd.to_datetime(my_msgs["Date Sent"], errors="coerce")
            my_msgs = my_msgs.sort_values("Date Sent_dt", ascending=False)
        except Exception:
            pass
        for idx, row in my_msgs.iterrows():
            status = row.get("Status", "")
            date_sent = row.get("Date Sent", "")
            st.markdown(f"**Subject:** {row.get('Subject','')}")
            st.caption(f"Sent: {pd.to_datetime(date_sent).strftime('%d-%m-%Y %H:%M') if pd.notna(pd.to_datetime(date_sent, errors='coerce')) else date_sent} — Status: {status}")
            st.write(row.get("Message",""))
            reply = row.get("Reply", "")
            if reply and str(reply).strip():
                st.markdown("**HR Reply:**")
                st.info(reply)
            st.markdown("---")
    else:
        st.info("No messages found.")

def page_hr_inbox(user):
    # only HR users should access this; caller must ensure user is HR
    st.subheader("📬 HR Inbox")
    st.markdown("View employee queries and reply to them here.")

    hr_df = load_hr_queries()
    if hr_df is None or hr_df.empty:
        st.info("No Ask HR messages.")
        return

    # show newest first
    try:
        hr_df["Date Sent_dt"] = pd.to_datetime(hr_df["Date Sent"], errors="coerce")
        hr_df = hr_df.sort_values("Date Sent_dt", ascending=False)
    except Exception:
        pass
    for idx, row in hr_df.iterrows():
        emp_code = str(row['Employee Code'])
        emp_name = row.get('Employee Name', '')
        subj = row['Subject']
        msg = row.get("Message", "")
        status = row['Status']
        date_sent = row.get("Date Sent", "")
        reply_existing = row.get("Reply", "")

    # تحديد اللون بناءً على الحالة
        if status == "Pending":
            status_color = "🟡 Pending"
        elif status == "Replied":
            status_color = "🟢 Replied"
        elif status == "Closed":
            status_color = "⚫ Closed"
        else:
            status_color = f"🔘 {status}"

    # عرض العنوان بشكل منسق وواضح (كل سطر منفصل)
        exp_title = (
            f"📩 **Subject:** {subj}  \n"
            f"🧑‍💼 **Employee:** {emp_name} ({emp_code})  \n"
            f"📊 **Status:** {status_color}"
    )

    with st.expander(exp_title):
        st.markdown(f"**From:** {emp_name} — {emp_code}")
        st.caption(
            f"Sent: {pd.to_datetime(date_sent).strftime('%d-%m-%Y %H:%M') if pd.notna(pd.to_datetime(date_sent, errors='coerce')) else date_sent}"
        )
        st.write(msg)
        st.markdown("---")
        st.markdown("### Reply")

        reply = st.text_area(
            "Reply",
            value=reply_existing if not pd.isna(reply_existing) else "",
            key=f"reply_{idx}"
        )

        col1, col2 = st.columns([1, 1])

        with col1:
            if st.button("Send Reply", key=f"send_reply_{idx}"):
                try:
                    hr_df.at[idx, "Reply"] = reply
                    hr_df.at[idx, "Status"] = "Replied"
                    hr_df.at[idx, "Date Replied"] = pd.Timestamp.now()
                    save_hr_queries(hr_df)
                    add_notification(emp_code, "", f"HR replied to your message: {subj}")
                    st.success("Reply sent and employee notified.")
                    st.experimental_rerun()
                except Exception as e:
                    st.error(f"Failed to send reply: {e}")

        with col2:
            if st.button("Mark as Closed", key=f"close_{idx}"):
                try:
                    hr_df.at[idx, "Status"] = "Closed"
                    hr_df.at[idx, "Date Replied"] = pd.Timestamp.now()
                    save_hr_queries(hr_df)
                    st.success("Marked as Closed.")
                    st.experimental_rerun()
                except Exception as e:
                    st.error(f"Failed to close message: {e}")


# ============================
# Remaining pages: Dashboard / HR Manager / Reports etc.
# (Keep original implementations — trimmed here for brevity if needed)
# ============================
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
    title_val = str(user.get("Title") or user.get("title") or "").strip().upper()
    is_hr = "HR" in title_val
    is_am = title_val == "AM"
    is_dm = title_val == "DM"

    st.sidebar.write(f"👋 Welcome, {user.get('Employee Name') or user.get('employee name') or user.get('name','')}")
    st.sidebar.markdown("---")

    pages = ["My Profile", "Notifications"]
    if is_hr:
        pages = ["Dashboard", "Reports", "HR Manager", "HR Inbox", "Notifications", "Logout"]
    elif is_am:
        pages = ["My Profile", "Team Structure", "Team Leaves", "Leave Request", "Ask HR", "Notifications", "Logout"]
    elif is_dm:
        pages = ["My Profile", "My Team", "Team Leaves", "Leave Request", "Ask HR", "Notifications", "Logout"]
    else:
        pages = ["My Profile", "Leave Request", "Ask HR", "Notifications", "Logout"]

    page = st.sidebar.radio("Pages", pages)

    if page == "My Profile":
        page_my_profile(user)
    elif page == "Notifications":
        page_notifications(user)
    elif page == "Leave Request":
        page_leave_request(user)
    elif page == "Team Leaves":
        page_manager_leaves(user)
    elif page == "Dashboard":
        page_dashboard(user)
    elif page == "Reports":
        page_reports(user)
    elif page == "HR Manager":
        page_hr_manager(user)
    elif page == "Team Structure":
        page_my_team(user, role="AM")
    elif page == "My Team":
        page_my_team(user, role="DM")
    elif page == "HR Inbox":
        # security: only HR role should access
        if not is_hr:
            st.error("Access denied. HR only.")
        else:
            page_hr_inbox(user)
    elif page == "Ask HR":
        page_ask_hr(user)
    elif page == "Logout":
        st.session_state["logged_in_user"] = None
        st.success("You have been logged out successfully.")
        st.stop()
