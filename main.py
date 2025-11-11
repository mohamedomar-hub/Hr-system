# hr_system_dark_mode_v3_final_with_responded_requests_and_hierarchical_structure.py
import streamlit as st
import pandas as pd
import requests
import base64
from io import BytesIO
import os
import datetime
import shutil
import zipfile
# ============================
# Configuration / Defaults
# ============================
DEFAULT_FILE_PATH = "Employees.xlsx"
LEAVES_FILE_PATH = "Leaves.xlsx"
NOTIFICATIONS_FILE_PATH = "Notifications.xlsx"
HR_QUERIES_FILE_PATH = "HR_Queries.xlsx"
HR_REQUESTS_FILE_PATH = "HR_Requests.xlsx"
LOGO_PATH = "logo.jpg"
GITHUB_TOKEN = st.secrets.get("GITHUB_TOKEN", None)
REPO_OWNER = st.secrets.get("REPO_OWNER", "mohamedomar-hub")
REPO_NAME = st.secrets.get("REPO_NAME", "hr-system")
BRANCH = st.secrets.get("BRANCH", "main")
FILE_PATH = st.secrets.get("FILE_PATH", DEFAULT_FILE_PATH) if st.secrets.get("FILE_PATH") else DEFAULT_FILE_PATH
# ============================
# Styling - Enhanced Dark Mode CSS with Bell, Fonts, and Sidebar Improvements
# ============================
st.set_page_config(page_title="HRAS — Averroes Admin", page_icon="👥", layout="wide")
# ✅ Add this CSS to hide Streamlit's default toolbar
hide_streamlit_style = """
<style>
/* Hide the Streamlit menu bar */
#MainMenu {visibility: hidden;}
/* Hide the Streamlit footer */
footer {visibility: hidden;}
/* ✅ Removed header hiding line to keep sidebar visible */
/* Optional: Hide the "Manage app" button in the bottom right */
div[data-testid="stDeployButton"] {
    display: none;
}
</style>
"""
st.markdown(hide_streamlit_style, unsafe_allow_html=True)
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
    background: linear-gradient(135deg, #071226 0%, #0a1a2f 100%);
    border-right: 2px solid #0b72b9;
}
.sidebar-title {
    font-size: 1.3rem;
    font-weight: 700;
    color: #ffd166;
    margin: 1.2rem 0 1rem;
    text-align: center;
    letter-spacing: 0.5px;
}
/* Inputs */
.stTextInput>div>div>input,
.stNumberInput>div>input,
.stSelectbox>div>div>div {
    background-color: #071226;
    color: #e6eef8;
    border: 1px solid #1e293b;
}
.stTextInput>div>div>input:focus,
.stNumberInput>div>input:focus {
    border-color: #0b72b9;
    box-shadow: 0 0 0 2px rgba(11, 114, 185, 0.2);
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
/* HR message card */
.hr-message-card {
    background-color: #0b1220;
    border: 1px solid #233240;
    padding: 14px;
    border-radius: 10px;
    margin-bottom: 12px;
    white-space: pre-wrap;
}
.hr-message-title {
    font-weight: 700;
    font-size: 16px;
    margin-bottom: 6px;
    color: #ffd166;
}
.hr-message-meta {
    font-size: 13px;
    color: #9fb0c8;
    margin-bottom: 8px;
}
.hr-message-body {
    color: #e6eef8;
    font-size: 14px;
    line-height: 1.4;
    margin-bottom: 8px;
}
/* Team Hierarchy Styling */
.team-node {
    background-color: #0b1220;
    border-left: 4px solid #0b72b9;
    padding: 12px;
    margin: 8px 0;
    border-radius: 6px;
}
.team-node-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-weight: 600;
    color: #ffd166;
    margin-bottom: 8px;
}
.team-node-summary {
    font-size: 0.9rem;
    color: #9fb0c8;
    margin-top: 4px;
}
.team-node-children {
    margin-left: 20px;
    margin-top: 8px;
}
.team-member {
    display: flex;
    align-items: center;
    padding: 6px 12px;
    background-color: #111827;
    border-radius: 4px;
    margin: 4px 0;
    font-size: 0.95rem;
}
.team-member-icon {
    margin-right: 8px;
    font-size: 1.1rem;
}
/* Leave Balance Cards */
.leave-balance-card {
    background-color: #0b1220;
    border: 1px solid #0b72b9;
    border-radius: 12px;
    padding: 16px;
    margin: 8px;
    text-align: center;
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
    transition: transform 0.2s ease;
}
.leave-balance-card:hover {
    transform: translateY(-5px);
    background-color: #0c1525;
}
.leave-balance-title {
    font-size: 14px;
    color: #9fb0c8;
    margin-bottom: 8px;
}
.leave-balance-value {
    font-size: 24px;
    font-weight: bold;
    color: #ffd166;
}
.leave-balance-value.used {
    color: #ff6b6b; /* Red for used days */
}
.leave-balance-value.remaining {
    color: #4ecdc4; /* Greenish for remaining days */
}
/* Team Structure Cards */
.team-structure-card {
    background-color: #0b1220;
    border: 1px solid #0b72b9;
    border-radius: 12px;
    padding: 16px;
    margin: 8px;
    text-align: center;
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
    transition: transform 0.2s ease;
}
.team-structure-card:hover {
    transform: translateY(-5px);
    background-color: #0c1525;
}
.team-structure-title {
    font-size: 14px;
    color: #9fb0c8;
    margin-bottom: 8px;
}
.team-structure-value {
    font-size: 24px;
    font-weight: bold;
    color: #ffd166;
}
.team-structure-value.am {
    color: #ffd166; /* Golden for AM */
}
.team-structure-value.dm {
    color: #64b5f6; /* Blue for DM */
}
.team-structure-value.mr {
    color: #81c784; /* Green for MR */
}
</style>
"""
st.markdown(enhanced_dark_css, unsafe_allow_html=True)
# ============================
# Photo Helper
# ============================
def save_employee_photo(employee_code, uploaded_file):
    os.makedirs("employee_photos", exist_ok=True)
    emp_code_clean = str(employee_code).strip().replace(".0", "")
    ext = uploaded_file.name.split(".")[-1].lower()
    if ext not in ["jpg", "jpeg", "png"]:
        raise ValueError("Only JPG/PNG files allowed.")
    filename = f"{emp_code_clean}.{ext}"
    filepath = os.path.join("employee_photos", filename)
    with open(filepath, "wb") as f:
        f.write(uploaded_file.getbuffer())
    return filename
# ============================
# GitHub helpers (unchanged)
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
        file_content_b64 = base64.b64decode(output.read()).decode("utf-8")
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
# Helpers (unchanged)
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
# Notifications System (unchanged)
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
    st.subheader("Notifications")
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
    if not user_code and not user_title:
        return 0
    user_notifs = notifications[
        (notifications["Recipient Code"].astype(str) == user_code) |
        (notifications["Recipient Title"].astype(str).str.upper() == user_title)
    ].copy()
    if user_notifs.empty:
        st.info("No notifications for you.")
        return
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
# HR Queries (Ask HR) — unchanged
# ============================
def load_hr_queries():
    if os.path.exists(HR_QUERIES_FILE_PATH):
        try:
            df = pd.read_excel(HR_QUERIES_FILE_PATH)
            return df
        except Exception:
            return pd.DataFrame()
    else:
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
        if "ID" in df.columns:
            df = df.copy()
            df["ID"] = pd.to_numeric(df["ID"], errors="coerce")
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
# HR Requests (Ask Employees) — NEW
# ============================
def load_hr_requests():
    if os.path.exists(HR_REQUESTS_FILE_PATH):
        try:
            df = pd.read_excel(HR_REQUESTS_FILE_PATH)
            if "Timestamp" in df.columns:
                df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
            return df
        except Exception:
            return pd.DataFrame()
    else:
        df = pd.DataFrame(columns=[
            "ID", "HR Code", "Employee Code", "Employee Name", "Request", "File Attached", "Status", "Response", "Response File", "Date Sent", "Date Responded"
        ])
        try:
            with pd.ExcelWriter(HR_REQUESTS_FILE_PATH, engine="openpyxl") as writer:
                df.to_excel(writer, index=False)
        except Exception:
            pass
        return df
def save_hr_requests(df):
    try:
        if "ID" in df.columns:
            df = df.copy()
            df["ID"] = pd.to_numeric(df["ID"], errors="coerce")
            if df["ID"].isna().any():
                existing_max = int(df["ID"].max(skipna=True)) if not df["ID"].isna().all() else 0
                for idx in df[df["ID"].isna()].index:
                    existing_max += 1
                    df.at[idx, "ID"] = existing_max
            df["ID"] = df["ID"].astype(int)
        with pd.ExcelWriter(HR_REQUESTS_FILE_PATH, engine="openpyxl") as writer:
            df.to_excel(writer, index=False)
        return True
    except Exception:
        return False
def save_request_file(uploaded_file, employee_code, request_id):
    os.makedirs("hr_request_files", exist_ok=True)
    ext = uploaded_file.name.split(".")[-1].lower()
    filename = f"req_{request_id}_emp_{employee_code}.{ext}"
    filepath = os.path.join("hr_request_files", filename)
    with open(filepath, "wb") as f:
        f.write(uploaded_file.getbuffer())
    return filename
def save_response_file(uploaded_file, employee_code, request_id):
    os.makedirs("hr_response_files", exist_ok=True)
    ext = uploaded_file.name.split(".")[-1].lower()
    filename = f"resp_{request_id}_emp_{employee_code}.{ext}"
    filepath = os.path.join("hr_response_files", filename)
    with open(filepath, "wb") as f:
        f.write(uploaded_file.getbuffer())
    return filename
def page_ask_employees(user):
    st.subheader("📤 Ask Employees")
    st.info("🔍 Type employee name or code to search. HR can send requests with file attachments.")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.error("Employee data not loaded.")
        return
    # ============================
    # ✅ Flexible Column Mapping for Employee Code and Name
    # ============================
    col_map = {c.lower().strip(): c for c in df.columns}
    # Try to find the Employee Code column
    code_col_options = ["employee_code", "employee code", "emp code", "code", "employeeid", "emp_id"]
    code_col = None
    for opt in code_col_options:
        if opt in col_map:
            code_col = col_map[opt]
            break
    if not code_col:
        st.error("Could not find any column for Employee Code. Please check your Excel sheet headers.")
        return
    # Try to find the Employee Name column
    name_col_options = ["employee_name", "employee name", "name", "emp name", "full name", "first name"]
    name_col = None
    for opt in name_col_options:
        if opt in col_map:
            name_col = col_map[opt]
            break
    if not name_col:
        st.error("Could not find any column for Employee Name. Please check your Excel sheet headers.")
        return
    # Ensure columns are strings and clean them
    df[code_col] = df[code_col].astype(str).str.strip()
    df[name_col] = df[name_col].astype(str).str.strip()
    # Create display options for the selectbox
    emp_options = df[[code_col, name_col]].copy()
    emp_options["Display"] = emp_options[name_col] + " (Code: " + emp_options[code_col] + ")"
    # ============================
    # ✅ Search Box with Note
    # ============================
    st.markdown("### 🔍 Search Employee by Name or Code")
    search_term = st.text_input("Type employee name or code to search...")
    if search_term:
        mask = (
            emp_options[name_col].str.contains(search_term, case=False, na=False) |
            emp_options[code_col].str.contains(search_term, case=False, na=False)
        )
        filtered_options = emp_options[mask].copy()
        if filtered_options.empty:
            st.warning("No employee found matching your search.")
            return
    else:
        filtered_options = emp_options.copy()
    if len(filtered_options) == 1:
        selected_row = filtered_options.iloc[0]
    elif len(filtered_options) > 1:
        selected_display = st.selectbox("Select Employee", filtered_options["Display"].tolist())
        selected_row = filtered_options[filtered_options["Display"] == selected_display].iloc[0]
    else:
        return
    selected_code = selected_row[code_col]
    selected_name = selected_row[name_col]
    st.success(f"✅ Selected: {selected_name} (Code: {selected_code})")
    request_text = st.text_area("Request Details", height=100)
    uploaded_file = st.file_uploader("Attach File (Optional)", type=["pdf", "docx", "xlsx", "jpg", "png"])
    if st.button("Send Request"):
        if not request_text.strip():
            st.warning("Please enter a request message.")
            return
        hr_code = str(user.get("Employee Code", "N/A")).strip().replace(".0", "")
        requests_df = load_hr_requests()
        new_id = int(requests_df["ID"].max()) + 1 if "ID" in requests_df.columns and not requests_df.empty else 1
        file_attached = ""
        if uploaded_file:
            file_attached = save_request_file(uploaded_file, selected_code, new_id)
        new_row = pd.DataFrame([{
            "ID": new_id,
            "HR Code": hr_code,
            "Employee Code": selected_code,
            "Employee Name": selected_name,
            "Request": request_text.strip(),
            "File Attached": file_attached,
            "Status": "Pending",
            "Response": "",
            "Response File": "",
            "Date Sent": pd.Timestamp.now(),
            "Date Responded": pd.NaT
        }])
        requests_df = pd.concat([requests_df, new_row], ignore_index=True)
        save_hr_requests(requests_df)
        add_notification(selected_code, "", f"HR has sent you a new request (ID: {new_id}). Check 'Request HR' page.")
        st.success(f"Request sent to {selected_name} (Code: {selected_code}) successfully.")
        st.rerun()
def page_request_hr(user):
    st.subheader("📥 Request HR")
    st.info("Here you can respond to requests sent by HR. You can upload files as response.")
    user_code = str(user.get("Employee Code", "N/A")).strip().replace(".0", "")
    requests_df = load_hr_requests()
    if requests_df.empty:
        st.info("No requests from HR.")
        return
    user_requests = requests_df[requests_df["Employee Code"].astype(str) == user_code].copy()
    if user_requests.empty:
        st.info("No requests from HR for you.")
        return
    user_requests = user_requests.sort_values("Date Sent", ascending=False).reset_index(drop=True)
    for idx, row in user_requests.iterrows():
        st.markdown(f"### 📄 Request ID: {row['ID']}")
        st.write(f"**From HR:** {row['Request']}")
        if pd.notna(row["Date Sent"]) and row["Date Sent"] != pd.NaT:
            st.write(f"**Date Sent:** {row['Date Sent'].strftime('%d-%m-%Y %H:%M')}")
        # ✅ Safe handling of File Attached
        file_attached = row.get("File Attached", "")  # Get the value or default to empty string
        if pd.notna(file_attached) and isinstance(file_attached, str) and file_attached.strip() != "":
            filepath = os.path.join("hr_request_files", file_attached)
            if os.path.exists(filepath):
                with open(filepath, "rb") as f:
                    st.download_button("📥 Download Attached File", f, file_name=file_attached, key=f"dl_req_{idx}")
            else:
                st.warning("The attached file does not exist on the server.")
        else:
            st.info("No file was attached to this request.")
        if row["Status"] == "Completed":
            st.success("✅ This request has been responded to.")
            # ✅ Safe handling of Response File
            response_file = row.get("Response File", "")  # Get the value or default to empty string
            if pd.notna(response_file) and isinstance(response_file, str) and response_file.strip() != "":
                resp_path = os.path.join("hr_response_files", response_file)
                if os.path.exists(resp_path):
                    with open(resp_path, "rb") as f:
                        st.download_button("📥 Download Your Response", f, file_name=response_file, key=f"dl_resp_{idx}")
                else:
                    st.warning("Your response file does not exist on the server.")
            continue
        st.markdown("---")
        response_text = st.text_area("Your Response", key=f"resp_text_{idx}")
        uploaded_resp_file = st.file_uploader("Attach Response File (Optional)", type=["pdf", "docx", "xlsx", "jpg", "png"], key=f"resp_file_{idx}")
        if st.button("Submit Response", key=f"submit_resp_{idx}"):
            if not response_text.strip() and not uploaded_resp_file:
                st.warning("Please provide a response or attach a file.")
                continue
            requests_df.loc[requests_df["ID"] == row["ID"], "Response"] = response_text.strip()
            requests_df.loc[requests_df["ID"] == row["ID"], "Status"] = "Completed"
            requests_df.loc[requests_df["ID"] == row["ID"], "Date Responded"] = pd.Timestamp.now()
            response_file_name = ""
            if uploaded_resp_file:
                # Save the uploaded file
                resp_filename = save_response_file(uploaded_resp_file, user_code, row["ID"])
                requests_df.loc[requests_df["ID"] == row["ID"], "Response File"] = resp_filename
                response_file_name = resp_filename
            save_hr_requests(requests_df)
            add_notification("", "HR", f"Employee {user_code} responded to request ID {row['ID']}.")
            st.success("Response submitted successfully.")
            st.rerun()
# ============================
# Team Hierarchy — NEW: Recursive Function (Updated for Summary)
# ============================
def build_team_hierarchy_recursive(df, manager_code, manager_title="AM"):
    """
    Recursively builds the team hierarchy starting from the given manager.
    Returns a dictionary representing the tree structure.
    This function now works for BUM, AM, and DM.
    """
    emp_code_col = "Employee Code"
    emp_name_col = "Employee Name"
    mgr_code_col = "Manager Code"
    title_col = "Title"
    addr_col = "Address as 702 bricks" # Assuming this column exists
    required_cols = [emp_code_col, emp_name_col, mgr_code_col, title_col]
    if not all(col in df.columns for col in required_cols):
        missing = [col for col in required_cols if col not in df.columns]
        st.warning(f"Missing required columns: {missing}")
        return {}
    df = df.copy()
    df[emp_code_col] = df[emp_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
    df[mgr_code_col] = df[mgr_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
    df[title_col] = df[title_col].astype(str).str.strip().str.upper()
    # Find the manager's own row to get their name and title
    mgr_row = df[df[emp_code_col] == str(manager_code)]
    if mgr_row.empty:
        st.warning(f"Manager with code {manager_code} not found in data.")
        return {}
    mgr_name = mgr_row.iloc[0][emp_name_col]
    current_title = mgr_row.iloc[0][title_col]
    # Determine the levels under this manager based on their title
    subordinates_filter = df[df[mgr_code_col] == str(manager_code)]
    # Define subordinate types based on current manager's title
    if current_title == "BUM":
        subordinate_types = ["AM", "DM"] # BUM can manage both AM and DM
    elif current_title == "AM":
        subordinate_types = ["DM"] # AM manages DM
    elif current_title == "DM":
        subordinate_types = ["MR"] # DM manages MR
    else:
        subordinate_types = [] # Others (like MR) have no subordinates
    # Filter subordinates based on determined types
    if subordinate_types:
        subordinates_filtered = subordinates_filter[subordinates_filter[title_col].isin(subordinate_types)]
    else:
        subordinates_filtered = pd.DataFrame(columns=df.columns) # Empty dataframe
    # Build the node for the current manager
    node = {
        "Manager": f"{mgr_name} ({current_title})",
        "Manager Code": str(manager_code),
        "Team": [],
        "Summary": {
            "AM": 0,
            "DM": 0,
            "MR": 0
        }
    }
    # Recursively build nodes for each subordinate
    for _, sub_row in subordinates_filtered.iterrows():
        sub_code = sub_row[emp_code_col]
        sub_title = sub_row[title_col]
        # Recursively call the function for the subordinate
        child_node = build_team_hierarchy_recursive(df, sub_code, sub_title)
        # Only add the child node if it has its own team or itself is a leaf (like MR)
        if child_node.get("Team") or sub_title == "MR": # MRs are always added as leaves
            node["Team"].append(child_node)
            # Update summary based on the child's title
            if sub_title == "AM":
                node["Summary"]["AM"] += 1
            elif sub_title == "DM":
                node["Summary"]["DM"] += 1
            elif sub_title == "MR":
                node["Summary"]["MR"] += 1
    return node
def page_my_team(user, role="AM"):
    st.subheader("My Team Structure")
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
    # Use the recursive function to build the hierarchy starting from the current user
    hierarchy = build_team_hierarchy_recursive(df, user_code, role.upper())
    if not hierarchy:
        st.info(f"Could not build team structure for your code: {user_code}. Check your manager assignment or title.")
        return
    # Add custom CSS for the team structure
    st.markdown("""
    <style>
    .team-node {
        background-color: #0b1220;
        border-left: 4px solid #0b72b9;
        padding: 12px;
        margin: 8px 0;
        border-radius: 6px;
    }
    .team-node-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        font-weight: 600;
        color: #ffd166;
        margin-bottom: 8px;
    }
    .team-node-summary {
        font-size: 0.9rem;
        color: #9fb0c8;
        margin-top: 4px;
    }
    .team-node-children {
        margin-left: 20px;
        margin-top: 8px;
    }
    .team-member {
        display: flex;
        align-items: center;
        padding: 6px 12px;
        background-color: #111827;
        border-radius: 4px;
        margin: 4px 0;
        font-size: 0.95rem;
    }
    .team-member-icon {
        margin-right: 8px;
        font-size: 1.1rem;
    }
    </style>
    """, unsafe_allow_html=True)

    # Determine user's title for card display
    user_title = role.upper()

    # Display Cards for BUM
    if user_title == "BUM":
        st.markdown("### Team Structure Summary")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown(f"""
            <div class="team-structure-card">
                <div class="team-structure-title">AM Count</div>
                <div class="team-structure-value am">{hierarchy['Summary']['AM']}</div>
            </div>
            """, unsafe_allow_html=True)
        with col2:
            st.markdown(f"""
            <div class="team-structure-card">
                <div class="team-structure-title">DM Count</div>
                <div class="team-structure-value dm">{hierarchy['Summary']['DM']}</div>
            </div>
            """, unsafe_allow_html=True)
        with col3:
            st.markdown(f"""
            <div class="team-structure-card">
                <div class="team-structure-title">MR Count</div>
                <div class="team-structure-value mr">{hierarchy['Summary']['MR']}</div>
            </div>
            """, unsafe_allow_html=True)

    # Display Cards for AM
    elif user_title == "AM":
        st.markdown("### Team Structure Summary")
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"""
            <div class="team-structure-card">
                <div class="team-structure-title">DM Count</div>
                <div class="team-structure-value dm">{hierarchy['Summary']['DM']}</div>
            </div>
            """, unsafe_allow_html=True)
        with col2:
            st.markdown(f"""
            <div class="team-structure-card">
                <div class="team-structure-title">MR Count</div>
                <div class="team-structure-value mr">{hierarchy['Summary']['MR']}</div>
            </div>
            """, unsafe_allow_html=True)

    # Function to recursively render the tree structure with summaries
    def render_tree(node, level=0):
        if not node: # Check if node is empty
            return
        # Get summary counts
        am_count = node["Summary"]["AM"]
        dm_count = node["Summary"]["DM"]
        mr_count = node["Summary"]["MR"]
        # Format summary string
        summary_parts = []
        if am_count > 0:
            summary_parts.append(f"🟢 {am_count} AM")
        if dm_count > 0:
            summary_parts.append(f"🔵 {dm_count} DM")
        if mr_count > 0:
            summary_parts.append(f"🟣 {mr_count} MR")
        summary_str = " | ".join(summary_parts) if summary_parts else "No direct reports"
        # Render the node header
        indent = "&nbsp;" * (level * 4) # 4 spaces per level
        manager_info = node.get("Manager", "Unknown")
        manager_code = node.get("Manager Code", "N/A")
        st.markdown(f"""
        <div class="team-node">
            <div class="team-node-header">
                {indent}<span>👤 <strong>{manager_info}</strong> (Code: {manager_code})</span>
                <span class="team-node-summary">{summary_str}</span>
            </div>
        """, unsafe_allow_html=True)
        # Display the team members
        if node.get("Team"):
            st.markdown('<div class="team-node-children">', unsafe_allow_html=True)
            for team_member in node.get("Team", []):
                render_tree(team_member, level + 1)
            st.markdown('</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

    # Render the main hierarchy starting from the user's node
    render_tree(hierarchy, 0)
    # If the user themselves is a leaf node (e.g., MR with no subordinates)
    # or if the hierarchy is just the root node itself with no team members
    if not hierarchy.get("Team"): # If the root node has no team members
        # Render the root node itself (the user)
        root_manager_info = hierarchy.get("Manager", "Unknown")
        root_manager_code = hierarchy.get("Manager Code", "N/A")
        st.markdown(f"👤 **{root_manager_info}** (Code: {root_manager_code})")
        st.info("No direct subordinates found under your supervision.")

# ============================
# Pages
# ============================
def render_logo_and_title():
    cols = st.columns([1,6,1])
    with cols[1]:
        st.markdown("""
        <div style="text-align: center; margin-bottom: 12px;">
            <h1 style="color: #ffd166; font-weight: 800; font-size: 2.4rem; text-shadow: 0 2px 6px rgba(0,0,0,0.4); letter-spacing: -0.5px;">
                HRAS
            </h1>
            <p style="color: #aab8c9; font-size: 1rem; margin-top: 6px;">
                Averroes Admin System — Dark Mode
            </p>
        </div>
        """, unsafe_allow_html=True)
    user = st.session_state.get("logged_in_user")
    if user:
        unread = get_unread_count(user)
        if unread > 0:
            st.markdown(f'<div class="notification-bell">{unread}<div class="notification-badge">{unread}</div></div>', unsafe_allow_html=True)

# ============================
# ✅ NEW: Employee Photos Page for HR
# ============================
def page_employee_photos(user):
    st.subheader("📸 Employee Photos (HR Only)")
    os.makedirs("employee_photos", exist_ok=True)
    photo_files = os.listdir("employee_photos")
    if not photo_files:
        st.info("No employee photos uploaded yet.")
        return
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.warning("Employee data not loaded.")
        return
    # Map Employee Code to Name
    code_to_name = {}
    col_map = {c.lower().strip(): c for c in df.columns}
    emp_code_col = col_map.get("employee_code") or col_map.get("employee code")
    emp_name_col = col_map.get("employee_name") or col_map.get("name") or col_map.get("employee name")
    if emp_code_col and emp_name_col:
        df[emp_code_col] = df[emp_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
        for _, row in df.iterrows():
            code = row[emp_code_col]
            name = row.get(emp_name_col, "N/A")
            code_to_name[code] = name
    # Display photos in grid
    cols_per_row = 4
    cols = st.columns(cols_per_row)
    for i, filename in enumerate(sorted(photo_files)):
        col = cols[i % cols_per_row]
        filepath = os.path.join("employee_photos", filename)
        emp_code = filename.rsplit(".", 1)[0]  # e.g., "1025.jpg" → "1025"
        emp_name = code_to_name.get(emp_code, "Unknown")
        with col:
            st.image(filepath, use_column_width=True)
            st.caption(f"{emp_code}<br>{emp_name}")
            with open(filepath, "rb") as f:
                st.download_button("📥 Download", f, file_name=filename, key=f"dl_{filename}")
    # ============================
    # ✅ Download All Button
    # ============================
    st.markdown("---")
    if st.button("📥 Download All Employee Photos (ZIP)"):
        zip_path = "employee_photos_all.zip"
        with zipfile.ZipFile(zip_path, 'w') as zipf:
            photo_dir = "employee_photos"
            if os.path.exists(photo_dir):
                for filename in os.listdir(photo_dir):
                    file_path = os.path.join(photo_dir, filename)
                    if os.path.isfile(file_path):
                        zipf.write(file_path, filename)
        with open(zip_path, "rb") as f:
            st.download_button(
                label="Download All Photos",
                data=f,
                file_name="employee_photos_all.zip",
                mime="application/zip"
            )
        st.success("✅ ZIP file created. Click the button to download.")

# ============================
# Modified: My Profile with Photo Upload
# ============================
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
    # === Photo Upload Section ===
    st.markdown("### 📸 Personal Photo")
    emp_code_clean = None
    for key, val in user.items():
        if key.lower().replace(" ", "").replace("_", "") in ["employeecode", "employee_code"]:
            emp_code_clean = str(val).strip().replace(".0", "")
            break
    if emp_code_clean:
        # Check if photo exists
        photo_path = None
        for ext in ["jpg", "jpeg", "png"]:
            p = os.path.join("employee_photos", f"{emp_code_clean}.{ext}")
            if os.path.exists(p):
                photo_path = p
                break
        if photo_path:
            st.image(photo_path, width=150, caption="Your current photo")
        else:
            st.info("No photo uploaded yet.")
        uploaded_file = st.file_uploader(
            "Upload your personal photo (JPG/PNG)",
            type=["jpg", "jpeg", "png"],
            key="photo_uploader"
        )
        if uploaded_file:
            if st.button("✅ Save Photo"):
                try:
                    filename = save_employee_photo(emp_code_clean, uploaded_file)
                    add_notification("", "HR", f"Employee {emp_code_clean} uploaded a new photo.")
                    st.success(f"Photo saved as: {filename}")
                    st.rerun()
                except Exception as e:
                    st.error(f"Failed to save photo: {e}")

# Rest of pages unchanged: leave_request, manager_leaves, dashboard, hr_manager, reports, hr_inbox, ask_hr

def calculate_leave_balance(user_code, leaves_df):
    """Calculates Annual Leave Balance, Used Days, and Remaining Days."""
    annual_balance = 21 # Default annual leave balance
    # Filter leaves for the specific user and approved status
    user_approved_leaves = leaves_df[
        (leaves_df["Employee Code"].astype(str) == str(user_code)) &
        (leaves_df["Status"] == "Approved")
    ].copy()
    if user_approved_leaves.empty:
        used_days = 0
    else:
        # Calculate the difference in days for each approved leave
        user_approved_leaves["Start Date"] = pd.to_datetime(user_approved_leaves["Start Date"])
        user_approved_leaves["End Date"] = pd.to_datetime(user_approved_leaves["End Date"])
        # ✅ MODIFICATION: Calculate Leave Days as (End Date - Start Date).dt.days only
        # This means a leave from 2023-01-10 to 2023-01-11 counts as 1 day (only 2023-01-10)
        user_approved_leaves["Leave Days"] = (user_approved_leaves["End Date"] - user_approved_leaves["Start Date"]).dt.days
        # Ensure no negative days are counted if dates are accidentally reversed
        user_approved_leaves["Leave Days"] = user_approved_leaves["Leave Days"].clip(lower=0)
        used_days = user_approved_leaves["Leave Days"].sum()
    remaining_days = annual_balance - used_days
    return annual_balance, used_days, remaining_days

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
    # Load leaves data
    leaves_df = load_leaves_data()
    # Calculate leave balance for the current user
    annual_balance, used_days, remaining_days = calculate_leave_balance(user_code, leaves_df)
    # Display Leave Balance Cards
    st.markdown("### Leave Balance Summary")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown(f"""
        <div class="leave-balance-card">
            <div class="leave-balance-title">Annual Leave Balance</div>
            <div class="leave-balance-value">{annual_balance} Days</div>
        </div>
        """, unsafe_allow_html=True)
    with col2:
        st.markdown(f"""
        <div class="leave-balance-card">
            <div class="leave-balance-title">Used Leave Balance</div>
            <div class="leave-balance-value used">{used_days} Days</div>
        </div>
        """, unsafe_allow_html=True)
    with col3:
        st.markdown(f"""
        <div class="leave-balance-card">
            <div class="leave-balance-title">Remaining Days</div>
            <div class="leave-balance-value remaining">{remaining_days} Days</div>
        </div>
        """, unsafe_allow_html=True)
    # Original leave request form
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

    # Load data
    leaves_df = load_leaves_data()
    df_emp = st.session_state.get("df", pd.DataFrame())

    if leaves_df.empty:
        st.info("No leave requests found.")
        return

    # Map Manager Code to Manager Name for display
    manager_code_to_name = {}
    if not df_emp.empty:
        col_map = {c.lower().strip(): c for c in df_emp.columns}
        emp_code_col = col_map.get("employee_code") or col_map.get("employee code")
        emp_name_col = col_map.get("employee_name") or col_map.get("employee name") or col_map.get("name")
        if emp_code_col and emp_name_col:
            df_emp[emp_code_col] = df_emp[emp_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
            for _, row in df_emp.iterrows():
                code = row[emp_code_col]
                name = row.get(emp_name_col, "N/A")
                manager_code_to_name[code] = name

    # Filter leaves for the current manager's team
    team_leaves = leaves_df[leaves_df["Manager Code"].astype(str) == manager_code].copy()
    if team_leaves.empty:
        st.info("No leave requests from your team.")
        return

    # Determine user's title
    user_title = str(user.get("Title", "")).strip().upper()
    is_bum = user_title == "BUM"

    # Merge with employee data to get employee names
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

    # Display pending requests (as before)
    st.markdown("### 🟡 Pending Requests")
    if not pending_leaves.empty:
        for idx, row in pending_leaves.iterrows():
            emp_name = row.get(name_col_to_use, "") if name_col_to_use in row else ""
            emp_display = f"{emp_name} ({row['Employee Code']})" if emp_name else row['Employee Code']
            st.markdown(f"**Employee**: {emp_display} | **Dates**: {row['Start Date'].strftime('%d-%m-%Y')} → {row['End Date'].strftime('%d-%m-%Y')} | **Type**: {row['Leave Type']}")
            st.write(f"**Reason**: {row['Reason']}")

            # Calculate and display balance for the specific employee in the pending list
            emp_code = str(row['Employee Code'])
            annual_balance, used_days, remaining_days = calculate_leave_balance(emp_code, leaves_df)
            col_bal1, col_bal2, col_bal3 = st.columns(3)
            with col_bal1:
                st.markdown(f"""
                <div class="leave-balance-card" style="padding: 8px; font-size: 12px;">
                    <div class="leave-balance-title">Annual Balance</div>
                    <div class="leave-balance-value">{annual_balance}</div>
                </div>
                """, unsafe_allow_html=True)
            with col_bal2:
                st.markdown(f"""
                <div class="leave-balance-card" style="padding: 8px; font-size: 12px;">
                    <div class="leave-balance-title">Used</div>
                    <div class="leave-balance-value used">{used_days}</div>
                </div>
                """, unsafe_allow_html=True)
            with col_bal3:
                st.markdown(f"""
                <div class="leave-balance-card" style="padding: 8px; font-size: 12px;">
                    <div class="leave-balance-title">Remaining</div>
                    <div class="leave-balance-value remaining">{remaining_days}</div>
                </div>
                """, unsafe_allow_html=True)

            col1, col2, col3 = st.columns([2, 2, 1])
            with col1:
                if st.button("✅ Approve", key=f"app_{idx}_{row['Employee Code']}"):
                    current_leaves = load_leaves_data()
                    mask = (
                        (current_leaves["Employee Code"].astype(str) == str(row['Employee Code'])) &
                        (current_leaves["Start Date"] == row['Start Date']) &
                        (current_leaves["Status"] == "Pending")
                    )
                    if mask.any():
                        current_leaves.loc[mask, "Status"] = "Approved"
                        current_leaves.loc[mask, "Decision Date"] = pd.Timestamp.now()
                        save_leaves_data(current_leaves)
                        # Add notification for employee
                        add_notification(row['Employee Code'], "", "Your leave request has been approved!")
                        # Send notification to HR about approval with manager details
                        mgr_name = manager_code_to_name.get(manager_code, manager_code)
                        emp_name_for_notif = row.get(name_col_to_use, row['Employee Code'])
                        add_notification("", "HR", f"Leave approved for {emp_name_for_notif} ({row['Employee Code']}) by {mgr_name} ({manager_code}).")
                        st.success("Approved!")
                        st.rerun()
                    else:
                        st.warning("Request not found or already processed.")
            with col2:
                if st.button("❌ Reject", key=f"rej_{idx}_{row['Employee Code']}"):
                    comment = st.text_input("Comment (optional)", key=f"com_{idx}_{row['Employee Code']}")
                    current_leaves = load_leaves_data()
                    mask = (
                        (current_leaves["Employee Code"].astype(str) == str(row['Employee Code'])) &
                        (current_leaves["Start Date"] == row['Start Date']) &
                        (current_leaves["Status"] == "Pending")
                    )
                    if mask.any():
                        current_leaves.loc[mask, "Status"] = "Rejected"
                        current_leaves.loc[mask, "Decision Date"] = pd.Timestamp.now()
                        current_leaves.loc[mask, "Comment"] = comment
                        save_leaves_data(current_leaves)
                        msg = f"Your leave request was rejected. Comment: {comment}" if comment else "Your leave request was rejected."
                        add_notification(row['Employee Code'], "", msg)
                        st.success("Rejected!")
                        st.rerun()
                    else:
                        st.warning("Request not found or already processed.")
            with col3:
                if st.button("🗑️", key=f"del_{idx}_{row['Employee Code']}"):
                    current_leaves = load_leaves_data()
                    mask = (
                        (current_leaves["Manager Code"].astype(str) == manager_code) &  # only his team
                        (current_leaves["Employee Code"].astype(str) == str(row['Employee Code'])) &
                        (current_leaves["Start Date"] == row['Start Date'])
                    )
                    if mask.any():
                        current_leaves = current_leaves[~mask].reset_index(drop=True)
                        save_leaves_data(current_leaves)
                        st.success("Request deleted!")
                        st.rerun()
                    else:
                        st.warning("Only your team's requests can be deleted.")
            st.markdown("---")
    else:
        st.info("No pending requests.")

    # Display All Team Leave History (as before)
    st.markdown("### 📋 All Team Leave History")
    if not all_leaves.empty:
        # Calculate balances for the entire team history
        all_leaves_with_balance = all_leaves.copy()
        all_leaves_with_balance["Annual Balance"] = 21 # Add default balance column
        all_leaves_with_balance["Used Days"] = 0
        all_leaves_with_balance["Remaining Days"] = 21
        unique_employees = all_leaves_with_balance["Employee Code"].unique()
        for emp_code in unique_employees:
            _, used, remaining = calculate_leave_balance(emp_code, leaves_df)
            mask = all_leaves_with_balance["Employee Code"] == emp_code
            all_leaves_with_balance.loc[mask, "Used Days"] = used
            all_leaves_with_balance.loc[mask, "Remaining Days"] = remaining

        if name_col_to_use in all_leaves_with_balance.columns:
            all_leaves_with_balance["Employee Name"] = all_leaves_with_balance[name_col_to_use]
        else:
            all_leaves_with_balance["Employee Name"] = all_leaves_with_balance["Employee Code"]

        all_leaves_with_balance["Start Date"] = pd.to_datetime(all_leaves_with_balance["Start Date"]).dt.strftime("%d-%m-%Y")
        all_leaves_with_balance["End Date"] = pd.to_datetime(all_leaves_with_balance["End Date"]).dt.strftime("%d-%m-%Y")

        # Add Manager Name column
        all_leaves_with_balance["Manager Name"] = all_leaves_with_balance["Manager Code"].map(manager_code_to_name).fillna(all_leaves_with_balance["Manager Code"])

        # Display the dataframe with the new balance and manager name columns
        st.dataframe(all_leaves_with_balance[[
            "Employee Name", "Employee Code", "Start Date", "End Date", "Leave Type", "Status", "Comment", "Manager Name", "Manager Code", "Annual Balance", "Used Days", "Remaining Days"
        ]], use_container_width=True)
    else:
        st.info("No leave history for your team.")

    # NEW SECTION: BUM - Detailed Leave Report for All Subordinates
    if is_bum:
        st.markdown("---")
        st.markdown("### 📊 Detailed Leave Report for All Subordinates")
        # Get all subordinates under BUM (AM, DM, MR) recursively
        df_full = st.session_state.get("df", pd.DataFrame())
        if not df_full.empty:
            col_map = {c.lower().strip(): c for c in df_full.columns}
            emp_code_col = col_map.get("employee_code") or col_map.get("employee code")
            mgr_code_col = col_map.get("manager_code") or col_map.get("manager code")
            title_col = col_map.get("title") or col_map.get("Title")
            emp_name_col = col_map.get("employee_name") or col_map.get("employee name") or col_map.get("name")

            if emp_code_col and mgr_code_col and title_col:
                df_full[emp_code_col] = df_full[emp_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
                df_full[mgr_code_col] = df_full[mgr_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
                df_full[title_col] = df_full[title_col].astype(str).str.strip().str.upper()

                # Recursive function to find all subordinates
                def get_all_subordinates_codes(start_manager_code):
                    subordinates = set()
                    stack = [start_manager_code]
                    while stack:
                        current_mgr = stack.pop()
                        # Find direct reports of current manager
                        direct_reports = df_full[df_full[mgr_code_col] == str(current_mgr)]
                        for _, rep_row in direct_reports.iterrows():
                            rep_code = rep_row[emp_code_col]
                            rep_title = rep_row[title_col]
                            subordinates.add(rep_code)
                            # If the direct report is also a manager, add them to stack to find their reports
                            if rep_title in ["AM", "DM", "BUM"]: # Avoid infinite loops by stopping at MR or non-managers if needed
                                stack.append(rep_code)
                    return list(subordinates)

                all_subordinate_codes = get_all_subordinates_codes(manager_code)
                if all_subordinate_codes:
                    # Filter leaves for all subordinates
                    detailed_report_df = leaves_df[leaves_df["Employee Code"].isin(all_subordinate_codes)].copy()
                    if not detailed_report_df.empty:
                        # Merge to get employee names and manager names
                        detailed_report_df = detailed_report_df.merge(
                            df_full[[emp_code_col, emp_name_col]].rename(columns={emp_name_col: "Employee Name"}),
                            left_on="Employee Code",
                            right_on=emp_code_col,
                            how="left"
                        )
                        detailed_report_df = detailed_report_df.merge(
                            df_full[[emp_code_col, emp_name_col]].rename(columns={emp_code_col: "Manager Code", emp_name_col: "Manager Name"}),
                            left_on="Manager Code",
                            right_on="Manager Code",
                            how="left"
                        )

                        # Format dates
                        detailed_report_df["Start Date"] = pd.to_datetime(detailed_report_df["Start Date"]).dt.strftime("%d-%m-%Y")
                        detailed_report_df["End Date"] = pd.to_datetime(detailed_report_df["End Date"]).dt.strftime("%d-%m-%Y")

                        # Calculate balances
                        detailed_report_df["Annual Balance"] = 21
                        detailed_report_df["Used Days"] = 0
                        detailed_report_df["Remaining Days"] = 21
                        for emp_code in detailed_report_df["Employee Code"].unique():
                            _, used, remaining = calculate_leave_balance(emp_code, leaves_df)
                            mask = detailed_report_df["Employee Code"] == emp_code
                            detailed_report_df.loc[mask, "Used Days"] = used
                            detailed_report_df.loc[mask, "Remaining Days"] = remaining

                        # Display the detailed report
                        st.dataframe(detailed_report_df[[
                            "Employee Name", "Employee Code", "Start Date", "End Date", "Leave Type", "Status", "Comment", "Manager Name", "Manager Code", "Annual Balance", "Used Days", "Remaining Days"
                        ]], use_container_width=True)
                    else:
                        st.info("No leave requests found for subordinates under your management.")
                else:
                    st.info("No subordinates found under your management.")
            else:
                st.warning("Required columns (Employee Code, Manager Code, Title) not found for detailed report.")

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
                    st.info("Saved locally. GitHub token not configured.")
        else:
            st.error("Failed to save dataset locally.")
    # ============================
    # ✅ CLEAR ALL TEST DATA BUTTON
    # ============================
    st.markdown("---")
    st.warning("🛠️ **Clear All Test Data** (Use BEFORE going live!)")
    if st.button("🗑️ Clear Leaves, HR Messages, Notifications & Photos"):
        try:
            test_files = [LEAVES_FILE_PATH, HR_QUERIES_FILE_PATH, NOTIFICATIONS_FILE_PATH, HR_REQUESTS_FILE_PATH]
            cleared = []
            for f in test_files:
                if os.path.exists(f):
                    os.remove(f)
                    cleared.append(f)
            if os.path.exists("employee_photos"):
                shutil.rmtree("employee_photos")
                cleared.append("employee_photos/")
            if os.path.exists("hr_request_files"):
                shutil.rmtree("hr_request_files")
                cleared.append("hr_request_files/")
            if os.path.exists("hr_response_files"):
                shutil.rmtree("hr_response_files")
                cleared.append("hr_response_files/")
            if cleared:
                st.success(f"✅ Cleared: {', '.join(cleared)}")
            else:
                st.info("Nothing to clear.")
            st.rerun()
        except Exception as e:
            st.error(f"❌ Failed to clear: {e}")

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

def page_hr_inbox(user):
    st.subheader("📬 HR Inbox")
    st.markdown("View employee queries and reply to them here.")
    hr_df = load_hr_queries()
    if hr_df is None or hr_df.empty:
        st.info("No Ask HR messages.")
        return
    try:
        hr_df["Date Sent_dt"] = pd.to_datetime(hr_df["Date Sent"], errors="coerce")
        hr_df = hr_df.sort_values("Date Sent_dt", ascending=False).reset_index(drop=True)
    except Exception:
        hr_df = hr_df.reset_index(drop=True)
    for idx, row in hr_df.iterrows():
        emp_code = str(row.get('Employee Code', ''))
        emp_name = row.get('Employee Name', '') if pd.notna(row.get('Employee Name', '')) else ''
        subj = row.get('Subject', '') if pd.notna(row.get('Subject', '')) else ''
        msg = row.get("Message", '') if pd.notna(row.get("Message", '')) else ''
        status = row.get('Status', '') if pd.notna(row.get('Status', '')) else ''
        date_sent = row.get("Date Sent", '')
        reply_existing = row.get("Reply", '') if pd.notna(row.get("Reply", '')) else ''
        try:
            sent_time = pd.to_datetime(date_sent).strftime('%d-%m-%Y %H:%M')
        except Exception:
            sent_time = str(date_sent)
        card_html = f"""
        <div class="hr-message-card">
            <div class="hr-message-title">📌 {subj if subj else 'No Subject'}</div>
            <div class="hr-message-meta">👤 {emp_name} — {emp_code} &nbsp;|&nbsp; 🕒 {sent_time} &nbsp;|&nbsp; 🏷️ {status}</div>
            <div class="hr-message-body">{msg if msg else ''}</div>
        """
        st.markdown(card_html, unsafe_allow_html=True)
        if reply_existing:
            st.markdown("**🟢 Existing reply:**")
            st.markdown(reply_existing)
            col1, col2 = st.columns([1, 4])
            with col1:
                if st.button("🗂️ Mark as Closed", key=f"close_{idx}"):
                    try:
                        hr_df.at[idx, "Status"] = "Closed"
                        hr_df.at[idx, "Date Replied"] = pd.Timestamp.now()
                        save_hr_queries(hr_df)
                        st.success("✅ Message marked as closed.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Failed to close message: {e}")
        else:
            reply_text = st.text_area("✍️ Write reply here:", value="", key=f"reply_{idx}", height=120)
            col1, col2, col3 = st.columns([2, 2, 1])
            with col1:
                if st.button("✅ Send Reply", key=f"send_reply_{idx}"):
                    try:
                        hr_df.at[idx, "Reply"] = reply_text
                        hr_df.at[idx, "Status"] = "Replied"
                        hr_df.at[idx, "Date Replied"] = pd.Timestamp.now()
                        save_hr_queries(hr_df)
                        add_notification(emp_code, "", f"HR replied to your message: {subj}")
                        st.success("✅ Reply sent and employee notified.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ Failed to send reply: {e}")
            with col2:
                if st.button("🗑️ Mark as Closed", key=f"close_{idx}"):
                    try:
                        hr_df.at[idx, "Status"] = "Closed"
                        hr_df.at[idx, "Date Replied"] = pd.Timestamp.now()
                        save_hr_queries(hr_df)
                        st.success("✅ Message marked as closed.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ Failed to close message: {e}")
            with col3:
                if st.button("🗑️ Delete", key=f"del_inbox_{idx}"):
                    hr_df = hr_df.drop(idx).reset_index(drop=True)
                    save_hr_queries(hr_df)
                    st.success("Message deleted!")
                    st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)
        st.markdown("---")

def page_ask_hr(user):
    st.subheader("💬 Ask HR")
    if user is None:
        st.error("User session not found. Please login.")
        return
    user_code = None
    user_name = None
    for key, val in user.items():
        if key.lower().replace(" ", "").replace("_", "") in ["employeecode", "employee_code"]:
            user_code = str(val).strip().replace(".0", "")
        if key.lower().replace(" ", "").replace("_", "") in ["employeename", "employee_name", "name"]:
            user_name = str(val).strip()
    if not user_code:
        st.error("Your Employee Code not found in session.")
        return
    if not user_name:
        user_name = user_code
    hr_df = load_hr_queries()
    with st.form("ask_hr_form"):
        subj = st.text_input("Subject")
        msg = st.text_area("Message", height=160)
        submitted = st.form_submit_button("Send to HR")
    if submitted:
        if not subj.strip() or not msg.strip():
            st.warning("Please fill both Subject and Message.")
        else:
            new_row = pd.DataFrame([{
                "Employee Code": user_code,
                "Employee Name": user_name,
                "Subject": subj.strip(),
                "Message": msg.strip(),
                "Reply": "",
                "Status": "Pending",
                "Date Sent": pd.Timestamp.now(),
                "Date Replied": pd.NaT
            }])
            if hr_df is None or hr_df.empty:
                hr_df = new_row
            else:
                hr_df = pd.concat([hr_df, new_row], ignore_index=True)
            if save_hr_queries(hr_df):
                st.success("✅ Your message was sent to HR.")
                add_notification("", "HR", f"New Ask HR from {user_name} ({user_code})")
                st.rerun()
            else:
                st.error("❌ Failed to save message. Check server permissions.")
    st.markdown("### 📜 Your previous messages")
    if hr_df is None or hr_df.empty:
        st.info("No messages found.")
        return
    try:
        hr_df["Date Sent_dt"] = pd.to_datetime(hr_df["Date Sent"], errors="coerce")
        my_msgs = hr_df[hr_df["Employee Code"].astype(str).str.strip() == str(user_code)].sort_values("Date Sent_dt", ascending=False)
    except Exception:
        my_msgs = hr_df[hr_df["Employee Code"].astype(str).str.strip() == str(user_code)]
    if my_msgs.empty:
        st.info("You have not sent any messages yet.")
        return
    for idx, row in my_msgs.iterrows():
        subj = row.get("Subject", "")
        msg = row.get("Message", "")
        reply = row.get("Reply", "")
        status = row.get("Status", "")
        date_sent = row.get("Date Sent", "")
        try:
            sent_time = pd.to_datetime(date_sent).strftime('%d-%m-%Y %H:%M')
        except Exception:
            sent_time = str(date_sent)
        st.markdown(f"<div class='hr-message-card'><div class='hr-message-title'>{subj}</div><div class='hr-message-meta'>Sent: {sent_time} — Status: {status}</div><div class='hr-message-body'>{msg}</div>", unsafe_allow_html=True)
        if pd.notna(reply) and str(reply).strip() != "":
            st.markdown("**🟢 HR Reply:**")
            st.markdown(reply)
        else:
            st.markdown("**🕒 HR Reply:** Pending")
        st.markdown("</div>")
        st.markdown("---")

# ============================
# Main App Flow
# ============================
ensure_session_df()
render_logo_and_title()
# Initialize session state
if "logged_in_user" not in st.session_state:
    st.session_state["logged_in_user"] = None
if "current_page" not in st.session_state:
    st.session_state["current_page"] = "My Profile"

# ============================
# Sidebar Navigation - Always Visible
# ============================
with st.sidebar:
    # 🎯 Always show the title/logo at the top of the sidebar
    if os.path.exists(LOGO_PATH):
        st.image(LOGO_PATH, use_container_width=True)
    else:
        st.markdown('<div class="sidebar-title">HRAS — Averroes Admin</div>', unsafe_allow_html=True)
    st.markdown("<hr style='border: 1px solid #0b72b9; margin: 10px 0;'>", unsafe_allow_html=True)
    # Show login form or menu based on session state
    if not st.session_state["logged_in_user"]:
        st.markdown("### 🔐 Login Required")
        with st.form("login_form"):
            uid = st.text_input("Employee Code")
            pwd = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Sign in")
        if submitted:
            df = st.session_state.get("df", pd.DataFrame())
            user = login(df, uid, pwd)
            if user is None:
                st.error("Invalid credentials or required columns missing.")
            else:
                st.session_state["logged_in_user"] = user
                st.session_state["current_page"] = "My Profile"
                st.success("Login successful!")
                st.rerun()
    else:
        user = st.session_state["logged_in_user"]
        title_val = str(user.get("Title") or user.get("title") or "").strip().upper()
        is_hr = "HR" in title_val
        is_bum = title_val == "BUM"
        is_am = title_val == "AM"
        is_dm = title_val == "DM"
        is_mr = title_val == "MR"
        st.write(f"👋 **Welcome, {user.get('Employee Name') or 'User'}**")
        st.markdown("---")
        # Determine pages based on user role
        if is_hr:
            pages = ["Dashboard", "Reports", "HR Manager", "HR Inbox", "Employee Photos", "Ask Employees", "Notifications"]
        elif is_bum:
            pages = ["My Profile", "Team Structure", "Team Leaves", "Leave Request", "Ask HR", "Request HR", "Notifications"]
        elif is_am:
            pages = ["My Profile", "Team Structure", "Team Leaves", "Leave Request", "Ask HR", "Request HR", "Notifications"]
        elif is_dm:
            pages = ["My Profile", "Team Structure", "Team Leaves", "Leave Request", "Ask HR", "Request HR", "Notifications"]
        elif is_mr:
            pages = ["My Profile", "Leave Request", "Ask HR", "Request HR", "Notifications"]
        else:
            pages = ["My Profile", "Leave Request", "Ask HR", "Request HR", "Notifications"]
        for p in pages:
            if st.button(p, key=f"nav_{p}", use_container_width=True):
                st.session_state["current_page"] = p
                st.rerun()
        # 👇 التعديل هنا: حذف المسافة البادئة الزائدة
        st.markdown("---")
        if st.button("🚪 Logout", use_container_width=True):
            st.session_state["logged_in_user"] = None
            st.session_state["current_page"] = "My Profile"
            st.success("You have been logged out.")
            st.rerun()

# Main Content
if st.session_state["logged_in_user"]:
    current_page = st.session_state["current_page"]
    user = st.session_state["logged_in_user"]
    title_val = str(user.get("Title") or "").strip().upper()
    is_hr = "HR" in title_val
    is_bum = title_val == "BUM"
    is_am = title_val == "AM"
    is_dm = title_val == "DM"
    is_mr = title_val == "MR" # Added for clarity
    if current_page == "My Profile":
        page_my_profile(user)
    elif current_page == "Notifications":
        page_notifications(user)
    elif current_page == "Leave Request":
        page_leave_request(user)
    elif current_page == "Team Leaves":
        # Now accessible by BUM, AM, DM, MR
        if is_bum or is_am or is_dm or is_mr:
            page_manager_leaves(user)
        else:
            st.error("Access denied. BUM, AM, DM, or MR only.")
    elif current_page == "Dashboard":
        page_dashboard(user)
    elif current_page == "Reports":
        page_reports(user)
    elif current_page == "HR Manager":
        page_hr_manager(user)
    elif current_page == "Team Structure":
        # Allow BUM, AM, DM to see this page
        if is_bum or is_am or is_dm:
            page_my_team(user, role=title_val)
        else:
            st.error("Access denied. BUM, AM, or DM only.")
    elif current_page == "My Team":
        # Keep old "My Team" for DM if needed, otherwise remove or redirect
        # For simplicity, we'll assume "Team Structure" covers this now for DM too
        if is_dm:
            page_my_team(user, role="DM")
        else:
            st.error("Access denied. DM only for legacy 'My Team'. Use 'Team Structure' instead.")
    elif current_page == "HR Inbox":
        if is_hr:
            page_hr_inbox(user)
        else:
            st.error("Access denied. HR only.")
    elif current_page == "Employee Photos":
        if is_hr:
            page_employee_photos(user)
        else:
            st.error("Access denied. HR only.")
    elif current_page == "Ask HR":
        page_ask_hr(user)
    elif current_page == "Ask Employees":
        if is_hr:
            page_ask_employees(user)
        else:
            st.error("Access denied. HR only.")
    elif current_page == "Request HR":
        page_request_hr(user)
else:
    st.info("Please log in to access the system.")
