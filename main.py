# hr_system_with_config_json.py — FULLY CONVERTED TO JSON (NO LINE DELETED)
import streamlit as st
import pandas as pd
import requests
import base64
from io import BytesIO
import os
import datetime
import shutil
import zipfile
import json
import bcrypt
from openpyxl import Workbook  # ✅ إضافة مكتبة openpyxl
# 🔐 NEW: For salary encryption
from cryptography.fernet import Fernet, InvalidToken
import hashlib

# ============================
# COMPLIANCE MESSAGES FILE PATH
# ============================
COMPLIANCE_MESSAGES_FILE = "compliance_messages.json"
# ============================
# IDB REPORTS FILE PATH
# ============================
IDB_REPORTS_FILE = "idb_reports.json"
# ============================
# SALARY ENCRYPTION SETUP (Secure: from Streamlit Secrets)
# ============================
SALARY_SECRET_KEY = st.secrets.get("SALARY_SECRET_KEY")
if not SALARY_SECRET_KEY:
    st.error("❌ Missing SALARY_SECRET_KEY in Streamlit Secrets.")
    st.stop()

def get_fernet_from_secret(secret: str) -> Fernet:
    key = hashlib.sha256(secret.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(key) [cite: 2]
    return Fernet(fernet_key)

fernet_salary = get_fernet_from_secret(SALARY_SECRET_KEY)

def encrypt_salary_value(value) -> str:
    try:
        if pd.isna(value):
            return ""
        num_str = str(float(value))
        encrypted = fernet_salary.encrypt(num_str.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    except Exception:
        return ""

def decrypt_salary_value(encrypted_str: str) -> float:
    try:
        if not encrypted_str or pd.isna(encrypted_str): [cite: 3]
            return 0.0
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_str.encode())
            decrypted = fernet_salary.decrypt(encrypted_bytes)
            return float(decrypted.decode())
        [cite_start]except Exception: [cite: 4]
            return float(encrypted_str)
    except (InvalidToken, ValueError, Exception):
        return 0.0

# ============================
# 🆕 FUNCTION: Load & Save Compliance Messages
# ============================
def load_compliance_messages():
    return load_json_file(COMPLIANCE_MESSAGES_FILE, default_columns=[
        "ID", "MR Code", "MR Name", "Compliance Recipient", "Compliance Code",
        "Manager Code", "Manager Name", "Message", "Timestamp", "Status"
    ])

def save_compliance_messages(df):
    df = df.copy()
    [cite_start]if "Timestamp" in df.columns: [cite: 5]
        df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce").astype(str)
    if "ID" in df.columns:
        df["ID"] = pd.to_numeric(df["ID"], errors="coerce")
        if df["ID"].isna().any():
            existing_max = int(df["ID"].max()) if not df["ID"].isna().all() else 0
            for idx in df[df["ID"].isna()].index:
                existing_max += 1
                [cite_start]df.at[idx, "ID"] = existing_max [cite: 6]
        df["ID"] = df["ID"].astype(int)
    return save_json_file(df, COMPLIANCE_MESSAGES_FILE)

# ============================
# 🆕 FUNCTION: Sanitize employee data (APPLY YOUR 3 RULES)
# ============================
def sanitize_employee_data(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    [cite_start]sensitive_columns_to_drop = ['annual_leave_balance', 'monthly_salary'] [cite: 7]
    for col in sensitive_columns_to_drop:
        if col in df.columns:
            df = df.drop(columns=[col])
    if 'E-Mail' in df.columns and 'Title' in df.columns:
        allowed_titles = {'BUM', 'AM', 'DM'}
        [cite_start]mask = ~df['Title'].astype(str).str.upper().isin(allowed_titles) [cite: 9]
        df.loc[mask, 'E-Mail'] = ""  
    return df

# ============================
# 🆕 FUNCTION: Load & Save IDB Reports
# ============================
def load_idb_reports():
    return load_json_file(IDB_REPORTS_FILE, default_columns=[
        "Employee Code", "Employee Name", "Selected Departments", "Strengths", "Development Areas", "Action Plan", "Updated At"
    ])

def save_idb_report(employee_code, employee_name, selected_deps, strengths, development, action):
    reports = load_idb_reports()
    now = pd.Timestamp.now().isoformat()
    new_row = {
        [cite_start]"Employee Code": employee_code, [cite: 10]
        "Employee Name": employee_name,
        "Selected Departments": selected_deps,
        "Strengths": strengths,
        "Development Areas": development,
        "Action Plan": action,
        "Updated At": now
    }
    reports = reports[reports["Employee Code"] != employee_code]
    [cite_start]reports = pd.concat([reports, pd.DataFrame([new_row])], ignore_index=True) [cite: 11]
    return save_json_file(reports, IDB_REPORTS_FILE)

# ============================
# Load Configuration from config.json
# ============================
def load_config():
    default_config = {
        "file_paths": {
            "employees": "employees.json",
            "leaves": "leaves.json",
            "notifications": "notifications.json",
            "hr_queries": "hr_queries.json",
            "hr_requests": "hr_requests.json",
            [cite_start]"salaries": "salaries.json", [cite: 12]
            "recruitment_data": "recruitment_data.json"
        },
        "github": {
            "repo_owner": "mohamedomar-hub",
            "repo_name": "hr-system",
            "branch": "main"
        },
        "recruitment": {
            [cite_start]"cv_dir": "recruitment_cvs", [cite: 13]
            "google_form_link": "https://docs.google.com/forms/d/e/1FAIpQLSccvOVVSrKDRAF-4rOt0N_rEr8SmQ2F6cVRSwk7RGjMoRhpLQ/viewform"
        },
        "system": {
            "logo_path": "logo.jpg",
            "default_annual_leave_days": 21
        }
    }
    try:
        with open("config.json", "r", encoding="utf-8") as f:
            [cite_start]user_config = json.load(f) [cite: 14]
        def deep_merge(a, b):
            for k, v in b.items():
                if isinstance(v, dict) and k in a and isinstance(a[k], dict):
                    deep_merge(a[k], v)
                else:
                    [cite_start]a[k] = v [cite: 15]
            return a
        return deep_merge(default_config, user_config)
    except FileNotFoundError:
        [cite_start]st.warning("config.json not found. Using default settings.") [cite: 16]
        return default_config
    except Exception as e:
        st.error(f"Error loading config.json: {e}. Using defaults.")
        return default_config

CONFIG = load_config()
DEFAULT_FILE_PATH = CONFIG["file_paths"]["employees"]
LEAVES_FILE_PATH = CONFIG["file_paths"]["leaves"]
NOTIFICATIONS_FILE_PATH = CONFIG["file_paths"]["notifications"]
HR_QUERIES_FILE_PATH = CONFIG["file_paths"]["hr_queries"]
HR_REQUESTS_FILE_PATH = CONFIG["file_paths"]["hr_requests"]
SALARIES_FILE_PATH = CONFIG["file_paths"]["salaries"]
RECRUITMENT_CV_DIR = CONFIG["recruitment"]["cv_dir"]
RECRUITMENT_DATA_FILE = CONFIG["file_paths"]["recruitment_data"]
GOOGLE_FORM_RECRUITMENT_LINK = CONFIG["recruitment"]["google_form_link"]
DEFAULT_ANNUAL_LEAVE = CONFIG["system"]["default_annual_leave_days"]
GITHUB_TOKEN = st.secrets.get("GITHUB_TOKEN", None)
REPO_OWNER = st.secrets.get("REPO_OWNER", CONFIG["github"]["repo_owner"])
REPO_NAME = st.secrets.get("REPO_NAME", CONFIG["github"]["repo_name"])
BRANCH = st.secrets.get("BRANCH", CONFIG["github"]["branch"])
FILE_PATH = st.secrets.get("FILE_PATH", DEFAULT_FILE_PATH) if st.secrets.get("FILE_PATH") else DEFAULT_FILE_PATH

# ============================
# 🔐 Secure Password Management
# ============================
SECURE_PASSWORDS_FILE = "secure_passwords.json"
def load_password_hashes():
    if os.path.exists(SECURE_PASSWORDS_FILE):
        with open(SECURE_PASSWORDS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}
def save_password_hashes(hashes):
    with open(SECURE_PASSWORDS_FILE, "w", encoding="utf-8") as f:
        json.dump(hashes, f, indent=2)
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
def verify_password(plain_password: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed.encode('utf-8'))
def initialize_passwords_from_data(data_list):
    hashes = load_password_hashes()
    for row in data_list:
        [cite_start]emp_code = str(row.get("Employee Code", "")).strip().replace(".0", "") [cite: 18]
        pwd = str(row.get("Password", "")).strip()
        if emp_code and pwd and emp_code not in hashes:
            hashes[emp_code] = hash_password(pwd)
    save_password_hashes(hashes)

# ============================
# JSON File Helpers
# ============================
def load_json_file(filepath, default_columns=None):
    if os.path.exists(filepath):
        try:
            [cite_start]with open(filepath, "r", encoding="utf-8") as f: [cite: 19]
                data = json.load(f)
            df = pd.DataFrame(data)
            return sanitize_employee_data(df)
        except Exception:
            return pd.DataFrame(columns=default_columns) if default_columns else pd.DataFrame()
    else:
        [cite_start]if default_columns: [cite: 20]
            return pd.DataFrame(columns=default_columns)
        return pd.DataFrame()

def save_json_file(df, filepath):
    try:
        df_sanitized = sanitize_employee_data(df)
        sensitive_cols = ["Basic Salary", "KPI Bonus", "Deductions", "Net Salary"]
        df_copy = df_sanitized.copy()
        [cite_start]for col in sensitive_cols: [cite: 21]
            if col in df_copy.columns:
                df_copy[col] = df_copy[col].apply(encrypt_salary_value)
        data = df_copy.where(pd.notnull(df_copy), None).to_dict(orient='records')
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        [cite_start]return True [cite: 22]
    except Exception:
        return False

# ============================
# Styling - Modern Light Mode CSS (Updated)
# ============================
st.set_page_config(page_title="HRAS — Averroes Admin", page_icon="👥", layout="wide")

updated_css = """
<style>
/* ========== COLORS SYSTEM ========== */
:root {
--primary: #05445E;
--secondary: #0A5C73;
--sky-blue: #1E88E5;
--hover-red: #dc2626;
--text-main: #2E2E2E;
--text-muted: #6B7280;
--card-bg: #FFFFFF;
--soft-bg: #F2F6F8;
--border-soft: #E5E7EB;
}

/* ========== SIDEBAR NAVIGATION BOXES MODIFICATION ========== */
/* Target the radio button container in the sidebar */
[data-testid="stSidebar"] .stRadio div[role="radiogroup"] {
    gap: 10px;
    padding-top: 15px;
}

/* Transform radio labels into styled boxes */
[data-testid="stSidebar"] .stRadio div[role="radiogroup"] label {
    background-color: var(--sky-blue) !important;
    border-radius: 8px !important;
    padding: 10px 15px !important;
    margin-bottom: 4px !important;
    transition: all 0.3s ease-in-out !important;
    border: none !important;
    display: block !important;
    width: 100% !important;
    cursor: pointer !important;
}

/* Text inside the boxes */
[data-testid="stSidebar"] .stRadio div[role="radiogroup"] label div[data-testid="stMarkdownContainer"] p {
    color: #FFFFFF !important;
    font-weight: 600 !important;
    font-size: 0.95rem !important;
}

/* Hover effect: Red background */
[data-testid="stSidebar"] .stRadio div[role="radiogroup"] label:hover {
    background-color: var(--hover-red) !important;
    transform: scale(1.02);
}

/* Hide the default radio circle/dot */
[data-testid="stSidebar"] .stRadio div[role="radiogroup"] label div[role="presentation"] {
    display: none !important;
}

/* Selected item styling */
[data-testid="stSidebar"] .stRadio div[role="radiogroup"] label[data-checked="true"] {
    background-color: var(--primary) !important;
    border: 1px solid #FFFFFF !important;
}

/* ========== GENERAL TEXT ========== */
html, body, p, span, label { color: var(--text-main) !important; }
h1, h2, h3, h4, h5 { color: var(--primary) !important; font-weight: 600; }

/* ========== SIDEBAR USER INFO ========== */
section[data-testid="stSidebar"] h4,
section[data-testid="stSidebar"] h5,
section[data-testid="stSidebar"] p { color: #FFFFFF !important; font-weight: 600; }

/* ========== CARDS & BOXES ========== */
.card {
    background-color: var(--card-bg);
    border-radius: 16px;
    padding: 18px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.06);
    border: 1px solid var(--border-soft);
}
.section-box {
    background-color: var(--soft-bg);
    padding: 14px 20px;
    border-radius: 14px;
    margin: 25px 0 15px 0;
}
.hr-message-card {
    background-color: #FFFFFF;
    border-left: 4px solid var(--primary);
    padding: 12px;
    margin: 10px 0;
    border-radius: 8px;
    box-shadow: 0 2px 6px rgba(0,0,0,0.05);
}

/* ========== BUTTONS ========== */
.stButton > button {
    background-color: var(--sky-blue) !important;
    color: white !important;
    border: none !important;
    font-weight: 600;
    padding: 0.5rem 1rem;
    border-radius: 6px;
}
.stButton > button:hover {
    background-color: var(--hover-red) !important;
    color: white !important;
}

/* General App Background */
[data-testid="stAppViewContainer"] { background-color: #F2F2F2 !important; }

/* Streamlit defaults hiding */
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
div[data-testid="stDeployButton"] { display: none; }
</style>
"""
st.markdown(updated_css, unsafe_allow_html=True)

# ============================
# ✅ External Password Change Page
# ============================
def page_forgot_password():
    st.subheader("🔐 Change Password (No Login Required)")
    st.info("Enter your Employee Code. If your password was reset by HR, you can set a new one directly.")
    with st.form("external_password_change"):
        emp_code = st.text_input("Employee Code")
        new_pwd = st.text_input("New Password", type="password")
        confirm_pwd = st.text_input("Confirm New Password", type="password")
        submitted = st.form_submit_button("Set New Password")
    
    [cite_start]if submitted: [cite: 48]
            if not emp_code.strip() or not new_pwd or not confirm_pwd:
                st.error("All fields are required.")
            elif new_pwd != confirm_pwd:
                st.error("New password and confirmation do not match.")
            else:
                [cite_start]emp_code_clean = emp_code.strip().replace(".0", "") [cite: 49]
                hashes = load_password_hashes()
                df = st.session_state.get("df", pd.DataFrame())
                [cite_start]if df.empty: [cite: 50]
                    st.error("Employee data not loaded.")
                    return
                col_map = {c.lower().strip(): c for c in df.columns}
                code_col = col_map.get("employee_code") or col_map.get("employee code")
                [cite_start]if not code_col: [cite: 51]
                    st.error("Employee code column not found in dataset.")
                    return
                df[code_col] = df[code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
                [cite_start]if emp_code_clean not in df[code_col].values: [cite: 52]
                    st.error("Employee code not found in the company database.")
                    return
                hashes[emp_code_clean] = hash_password(new_pwd)
                [cite_start]save_password_hashes(hashes) [cite: 53]
                [cite_start]st.success("✅ Your password has been set successfully. You can now log in.") [cite: 54]
                add_notification("", "HR", f"Employee {emp_code_clean} set a new password after reset.")
                st.rerun()

# ============================
# Photo & Recruitment Helpers
# ============================
def save_employee_photo(employee_code, uploaded_file):
    os.makedirs("employee_photos", exist_ok=True)
    emp_code_clean = str(employee_code).strip().replace(".0", "")
    ext = uploaded_file.name.split(".")[-1].lower()
    if ext not in ["jpg", "jpeg", "png"]:
        raise ValueError("Only JPG/PNG files allowed.")
    filename = f"{emp_code_clean}.{ext}"
    [cite_start]filepath = os.path.join("employee_photos", filename) [cite: 55]
    with open(filepath, "wb") as f:
        f.write(uploaded_file.getbuffer())
    return filename

def save_recruitment_cv(uploaded_file):
    os.makedirs(RECRUITMENT_CV_DIR, exist_ok=True)
    ext = uploaded_file.name.split(".")[-1].lower()
    if ext not in ["pdf", "doc", "docx"]:
        raise ValueError("Only PDF or DOC/DOCX files allowed for CV.")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"cv_{timestamp}.{ext}"
    filepath = os.path.join(RECRUITMENT_CV_DIR, filename)
    [cite_start]with open(filepath, "wb") as f: [cite: 56]
        f.write(uploaded_file.getbuffer())
    return filename

# ============================
# GitHub helpers (JSON version)
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
            [cite_start]content = resp.json() [cite: 57]
            file_content = base64.b64decode(content["content"])
            data = json.loads(file_content.decode('utf-8'))
            df = pd.DataFrame(data)
            return sanitize_employee_data(df)
        else:
            return pd.DataFrame()
    [cite_start]except Exception: [cite: 58]
        return pd.DataFrame()

def get_file_sha(filepath):
    try:
        url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{filepath}"
        params = {"ref": BRANCH}
        resp = requests.get(url, headers=github_headers(), params=params, timeout=30)
        if resp.status_code == 200:
            return resp.json().get("sha")
        else:
            return None
    [cite_start]except Exception: [cite: 59]
        return None

def upload_json_to_github(filepath, data_list, commit_message):
    if not GITHUB_TOKEN:
        return False
    try:
        df_temp = pd.DataFrame(data_list)
        df_sanitized = sanitize_employee_data(df_temp)
        data_list_sanitized = df_sanitized.to_dict(orient='records')
        [cite_start]sensitive_cols = ["Basic Salary", "KPI Bonus", "Deductions", "Net Salary"] [cite: 60]
        data_list_copy = [row.copy() for row in data_list_sanitized]
        for item in data_list_copy:
            for col in sensitive_cols:
                if col in item and item[col] is not None:
                    [cite_start]if isinstance(item[col], str): [cite: 61]
                        try:
                            base64.urlsafe_b64decode(item[col].encode())
                            continue
                        [cite_start]except Exception: [cite: 62]
                            item[col] = encrypt_salary_value(item[col])
                    else:
                        item[col] = encrypt_salary_value(item[col])
        json_content = json.dumps(data_list_copy, ensure_ascii=False, indent=2).encode('utf-8')
        file_content_b64 = base64.b64encode(json_content).decode("utf-8")
        [cite_start]url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{filepath}" [cite: 63]
        sha = get_file_sha(filepath)
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
    [cite_start]if "df" not in st.session_state: [cite: 64]
        df_loaded = load_employee_data_from_github()
        if not df_loaded.empty:
            st.session_state["df"] = df_loaded
        else:
            st.session_state["df"] = load_json_file(FILE_PATH)

# ============================
# Login & Save Helpers
# ============================
def login(df, code, password):
    if df is None or df.empty:
        return None
    col_map = {c.lower().strip(): c for c in df.columns}
    [cite_start]code_col = col_map.get("employee_code") or col_map.get("employee code") [cite: 65]
    if not code_col:
        return None
    df_local = df.copy()
    df_local[code_col] = df_local[code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
    code_s = str(code).strip()
    matched = df_local[df_local[code_col] == code_s]
    if matched.empty:
        return None
    hashes = load_password_hashes()
    stored_hash = hashes.get(code_s)
    if stored_hash and verify_password(password, stored_hash):
        return matched.iloc[0].to_dict()
    return None

def save_df_to_local(df):
    [cite_start]return save_json_file(df, FILE_PATH) [cite: 66]

def save_and_maybe_push(df, actor="HR"):
    saved = save_json_file(df, FILE_PATH)
    pushed = False
    if GITHUB_TOKEN:
        data_list = df.where(pd.notnull(df), None).to_dict(orient='records')
        pushed = upload_json_to_github(FILE_PATH, data_list, f"Update {FILE_PATH} via Streamlit by {actor}")
        if pushed:
            saved = True
    return saved, pushed

def load_leaves_data():
    df = load_json_file(LEAVES_FILE_PATH, default_columns=[
        [cite_start]"Employee Code", "Manager Code", "Start Date", "End Date", [cite: 67]
        "Leave Type", "Reason", "Status", "Decision Date", "Comment"
    ])
    date_cols = ["Start Date", "End Date", "Decision Date"]
    for col in date_cols:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors="coerce")
    return df

def save_leaves_data(df):
    df = df.copy()
    date_cols = ["Start Date", "End Date", "Decision Date"]
    for col in date_cols:
        [cite_start]if col in df.columns: [cite: 68]
            df[col] = pd.to_datetime(df[col], errors="coerce").dt.strftime("%Y-%m-%d")
    return save_json_file(df, LEAVES_FILE_PATH)

# ============================
# Notifications System
# ============================
def load_notifications():
    return load_json_file(NOTIFICATIONS_FILE_PATH, default_columns=[
        "Recipient Code", "Recipient Title", "Message", "Timestamp", "Is Read"
    ])

def save_notifications(df):
    df = df.copy()
    if "Timestamp" in df.columns:
        df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce").astype(str)
    return save_json_file(df, NOTIFICATIONS_FILE_PATH)

def add_notification(recipient_code, recipient_title, message):
    notifications = load_notifications()
    [cite_start]new_row = pd.DataFrame([{ [cite: 69]
        "Recipient Code": str(recipient_code),
        "Recipient Title": str(recipient_title),
        "Message": message,
        "Timestamp": pd.Timestamp.now().isoformat(),
        "Is Read": False
    }])
    notifications = pd.concat([notifications, new_row], ignore_index=True)
    save_notifications(notifications)

def get_unread_count(user):
    notifications = load_notifications()
    if notifications.empty:
        return 0
    user_code = None
    [cite_start]user_title = None [cite: 70]
    for key, val in user.items():
        if key == "Employee Code":
            user_code = str(val).strip().replace(".0", "")
        if key == "Title":
            user_title = str(val).strip().upper()
    if not user_code and not user_title:
        return 0
    mask = (
        (notifications["Recipient Code"].astype(str) == user_code) |
        (notifications["Recipient Title"].astype(str)[cite_start].str.upper() == user_title) [cite: 71]
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
            [cite_start]user_title = str(val).strip().upper() [cite: 72]
    mask = (
        (notifications["Recipient Code"].astype(str) == user_code) |
        (notifications["Recipient Title"].astype(str).str.upper() == user_title)
    )
    notifications.loc[mask, "Is Read"] = True
    save_notifications(notifications)

def format_relative_time(ts):
    if not ts or pd.isna(ts):
        return "N/A"
    try:
        dt = pd.to_datetime(ts)
        [cite_start]now = pd.Timestamp.now() [cite: 73]
        diff = now - dt
        seconds = int(diff.total_seconds())
        if seconds < 60:
            return "الآن"
        elif seconds < 3600:
            return f"قبل {seconds // 60} دقيقة"
        elif seconds < 86400:
            [cite_start]return f"قبل {seconds // 3600} ساعة" [cite: 74]
        else:
            return dt.strftime("%d-%m-%Y")
    except Exception:
        return str(ts)

# ============================
# page_notifications
# ============================
def page_notifications(user):
    st.subheader("🔔 Notifications")
    notifications = load_notifications()
    if notifications.empty:
        st.info("No notifications.")
        return
    user_code = None
    user_title = None
    for key, val in user.items():
        [cite_start]if key == "Employee Code": [cite: 75]
            user_code = str(val).strip().replace(".0", "")
        if key == "Title":
            user_title = str(val).strip().upper()
    if not user_code and not user_title:
        return
    user_notifs = notifications[
        (notifications["Recipient Code"].astype(str) == user_code) |
        (notifications["Recipient Title"].astype(str)[cite_start].str.upper() == user_title) [cite: 76]
    ].copy()
    if user_notifs.empty:
        st.info("No notifications for you.")
        return
    user_notifs = user_notifs.sort_values("Timestamp", ascending=False).reset_index(drop=True)
    filter_option = st.radio("Filter notifications:", ["All", "Unread", "Read"], index=1, horizontal=True, key="notif_filter")
    if filter_option == "Unread":
        [cite_start]filtered_notifs = user_notifs[~user_notifs["Is Read"]] [cite: 77]
    elif filter_option == "Read":
        filtered_notifs = user_notifs[user_notifs["Is Read"]]
    else:
        filtered_notifs = user_notifs.copy()
    if not user_notifs[user_notifs["Is Read"] == False].empty:
        col1, col2 = st.columns([4, 1])
        with col2:
            if st.button("✅ Mark all as read", key="mark_all_read_btn"):
                [cite_start]mark_all_as_read(user) [cite: 78]
                st.success("All notifications marked as read.")
                st.rerun()
    if filtered_notifs.empty:
        st.info(f"No {filter_option.lower()} notifications.")
        return
    for idx, row in filtered_notifs.iterrows():
        if "approved" in str(row["Message"]).lower():
            icon = "✅"
            [cite_start]color = "#059669" [cite: 79]
            bg_color = "#f0fdf4"
        elif "rejected" in str(row["Message"]).lower():
            icon = "❌"
            color = "#dc2626"
            bg_color = "#fef2f2"
        else:
            [cite_start]icon = "📝" [cite: 80]
            color = "#05445E"
            bg_color = "#f8fafc"
        status_badge = "✅" if row["Is Read"] else "🆕"
        time_formatted = format_relative_time(row["Timestamp"])
        st.markdown(f"""
[cite_start]<div style="background-color: {bg_color}; border-left: 4px solid {color}; padding: 12px; margin: 10px 0; border-radius: 8px; box-shadow: 0 2px 6px rgba(0,0,0,0.05);"> [cite: 81]
[cite_start]<div style="display: flex; justify-content: space-between; align-items: flex-start;"> [cite: 82]
<div style="display: flex; align-items: center; gap: 10px; flex: 1;">
<span style="font-size: 1.3rem; color: {color};">{icon}</span>
<div>
[cite_start]<div style="color: {color}; font-weight: bold; font-size: 1.05rem;"> [cite: 83]
{status_badge} {row['Message']}
</div>
<div style="color: #666666; font-size: 0.9rem; margin-top: 4px;">
• {time_formatted}
</div>
</div>
</div>
</div>
</div>
""", unsafe_allow_html=True)
        st.markdown("---")

# ============================
# page_manager_leaves
# ============================
def page_manager_leaves(user):
    st.subheader("📅 Team Leave Requests")
    manager_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    if not manager_code:
        st.error("Your Employee Code not found.")
        return
    leaves_df = load_leaves_data()
    if leaves_df.empty:
        [cite_start]st.info("No leave requests in the system.") [cite: 84]
        return
    leaves_df["Manager Code"] = leaves_df["Manager Code"].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
    team_leaves = leaves_df[leaves_df["Manager Code"] == manager_code].copy()
    if team_leaves.empty:
        st.info("No leave requests from your team.")
        return
    df_emp = st.session_state.get("df", pd.DataFrame())
    name_col_to_use = "Employee Code"
    if not df_emp.empty:
        [cite_start]col_map = {c.lower().strip(): c for c in df_emp.columns} [cite: 85]
        emp_code_col = col_map.get("employee_code") or col_map.get("employee code")
        emp_name_col = col_map.get("employee_name") or col_map.get("employee name") or col_map.get("name")
        if emp_code_col and emp_name_col:
            df_emp[emp_code_col] = df_emp[emp_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
            team_leaves["Employee Code"] = team_leaves["Employee Code"].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
            team_leaves = team_leaves.merge(
                [cite_start]df_emp[[emp_code_col, emp_name_col]], [cite: 86]
                left_on="Employee Code",
                right_on=emp_code_col,
                how="left"
            )
            name_col_to_use = emp_name_col
    pending_leaves = team_leaves[team_leaves["Status"] == "Pending"].reset_index(drop=True)
    all_leaves = team_leaves.copy()
    [cite_start]st.markdown("### 🟡 Pending Requests") [cite: 87]
    if not pending_leaves.empty:
        for idx, row in pending_leaves.iterrows():
            emp_name = row.get(name_col_to_use, "") if name_col_to_use in row else ""
            emp_display = f"{emp_name} ({row['Employee Code']})" if emp_name else row['Employee Code']
            [cite_start]st.markdown(f"**Employee**: {emp_display} | **Dates**: {row['Start Date']} → {row['End Date']} | **Type**: {row['Leave Type']}") [cite: 88]
            st.write(f"**Reason**: {row['Reason']}")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("✅ Approve", key=f"app_{idx}_{row['Employee Code']}"):
                    [cite_start]leaves_df.at[leaves_df[leaves_df["Manager Code"] == manager_code].index[leaves_df[leaves_df["Manager Code"] == manager_code]["Employee Code"] == row["Employee Code"]].tolist()[idx], "Status"] = "Approved" [cite: 89]
                    leaves_df.at[leaves_df[leaves_df["Manager Code"] == manager_code].index[leaves_df[leaves_df["Manager Code"] == manager_code]["Employee Code"] == row["Employee Code"]].tolist()[idx], "Decision Date"] = pd.Timestamp.now()
                    save_leaves_data(leaves_df)
                    add_notification(row['Employee Code'], "", "Your leave request has been approved!")
                    [cite_start]st.success("Approved!") [cite: 90]
                    st.rerun()
            with col2:
                if st.button("❌ Reject", key=f"rej_{idx}_{row['Employee Code']}"):
                    comment = st.text_input("Comment (optional)", key=f"com_{idx}_{row['Employee Code']}")
                    [cite_start]leaves_df.at[leaves_df[leaves_df["Manager Code"] == manager_code].index[leaves_df[leaves_df["Manager Code"] == manager_code]["Employee Code"] == row["Employee Code"]].tolist()[idx], "Status"] = "Rejected" [cite: 91]
                    leaves_df.at[leaves_df[leaves_df["Manager Code"] == manager_code].index[leaves_df[leaves_df["Manager Code"] == manager_code]["Employee Code"] == row["Employee Code"]].tolist()[idx], "Decision Date"] = pd.Timestamp.now()
                    leaves_df.at[leaves_df[leaves_df["Manager Code"] == manager_code].index[leaves_df[leaves_df["Manager Code"] == manager_code]["Employee Code"] == row["Employee Code"]].tolist()[idx], "Comment"] = comment
                    [cite_start]save_leaves_data(leaves_df) [cite: 92]
                    [cite_start]msg = f"Your leave request was rejected. Comment: {comment}" if comment else "Your leave request was rejected." [cite: 93]
                    add_notification(row['Employee Code'], "", msg)
                    st.success("Rejected!")
                    st.rerun()
        st.markdown("---")
    else:
        st.info("No pending requests.")
    [cite_start]st.markdown("### 📋 All Team Leave History") [cite: 94]
    if not all_leaves.empty:
        if name_col_to_use in all_leaves.columns:
            all_leaves["Employee Name"] = all_leaves[name_col_to_use]
        else:
            all_leaves["Employee Name"] = all_leaves["Employee Code"]
        all_leaves["Start Date"] = pd.to_datetime(all_leaves["Start Date"]).dt.strftime("%d-%m-%Y")
        all_leaves["End Date"] = pd.to_datetime(all_leaves["End Date"]).dt.strftime("%d-%m-%Y")
        [cite_start]st.dataframe(all_leaves[[ [cite: 95]
            "Employee Name", "Start Date", "End Date", "Leave Type", "Status", "Comment"
        ]], use_container_width=True)
        buf = BytesIO()
        with pd.ExcelWriter(buf, engine="openpyxl") as writer:
            all_leaves[["Employee Name", "Start Date", "End Date", "Leave Type", "Status", "Comment"]].to_excel(writer, index=False)
        buf.seek(0)
        [cite_start]st.download_button("📥 Download Full Team Leave History", data=buf, file_name=f"Team_Leaves_{manager_code}.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet") [cite: 96]
    else:
        st.info("No leave history for your team.")

# ============================
# page_salary_monthly
# ============================
def page_salary_monthly(user):
    st.subheader("Monthly Salaries")
    [cite_start]user_code = str(user.get("Employee Code", "")).strip().replace(".0", "") [cite: 97]
    try:
        if not os.path.exists(SALARIES_FILE_PATH):
            st.error(f"❌ File '{SALARIES_FILE_PATH}' not found.")
            return
        salary_df = load_json_file(SALARIES_FILE_PATH)
        if salary_df.empty:
            [cite_start]st.info("No salary data available.") [cite: 98]
            return
        required_columns = ["Employee Code", "Month", "Basic Salary", "KPI Bonus", "Deductions"]
        missing_cols = [c for c in required_columns if c not in salary_df.columns]
        if missing_cols:
            [cite_start]st.error(f"❌ Missing columns: {missing_cols}") [cite: 99]
            return
        salary_df["Employee Code"] = salary_df["Employee Code"].astype(str).str.strip().str.replace(".0", "", regex=False)
        [cite_start]user_salaries = salary_df[salary_df["Employee Code"] == user_code].copy() [cite: 100]
        if user_salaries.empty:
            st.info(f"🚫 No salary records found for you (Code: {user_code}).")
            return
        for col in ["Basic Salary", "KPI Bonus", "Deductions"]:
            user_salaries[col] = user_salaries[col].apply(decrypt_salary_value)
        [cite_start]user_salaries["Net Salary"] = user_salaries["Basic Salary"] + user_salaries["KPI Bonus"] - user_salaries["Deductions"] [cite: 101]
        user_salaries = user_salaries.reset_index(drop=True)
        [cite_start]if st.button("📊 Show All Details"): [cite: 102]
            st.session_state["show_all_details"] = not st.session_state.get("show_all_details", False)
        if st.session_state.get("show_all_details", False):
            st.markdown("### All Salary Records")
            [cite_start]st.dataframe(user_salaries[["Month", "Basic Salary", "KPI Bonus", "Deductions", "Net Salary"]], use_container_width=True) [cite: 103]
        for idx, row in user_salaries.iterrows():
            month = row["Month"]
            btn_key = f"show_details_{month}_{idx}"
            if st.button(f"Show Details for {month}", key=btn_key):
                [cite_start]st.session_state[f"salary_details_{month}"] = row.to_dict() [cite: 104]
        for idx, row in user_salaries.iterrows():
            month = row["Month"]
            details_key = f"salary_details_{month}"
            if st.session_state.get(details_key):
                details = st.session_state[details_key]
                card = f"""
[cite_start]<div style="background-color:#f0fdf4; padding:14px; border-radius:10px; margin-bottom:10px; box-shadow:0 4px 8px rgba(0,0,0,0.05);"> [cite: 105]
<h4 style="color:#05445E;">Salary Details – {details['Month']}</h4>
<p style="color:#666666;">💰 Basic Salary: <b style="color:#05445E;">{details['Basic Salary']:.2f}</b></p>
<p style="color:#666666;">🎯 KPI Bonus: <b style="color:#05445E;">{details['KPI Bonus']:.2f}</b></p>
<p style="color:#666666;">📉 Deductions: <b style="color:#dc2626;">{details['Deductions']:.2f}</b></p>
<hr style="border-color:#cbd5e1;">
<p style="color:#666666;">🧮 Net Salary: <b style="color:#059669;">{details['Net Salary']:.2f}</b></p>
</div>
"""
                st.markdown(card, unsafe_allow_html=True)
                output = BytesIO()
                [cite_start]with pd.ExcelWriter(output, engine="openpyxl") as writer: [cite: 106]
                    pd.DataFrame([details]).to_excel(writer, index=False, sheet_name=f"Salary_{month}")
                output.seek(0)
                [cite_start]st.download_button(f"📥 Download Salary Slip for {month}", data=output, file_name=f"Salary_{user_code}_{month}.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet") [cite: 107]
            [cite_start]if st.button(f"Hide Details for {month}", key=f"hide_{month}"): [cite: 108]
                del st.session_state[details_key]
                st.rerun()
    except Exception as e:
        st.error(f"❌ Error loading salary {e}")

# ============================
# page_salary_report
# ============================
def page_salary_report(user):
    st.subheader("Salary Report")
    [cite_start]st.info("Upload the monthly salary sheet. HR can save it to update the system for all employees.") [cite: 109]
    uploaded_file = st.file_uploader("Upload Salary Excel File (.xlsx)", type=["xlsx"])
    if uploaded_file:
        try:
            new_salary_df = pd.read_excel(uploaded_file)
            required_cols = ["Employee Code", "Month", "Basic Salary", "KPI Bonus", "Deductions"]
            if not all(col in new_salary_df.columns for col in required_cols):
                [cite_start]st.error("Missing required columns. Must include: Employee Code, Month, Basic Salary, KPI Bonus, Deductions.") [cite: 110]
                return
            cols_to_encrypt = ["Basic Salary", "KPI Bonus", "Deductions"]
            for col in cols_to_encrypt:
                new_salary_df[col] = new_salary_df[col].apply(encrypt_salary_value)
            [cite_start]if "Net Salary" in new_salary_df.columns: [cite: 111]
                new_salary_df["Net Salary"] = new_salary_df["Net Salary"].apply(encrypt_salary_value)
            st.session_state["uploaded_salary_df_preview"] = new_salary_df.copy()
            [cite_start]st.success("File loaded and encrypted. Preview below (values appear as encrypted strings).") [cite: 112]
            st.dataframe(new_salary_df.head(50), use_container_width=True)
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Replace In-Memory Salary Dataset with Uploaded File"):
                    save_json_file(new_salary_df, SALARIES_FILE_PATH)
                    [cite_start]st.session_state["salary_df"] = new_salary_df.copy() [cite: 113]
                    st.success("✅ Salary data encrypted and saved locally.")
            with col2:
                if st.button("Preview only (do not replace)"):
                    [cite_start]st.info("Preview shown above.") [cite: 114]
        except Exception as e:
            st.error(f"Failed to process uploaded file: {e}")
    st.markdown("---")
    st.markdown("### Save & Push Salary Report to GitHub")
    if st.button("Save current salary dataset locally and push to GitHub"):
        current_salary_df = st.session_state.get("salary_df")
        if current_salary_df is None:
            current_salary_df = load_json_file(SALARIES_FILE_PATH)
        if current_salary_df is None:
            [cite_start]st.error(f"Could not load salary data from {SALARIES_FILE_PATH}. Upload a file first.") [cite: 115]
            return
        saved = save_json_file(current_salary_df, SALARIES_FILE_PATH)
        pushed_to_github = False
        if saved and GITHUB_TOKEN:
            data_list = current_salary_df.where(pd.notnull(current_salary_df), None).to_dict(orient='records')
            pushed_to_github = upload_json_to_github(SALARIES_FILE_PATH, data_list, f"Update salary report via HR by {user.get('Employee Name', 'HR')}")
        if saved:
            [cite_start]if pushed_to_github: [cite: 117]
                st.success("✅ Salary data saved and pushed to GitHub.")
            else:
                if GITHUB_TOKEN:
                    st.warning("✅ Saved locally, but GitHub push failed.")
                [cite_start]else: [cite: 118]
                    st.info("✅ Saved locally. GitHub token not configured.")
        else:
            st.error("❌ Failed to save locally.")
    st.markdown("---")
    st.markdown("### Current Salary Data (Encrypted View)")
    current_salary_df = st.session_state.get("salary_df")
    if current_salary_df is None:
        current_salary_df = load_json_file(SALARIES_FILE_PATH)
    if current_salary_df is not None:
        [cite_start]st.session_state["salary_df"] = current_salary_df [cite: 119]
    if current_salary_df is not None and not current_salary_df.empty:
        st.dataframe(current_salary_df.head(100), use_container_width=True)
        buf = BytesIO()
        with pd.ExcelWriter(buf, engine="openpyxl") as writer:
            current_salary_df.to_excel(writer, index=False, sheet_name="Salaries")
        buf.seek(0)
        [cite_start]st.download_button("Download Current Encrypted Salary Data", data=buf, file_name="Salaries.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet") [cite: 120]
    else:
        st.info("No salary data available.")

# ============================
# page_hr_manager
# ============================
def page_hr_manager(user):
    st.subheader("HR Manager")
    st.info("Upload new employee sheet, manage employees, and perform administrative actions.")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        [cite_start]st.error("Employee data not loaded.") [cite: 121]
        return
    st.markdown("### 🔑 Reset Employee Password")
    [cite_start]st.warning("This will invalidate the current password. The employee must use 'Change Password (No Login)' to set a new one.") [cite: 122]
    with st.form("reset_password_form"):
        emp_code_reset = st.text_input("Enter Employee Code to Reset Password")
        reset_submitted = st.form_submit_button("🔐 Reset Password")
        if reset_submitted:
            if not emp_code_reset.strip():
                st.error("Please enter a valid Employee Code.")
            [cite_start]else: [cite: 123]
                emp_code_clean = emp_code_reset.strip().replace(".0", "")
                hashes = load_password_hashes()
                if emp_code_clean in hashes:
                    del hashes[emp_code_clean]
                    save_password_hashes(hashes)
                    [cite_start]st.success(f"✅ Password for Employee {emp_code_clean} has been reset. Employee must set a new password using the external link.") [cite: 124]
                    add_notification(emp_code_clean, "", "Your password was reset by HR. Please set a new password using the 'Change Password (No Login)' link on the login page.")
                else:
                    [cite_start]col_map = {c.lower().strip(): c for c in df.columns} [cite: 125]
                    code_col = col_map.get("employee_code") or col_map.get("employee code")
                    if code_col:
                        [cite_start]df[code_col] = df[code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True) [cite: 126]
                        if emp_code_clean in df[code_col].values:
                            [cite_start]st.success(f"✅ Employee {emp_code_clean} marked for password reset. They can now set a new password.") [cite: 127]
                            add_notification(emp_code_clean, "", "Your account is ready for a new password. Use the 'Change Password (No Login)' link.")
                        else:
                            [cite_start]st.error("Employee code not found in company database.") [cite: 128]
                    else:
                        st.error("Employee code column not found.")
    st.markdown("---")
    st.markdown("### 📊 HR: Detailed Leave Report for All Employees")
    leaves_df_all = load_leaves_data()
    [cite_start]df_emp_global = st.session_state.get("df", pd.DataFrame()) [cite: 129]
    if not df_emp_global.empty and not leaves_df_all.empty:
        col_map = {c.lower().strip(): c for c in df_emp_global.columns}
        emp_code_col = col_map.get("employee_code") or col_map.get("employee code")
        emp_name_col = col_map.get("employee_name") or col_map.get("employee name") or col_map.get("name")
        mgr_code_col = col_map.get("manager_code") or col_map.get("manager code")
        if emp_code_col and emp_name_col and mgr_code_col:
            leaves_df_all["Employee Code"] = leaves_df_all["Employee Code"].astype(str).str.strip()
            [cite_start]leaves_df_all["Manager Code"] = leaves_df_all["Manager Code"].astype(str).str.strip() [cite: 130]
            df_emp_global[emp_code_col] = df_emp_global[emp_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
            df_emp_global[mgr_code_col] = df_emp_global[mgr_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
            [cite_start]leaves_with_names = leaves_df_all.merge(df_emp_global[[emp_code_col, emp_name_col]].rename(columns={emp_code_col: "Employee Code", emp_name_col: "Employee Name"}), on="Employee Code", how="left") [cite: 131]
            leaves_with_names = leaves_with_names.merge(df_emp_global[[emp_code_col, emp_name_col]].rename(columns={emp_code_col: "Manager Code", emp_name_col: "Manager Name"}), on="Manager Code", how="left")
            leaves_with_names["Start Date"] = pd.to_datetime(leaves_with_names["Start Date"]).dt.strftime("%d-%m-%Y")
            [cite_start]leaves_with_names["End Date"] = pd.to_datetime(leaves_with_names["End Date"]).dt.strftime("%d-%m-%Y") [cite: 132]
            leaves_with_names["Annual Balance"] = 21
            leaves_with_names["Used Days"] = 0
            leaves_with_names["Remaining Days"] = 21
            for emp_code in leaves_with_names["Employee Code"].unique():
                [cite_start]_, used, remaining = calculate_leave_balance(emp_code, leaves_df_all) [cite: 133]
                mask = leaves_with_names["Employee Code"] == emp_code
                leaves_with_names.loc[mask, "Used Days"] = used
                leaves_with_names.loc[mask, "Remaining Days"] = remaining
            [cite_start]st.dataframe(leaves_with_names[["Employee Name", "Employee Code", "Start Date", "End Date", "Leave Type", "Status", "Comment", "Manager Name", "Manager Code", "Annual Balance", "Used Days", "Remaining Days"]], use_container_width=True) [cite: 134]
        else:
            st.warning("Required columns not found.")
    st.markdown("---")
    st.markdown("### Upload Employees Excel")
    [cite_start]uploaded_file = st.file_uploader("Upload Excel file (.xlsx) to replace the current employees dataset", type=["xlsx"]) [cite: 135]
    if uploaded_file:
        try:
            new_df = pd.read_excel(uploaded_file)
            new_df = sanitize_employee_data(new_df)
            [cite_start]st.session_state["uploaded_df_preview"] = new_df.copy() [cite: 136]
            [cite_start]st.success("File loaded and sanitized. Preview below.") [cite: 137]
            st.dataframe(new_df.head(50), use_container_width=True)
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Replace In-Memory Dataset with Uploaded File"):
                    [cite_start]st.session_state["df"] = new_df.copy() [cite: 138]
                    initialize_passwords_from_data(new_df.to_dict(orient='records'))
                    st.success("In-memory dataset replaced.")
            with col2:
                [cite_start]if st.button("Preview only (do not replace)"): [cite: 139]
                    st.info("Preview shown above.")
        except Exception as e:
            st.error(f"Failed to read uploaded file: {e}")
    st.markdown("---")
    st.markdown("### Manage Employees (Edit / Delete)")
    if df.empty:
        [cite_start]st.info("Dataset empty. Upload or load data first.") [cite: 140]
        return
    st.dataframe(df.head(100), use_container_width=True)
    col_map = {c.lower(): c for c in df.columns}
    code_col = col_map.get("employee_code") or list(df.columns)[0]
    selected_code = st.text_input("Enter employee code to edit/delete (exact match)", value="")
    if selected_code:
        matched_rows = df[df[code_col].astype(str) == str(selected_code).strip()]
        if matched_rows.empty:
            [cite_start]st.warning("No employee found with that code.") [cite: 141]
        else:
            row = matched_rows.iloc[0]
            st.markdown("#### Edit Employee")
            with st.form("edit_employee_form"):
                updated = {}
                for col in df.columns:
                    [cite_start]val = row[col] [cite: 142]
                    if pd.isna(val): val = ""
                    if isinstance(val, (int, float)) and not isinstance(val, bool):
                        [cite_start]try: [cite: 143]
                            updated[col] = st.number_input(label=str(col), value=float(val) if pd.notna(val) else 0.0, key=f"edit_{col}")
                        except Exception:
                            [cite_start]updated[col] = st.text_input(label=str(col), value=str(val), key=f"edit_{col}") [cite: 144]
                    elif "date" in str(col).lower():
                        try:
                            date_val = pd.to_datetime(val, errors="coerce")
                        [cite_start]except Exception: [cite: 145]
                            date_val = None
                        try:
                            updated[col] = st.date_input(label=str(col), value=date_val.date() if date_val is not None and pd.notna(date_val) else datetime.date.today(), key=f"edit_{col}_date")
                        [cite_start]except Exception: [cite: 146]
                            updated[col] = st.text_input(label=str(col), value=str(val), key=f"edit_{col}")
                    else:
                        [cite_start]updated[col] = st.text_input(label=str(col), value=str(val), key=f"edit_{col}") [cite: 147]
                if st.form_submit_button("Save Changes"):
                    for k, v in updated.items():
                        [cite_start]if isinstance(v, datetime.date): [cite: 148]
                            v = pd.Timestamp(v)
                        df.loc[df[code_col].astype(str) == str(selected_code).strip(), k] = v
                    st.session_state["df"] = df
                    saved, pushed = save_and_maybe_push(df, actor=user.get("Employee Name","HR"))
                    [cite_start]if saved: [cite: 149]
                        st.success("Employee updated and saved locally.")
                        [cite_start]if pushed: st.success("Changes pushed to GitHub.") [cite: 150]
                        else:
                            if GITHUB_TOKEN: st.warning("Saved locally but GitHub push failed.")
                            [cite_start]else: st.info("Saved locally. GitHub not configured.") [cite: 152]
                    else: st.error("Failed to save changes locally.")
            st.markdown("#### Delete Employee")
            if st.button("Initiate Delete"):
                st.session_state["delete_target"] = str(selected_code).strip()
            [cite_start]if st.session_state.get("delete_target") == str(selected_code).strip(): [cite: 153]
                st.warning(f"You are about to delete employee with code: {selected_code}.")
                col_del1, col_del2 = st.columns(2)
                with col_del1:
                    if st.button("Confirm Delete"):
                        [cite_start]st.session_state["df"] = df[df[code_col].astype(str) != str(selected_code).strip()].reset_index(drop=True) [cite: 154]
                        saved, pushed = save_and_maybe_push(st.session_state["df"], actor=user.get("Employee Name","HR"))
                        st.session_state["delete_target"] = None
                        [cite_start]if saved: [cite: 155]
                            st.success("Employee deleted and dataset saved locally.")
                            if pushed: st.success("Deletion pushed to GitHub.")
                            else:
                                [cite_start]if GITHUB_TOKEN: st.warning("Saved locally but GitHub push failed.") [cite: 157]
                                [cite_start]else: st.info("Saved locally. GitHub not configured.") [cite: 158]
                        else: st.error("Failed to save after deletion.")
                with col_del2:
                    if st.button("Cancel Delete"):
                        [cite_start]st.session_state["delete_target"] = None [cite: 159]
                        st.info("Deletion cancelled.")
    st.markdown("---")
    st.markdown("### Save / Push Dataset")
    if st.button("Save current in-memory dataset locally and optionally push to GitHub"):
        [cite_start]df_current = st.session_state.get("df", pd.DataFrame()) [cite: 160]
        saved, pushed = save_and_maybe_push(df_current, actor=user.get("Employee Name","HR"))
        if saved:
            if pushed: st.success("Saved locally and pushed to GitHub.")
            else:
                [cite_start]if GITHUB_TOKEN: st.warning("Saved locally but GitHub push failed.") [cite: 161]
                [cite_start]else: st.info("Saved locally. GitHub not configured.") [cite: 162]
        else: st.error("Failed to save dataset locally.")
    st.markdown("---")
    st.warning("🛠️ **Clear All Test Data** (Use BEFORE going live!)")
    if st.button("🗑️ Clear Leaves, HR Messages, Notifications & Photos"):
        try:
            test_files = [LEAVES_FILE_PATH, HR_QUERIES_FILE_PATH, NOTIFICATIONS_FILE_PATH, HR_REQUESTS_FILE_PATH, SALARIES_FILE_PATH]
            [cite_start]cleared = [] [cite: 163]
            for f in test_files:
                if os.path.exists(f): os.remove(f); cleared.append(f)
            [cite_start]if os.path.exists("employee_photos"): shutil.rmtree("employee_photos"); cleared.append("employee_photos/") [cite: 164]
            if os.path.exists("hr_request_files"): shutil.rmtree("hr_request_files"); cleared.append("hr_request_files/")
            [cite_start]if os.path.exists("hr_response_files"): shutil.rmtree("hr_response_files"); cleared.append("hr_response_files/") [cite: 165]
            if cleared: st.success(f"✅ Cleared: {', '.join(cleared)}")
            else: st.info("Nothing to clear.")
            st.rerun()
        [cite_start]except Exception as e: [cite: 166]
            st.error(f"❌ Failed to clear: {e}")

# ============================
# page_notify_compliance
# ============================
def page_notify_compliance(user):
    st.subheader("📨 Notify Compliance Team")
    st.info("Use this form to notify the Compliance team about delays, absences, or other operational issues.")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        [cite_start]st.error("Employee data not loaded.") [cite: 167]
        return
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    emp_code_col, mgr_code_col, emp_name_col = "Employee Code", "Manager Code", "Employee Name"
    if not all(col in df.columns for col in [emp_code_col, mgr_code_col, emp_name_col]):
        st.error(f"❌ Required columns missing.")
        return
    [cite_start]df[emp_code_col] = df[emp_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True) [cite: 168]
    df[mgr_code_col] = df[mgr_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
    user_row = df[df[emp_code_col] == user_code]
    if user_row.empty:
        st.error("Your record not found.")
        return
    manager_code = user_row.iloc[0].get(mgr_code_col, "N/A")
    manager_name = "N/A"
    if manager_code != "N/A":
        mgr_row = df[df[emp_code_col] == str(manager_code).strip()]
        if not mgr_row.empty:
            [cite_start]manager_name = mgr_row.iloc[0].get(emp_name_col, "N/A") [cite: 169]
    st.markdown(f"**Your Manager**: {manager_name} (Code: {manager_code})")
    compliance_titles = {"ASSOCIATE COMPLIANCE", "FIELD COMPLIANCE SPECIALIST", "COMPLIANCE MANAGER"}
    df["Title_upper"] = df["Title"].astype(str).str.upper()
    compliance_df = df[df["Title_upper"].isin(compliance_titles)].copy()
    if compliance_df.empty:
        [cite_start]st.warning("No Compliance officers found in the system.") [cite: 170]
        return
    compliance_options = {f"{r[emp_name_col]} (Code: {r[emp_code_col]})": {"name": r[emp_name_col], "code": r[emp_code_col]} for _, r in compliance_df.iterrows()}
    selected_option = st.selectbox("Select Compliance Officer", list(compliance_options.keys()))
    recipient_data = compliance_options[selected_option]
    [cite_start]message = st.text_area("Your Message", height=120, placeholder="Example: I was delayed today...") [cite: 171]
    if st.button("📤 Send to Compliance"):
        if not message.strip(): st.warning("Please write a message.")
        else:
            messages_df = load_compliance_messages()
            new_id = int(messages_df["ID"].max()) + 1 if not messages_df.empty else 1
            [cite_start]new_row = pd.DataFrame([{ [cite: 172]
                "ID": new_id, "MR Code": user_code, "MR Name": user.get("Employee Name", user_code),
                [cite_start]"Compliance Recipient": recipient_data["name"], "Compliance Code": recipient_data["code"], [cite: 173]
                "Manager Code": manager_code, "Manager Name": manager_name,
                [cite_start]"Message": message.strip(), "Timestamp": pd.Timestamp.now(), "Status": "Pending" [cite: 174]
            }])
            messages_df = pd.concat([messages_df, new_row], ignore_index=True)
            if save_compliance_messages(messages_df):
                [cite_start]for title in compliance_titles: add_notification("", title, f"New message from MR {user_code}") [cite: 175]
                if manager_code != "N/A": add_notification(manager_code, "", f"New compliance message from {user_code}")
                [cite_start]st.success("✅ Your message has been sent to Compliance and your manager.") [cite: 176]
            else: st.error("❌ Failed to send message.")

# ============================
# page_report_compliance
# ============================
def page_report_compliance(user):
    st.subheader("📋 Report Compliance")
    [cite_start]messages_df = load_compliance_messages() [cite: 177]
    if messages_df.empty:
        st.info("No compliance messages yet.")
        return
    df = st.session_state.get("df", pd.DataFrame())
    title_val = str(user.get("Title", "")).strip().upper()
    is_compliance = title_val in {"ASSOCIATE COMPLIANCE", "FIELD COMPLIANCE SPECIALIST", "COMPLIANCE MANAGER"}
    [cite_start]is_manager = title_val in {"AM", "DM"} [cite: 178]
    if not is_compliance and is_manager:
        user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
        hierarchy = build_team_hierarchy_recursive(df, user_code, title_val)
        if hierarchy:
            [cite_start]def collect_all_team_codes(node, codes_set): [cite: 179]
                if node:
                    codes_set.add(node.get("Manager Code", ""))
                    for child in node.get("Team", []): collect_all_team_codes(child, codes_set)
                [cite_start]return codes_set [cite: 180]
            team_codes = collect_all_team_codes(hierarchy, {user_code})
            [cite_start]messages_df = messages_df[messages_df["MR Code"].astype(str).isin(team_codes)].copy() [cite: 181]
    messages_df = messages_df.sort_values("Timestamp", ascending=False).reset_index(drop=True)
    messages_df["Date"] = pd.to_datetime(messages_df["Timestamp"]).dt.strftime("%d-%m-%Y %H:%M")
    [cite_start]display_df = messages_df[["Date", "MR Name", "MR Code", "Message", "Compliance Recipient", "Manager Name"]].rename(columns={"Date": "Date & Time", "MR Name": "Employee Name", "MR Code": "Employee Code", "Message": "Reason", "Compliance Recipient": "Sent To Compliance", "Manager Name": "Team Manager"}) [cite: 182]
    st.dataframe(display_df, use_container_width=True)
    buf = BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as writer: display_df.to_excel(writer, index=False)
    buf.seek(0)
    [cite_start]st.download_button("📥 Download Report (Excel)", data=buf, file_name="Compliance_Report.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet") [cite: 183]

# ============================
# page_idb_mr
# ============================
def page_idb_mr(user):
    st.subheader("🚀 IDB – Individual Development Blueprint")
    [cite_start]st.markdown('<div style="background-color:#f0fdf4; padding:12px; border-radius:8px; border-left:4px solid #059669;"><p style="color:#05445E; font-weight:bold;">We want you to always aim higher — your success matters to us.</p></div>', unsafe_allow_html=True) [cite: 184]
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    user_name = user.get("Employee Name", user_code)
    reports = load_idb_reports()
    existing = reports[reports["Employee Code"] == user_code]
    if not existing.empty:
        row = existing.iloc[0]
        selected_deps = eval(row["Selected Departments"]) if isinstance(row["Selected Departments"], str) else row["Selected Departments"]
        [cite_start]strengths = eval(row["Strengths"]) if isinstance(row["Strengths"], str) else row["Strengths"] [cite: 185]
        development = eval(row["Development Areas"]) if isinstance(row["Development Areas"], str) else row["Development Areas"]
        action = row["Action Plan"]
    else:
        selected_deps, strengths, development, action = [], ["", "", ""], ["", "", ""], ""
    with st.form("idb_form"):
        [cite_start]st.markdown("### 🔍 Select Target Departments (Max 2)") [cite: 186]
        selected = st.multiselect("Choose up to 2 departments:", options=["Sales", "Marketing", "HR", "SFE", "Distribution", "Market Access"], default=selected_deps)
        [cite_start]if len(selected) > 2: st.warning("⚠️ You can select a maximum of 2 departments.") [cite: 187]
        st.markdown("### 💪 Area of Strength")
        strength_inputs = [st.text_input(f"Strength {i+1}", value=strengths[i] if i < len(strengths) else "", key=f"str_{i}") for i in range(3)]
        [cite_start]st.markdown("### 📈 Area of Development") [cite: 188]
        dev_inputs = [st.text_input(f"Development {i+1}", value=development[i] if i < len(development) else "", key=f"dev_{i}") for i in range(3)]
        action_input = st.text_area("Action Plan", value=action, height=100)
        if st.form_submit_button("💾 Save IDB Report"):
            [cite_start]if len(selected) > 2: st.error("You cannot select more than 2 departments.") [cite: 189]
            else:
                [cite_start]if save_idb_report(user_code, user_name, selected, [s.strip() for s in strength_inputs if s.strip()], [d.strip() for d in dev_inputs if d.strip()], action_input.strip()): [cite: 191]
                    [cite_start]add_notification("", "HR", f"MR {user_name} updated IDB."); [cite: 192] add_notification("", "DM", f"MR {user_name} updated IDB."); add_notification("", "AM", f"MR {user_name} updated IDB."); add_notification("", "BUM", f"MR {user_name} updated IDB.")
                    [cite_start]st.success("✅ IDB Report saved!"); st.rerun() [cite: 193]
                else: st.error("❌ Failed to save.")
    if not existing.empty:
        st.markdown("### 📊 Your Current IDB Report")
        [cite_start]display_df = pd.DataFrame({"Field": ["Selected Departments", "Strength 1", "Strength 2", "Strength 3", "Development 1", "Development 2", "Development 3", "Action Plan", "Updated At"], "Value": [", ".join(selected_deps), *(strengths + [""] * (3 - len(strengths))), *(development + [""] * (3 - len(development))), action, existing.iloc[0]["Updated At"]]}) [cite: 194, 195, 196]
        st.table(display_df)
        [cite_start]buf = BytesIO(); [cite: 197]
        with pd.ExcelWriter(buf, engine="openpyxl") as writer: display_df.to_excel(writer, index=False)
        buf.seek(0); st.download_button("📥 Download IDB Report", data=buf, file_name=f"IDB_{user_code}.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

# ============================
# page_self_development
# ============================
def page_self_development(user):
    st.subheader("🌱 Self Development")
    [cite_start]st.markdown('<div style="background-color:#e0f2fe; padding:16px; border-radius:10px; text-align:center; margin-bottom:20px;"><h3 style="color:#05445E;">We always want you at your best — your success matters to us.</h3></div>', unsafe_allow_html=True) [cite: 198]
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    uploaded_cert = st.file_uploader("Upload your certification", type=["pdf", "jpg", "jpeg", "png"])
    cert_desc = st.text_input("Description", placeholder="e.g., Leadership Course...")
    if uploaded_cert and st.button("📤 Submit Certification"):
        os.makedirs("certifications", exist_ok=True)
        [cite_start]filename = f"cert_{user_code}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.{uploaded_cert.name.split('.')[-1].lower()}" [cite: 199]
        with open(os.path.join("certifications", filename), "wb") as f: f.write(uploaded_cert.getbuffer())
        cert_log = load_json_file("certifications_log.json", default_columns=["Employee Code", "File", "Description", "Uploaded At"])
        [cite_start]new_log = pd.DataFrame([{"Employee Code": user_code, "File": filename, "Description": cert_desc, "Uploaded At": pd.Timestamp.now().isoformat()}]) [cite: 200]
        save_json_file(pd.concat([cert_log, new_log], ignore_index=True), "certifications_log.json")
        add_notification("", "HR", f"MR {user_code} uploaded certification.")
        [cite_start]st.success("✅ Submitted to HR!"); st.rerun() [cite: 201]

# ============================
# page_hr_development
# ============================
def page_hr_development(user):
    st.subheader("🎓 Employee Development (HR View)")
    tab_idb, tab_certs = st.tabs(["📋 IDB Reports", "📜 Certifications"])
    with tab_idb:
        idb_df = load_idb_reports()
        if not idb_df.empty:
            if "Employee Name" not in idb_df.columns:
                [cite_start]df = st.session_state.get("df", pd.DataFrame()) [cite: 202]
                if not df.empty:
                    col_map = {c.lower().strip(): c for c in df.columns}
                    [cite_start]emp_code_col, emp_name_col = col_map.get("employee_code") or col_map.get("employee code"), col_map.get("employee_name") or col_map.get("employee name") or col_map.get("name") [cite: 203]
                    if emp_code_col and emp_name_col:
                        [cite_start]idb_df = idb_df.merge(df[[emp_code_col, emp_name_col]].rename(columns={emp_code_col: "Employee Code", emp_name_col: "Employee Name"}), on="Employee Code", how="left") [cite: 204, 205]
            [cite_start]idb_df["Selected Departments"] = idb_df["Selected Departments"].apply(lambda x: ", ".join(eval(x)) if isinstance(x, str) else ", ".join(x)) [cite: 206]
            [cite_start]idb_df["Strengths"] = idb_df["Strengths"].apply(lambda x: "; ".join(eval(x)) if isinstance(x, str) else "; ".join(x)) [cite: 207]
            idb_df["Development Areas"] = idb_df["Development Areas"].apply(lambda x: "; ".join(eval(x)) if isinstance(x, str) else "; ".join(x))
            [cite_start]st.dataframe(idb_df[["Employee Code", "Employee Name", "Selected Departments", "Strengths", "Development Areas", "Action Plan", "Updated At"]], use_container_width=True) [cite: 208]
            [cite_start]buf = BytesIO(); [cite: 209]
            with pd.ExcelWriter(buf, engine="openpyxl") as writer: idb_df.to_excel(writer, index=False)
            st.download_button("📥 Download IDB Reports", data=buf, file_name="HR_IDB_Reports.xlsx")
        else: st.info("📭 No IDB reports yet.")
    with tab_certs:
        cert_log = load_json_file("certifications_log.json")
        if not cert_log.empty:
            st.dataframe(cert_log, use_container_width=True)
            for idx, row in cert_log.iterrows():
                [cite_start]filepath = os.path.join("certifications", row["File"]) [cite: 210]
                if os.path.exists(filepath):
                    [cite_start]with open(filepath, "rb") as f: [cite: 211]
                        [cite_start]st.download_button(label=f"📥 Download {row['File']}", data=f.read(), file_name=row["File"], mime="application/octet-stream", key=f"dl_cert_{idx}") [cite: 212]
        else: st.info("📭 No certifications uploaded.")

# ============================
# page_manager_development
# ============================
def page_manager_development(user):
    st.subheader("🎓 Team Development (Manager View)")
    [cite_start]st.markdown('<div style="background-color:#e0f2fe; padding:12px; border-radius:8px; border-left:4px solid #05445E; margin-bottom:20px;"><p style="color:#05445E; font-weight:bold;">View your team\'s development reports and certifications.</p></div>', unsafe_allow_html=True) [cite: 214]
    user_code, user_title = str(user.get("Employee Code", "")).strip().replace(".0", ""), str(user.get("Title", "")).strip().upper()
    df = st.session_state.get("df", pd.DataFrame())
    hierarchy = build_team_hierarchy_recursive(df, user_code, user_title)
    [cite_start]def collect_all_team_codes(node, codes_set): [cite: 215]
        if node:
            codes_set.add(node.get("Manager Code", ""))
            for child in node.get("Team", []): collect_all_team_codes(child, codes_set)
        return codes_set
    [cite_start]team_codes = collect_all_team_codes(hierarchy, {user_code}) [cite: 216]
    st.info(f"👥 Your team includes {len(team_codes)} members")
    tab_idb, tab_certs = st.tabs(["📋 IDB Reports", "📜 Certifications"])
    with tab_idb:
        idb_df = load_idb_reports()
        if not idb_df.empty:
            [cite_start]idb_df = idb_df[idb_df["Employee Code"].astype(str).isin(team_codes)].copy() [cite: 217]
            if not idb_df.empty:
                if "Employee Name" not in idb_df.columns:
                    [cite_start]if not df.empty: [cite: 218]
                        col_map = {c.lower().strip(): c for c in df.columns}
                        [cite_start]emp_code_col, emp_name_col = col_map.get("employee_code"), col_map.get("employee_name") or col_map.get("name") [cite: 219]
                        if emp_code_col and emp_name_col:
                            [cite_start]idb_df = idb_df.merge(df[[emp_code_col, emp_name_col]].rename(columns={emp_code_col: "Employee Code", emp_name_col: "Employee Name"}), on="Employee Code", how="left") [cite: 220, 221]
                [cite_start]idb_df["Selected Departments"] = idb_df["Selected Departments"].apply(lambda x: ", ".join(eval(x)) if isinstance(x, str) else ", ".join(x)) [cite: 222]
                [cite_start]idb_df["Strengths"] = idb_df["Strengths"].apply(lambda x: "; ".join(eval(x)) if isinstance(x, str) else "; ".join(x)) [cite: 223]
                idb_df["Development Areas"] = idb_df["Development Areas"].apply(lambda x: "; ".join(eval(x)) if isinstance(x, str) else "; ".join(x))
                [cite_start]st.dataframe(idb_df[["Employee Code", "Employee Name", "Selected Departments", "Strengths", "Development Areas", "Action Plan", "Updated At"]], use_container_width=True) [cite: 224]
                [cite_start]buf = BytesIO(); [cite: 225]
                with pd.ExcelWriter(buf, engine="openpyxl") as writer: idb_df.to_excel(writer, index=False)
                [cite_start]st.download_button("📥 Download Team IDB Reports", data=buf, file_name=f"Team_IDB_{user_code}.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet") [cite: 226]
            [cite_start]else: st.info("📭 No IDB reports from your team.") [cite: 227]
        else: st.info("📭 No IDB reports yet.")
    with tab_certs:
        cert_log = load_json_file("certifications_log.json")
        if not cert_log.empty:
            [cite_start]cert_log = cert_log[cert_log["Employee Code"].astype(str).isin(team_codes)].copy() [cite: 228]
            if not cert_log.empty:
                st.dataframe(cert_log, use_container_width=True)
                for idx, row in cert_log.iterrows():
                    [cite_start]filepath = os.path.join("certifications", row["File"]) [cite: 229]
                    if os.path.exists(filepath):
                        [cite_start]with open(filepath, "rb") as f: [cite: 230]
                            [cite_start]st.download_button(label=f"📥 Download {row['File']}", data=f.read(), file_name=row["File"], mime="application/octet-stream", key=f"dl_cert_mgr_{idx}") [cite: 231]
            [cite_start]else: st.info("📭 No certifications from your team.") [cite: 232]
        else: st.info("📭 No certifications uploaded.")

# ============================
# Remaining Page Functions
# ============================
def render_logo_and_title(): pass
def page_employee_photos(user):
    st.subheader("📸 Employee Photos (HR Only)")
    os.makedirs("employee_photos", exist_ok=True)
    photo_files = os.listdir("employee_photos")
    [cite_start]if not photo_files: st.info("No employee photos uploaded yet."); return [cite: 233]
    df = st.session_state.get("df", pd.DataFrame())
    code_to_name = {}
    if not df.empty:
        col_map = {c.lower().strip(): c for c in df.columns}
        emp_code_col, emp_name_col = col_map.get("employee_code"), col_map.get("employee_name") or col_map.get("name")
        if emp_code_col and emp_name_col:
            df[emp_code_col] = df[emp_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
            [cite_start]for _, row in df.iterrows(): code_to_name[row[emp_code_col]] = row.get(emp_name_col, "N/A") [cite: 234]
    cols = st.columns(4)
    for i, filename in enumerate(sorted(photo_files)):
        with cols[i % 4]:
            filepath = os.path.join("employee_photos", filename)
            [cite_start]emp_code = filename.rsplit(".", 1)[0] [cite: 235]
            st.image(filepath, use_column_width=True); st.caption(f"{emp_code}<br>{code_to_name.get(emp_code, 'Unknown')}", unsafe_allow_html=True)
            with open(filepath, "rb") as f: st.download_button("📥 Download", f, file_name=filename, key=f"dl_{filename}")
    if st.button("📥 Download All Employee Photos (ZIP)"):
        [cite_start]zip_path = "employee_photos_all.zip" [cite: 236]
        with zipfile.ZipFile(zip_path, 'w') as zipf:
            for f in os.listdir("employee_photos"):
                fp = os.path.join("employee_photos", f)
                [cite_start]if os.path.isfile(fp): zipf.write(fp, f) [cite: 237]
        [cite_start]with open(zip_path, "rb") as f: st.download_button(label="Download All Photos", data=f, file_name="employee_photos_all.zip", mime="application/zip") [cite: 238]
        [cite_start]st.success("✅ ZIP file created.") [cite: 239]

def page_my_profile(user):
    st.subheader("My Profile")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty: st.info("No data available."); return
    col_map = {c.lower().strip(): c for c in df.columns}
    code_col = col_map.get("employee_code") or col_map.get("employee code")
    [cite_start]user_code = None [cite: 240]
    for k, v in user.items():
        if k.lower().replace(" ", "").replace("_", "") in ["employeecode", "employee_code"]:
            user_code = str(v).strip().replace(".0", ""); break
    [cite_start]if user_code is None: st.error("Code not found."); return [cite: 241]
    df[code_col] = df[code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
    row = df[df[code_col] == user_code]
    tab1, tab2 = st.tabs(["Profile Data", "Personal Photo"])
    with tab1:
        st.dataframe(row.reset_index(drop=True), use_container_width=True)
        [cite_start]buf = BytesIO(); [cite: 242]
        with pd.ExcelWriter(buf, engine="openpyxl") as writer: row.to_excel(writer, index=False)
        st.download_button("Download My Profile", data=buf, file_name="my_profile.xlsx")
    with tab2:
        photo_path = None
        for ext in ["jpg", "jpeg", "png"]:
            [cite_start]p = os.path.join("employee_photos", f"{user_code}.{ext}") [cite: 243, 244]
            if os.path.exists(p): photo_path = p; break
        if photo_path: st.image(photo_path, width=150)
        [cite_start]else: st.info("No photo uploaded yet.") [cite: 245]
        [cite_start]uploaded_file = st.file_uploader("Upload photo", type=["jpg", "png"], key="photo_uploader") [cite: 246]
        if uploaded_file and st.button("✅ Save Photo"):
            try:
                fn = save_employee_photo(user_code, uploaded_file)
                [cite_start]add_notification("", "HR", f"Employee {user_code} uploaded photo.") [cite: 247]
                st.success(f"Saved: {fn}"); st.rerun()
            [cite_start]except Exception as e: st.error(f"Failed: {e}") [cite: 248]
    with st.form("change_password_form"):
        curr, n1, n2 = st.text_input("Current", type="password"), st.text_input("New", type="password"), st.text_input("Confirm", type="password")
        if st.form_submit_button("Change Password"):
            [cite_start]if not curr or not n1 or not n2: st.error("All required.") [cite: 249]
            elif n1 != n2: st.error("Mismatch.")
            else:
                h = load_password_hashes()
                if h.get(user_code) and verify_password(curr, h.get(user_code)):
                    [cite_start]h[user_code] = hash_password(n1); save_password_hashes(h) [cite: 250]
                    [cite_start]st.success("✅ Updated."); add_notification("", "HR", f"Employee {user_code} changed password.") [cite: 251]
                else: st.error("❌ Incorrect.")

def calculate_leave_balance(user_code, leaves_df):
    annual_balance = DEFAULT_ANNUAL_LEAVE
    [cite_start]user_approved = leaves_df[(leaves_df["Employee Code"].astype(str) == str(user_code)) & (leaves_df["Status"] == "Approved")].copy() [cite: 252]
    if user_approved.empty: used_days = 0
    else:
        user_approved["Start Date"], user_approved["End Date"] = pd.to_datetime(user_approved["Start Date"]), pd.to_datetime(user_approved["End Date"])
        used_days = (user_approved["End Date"] - user_approved["Start Date"]).dt.days.clip(lower=0).sum()
    [cite_start]return annual_balance, used_days, annual_balance - used_days [cite: 253]

def page_leave_request(user):
    st.subheader("Request Leave")
    df_emp = st.session_state.get("df", pd.DataFrame())
    [cite_start]user_code = next((str(v).strip().replace(".0", "") for k, v in user.items() if k.lower().replace(" ", "").replace("_", "") in ["employeecode", "employee_code"]), None) [cite: 254]
    leaves_df = load_leaves_data()
    ann, used, rem = calculate_leave_balance(user_code, leaves_df)
    cols = st.columns(3)
    [cite_start]cols[0].markdown(f'<div class="leave-balance-card"><div class="leave-balance-title">Annual</div><div class="leave-balance-value">{ann} Days</div></div>', unsafe_allow_html=True) [cite: 255]
    cols[1].markdown(f'<div class="leave-balance-card"><div class="leave-balance-title">Used</div><div class="leave-balance-value used">{used} Days</div></div>', unsafe_allow_html=True)
    cols[2].markdown(f'<div class="leave-balance-card"><div class="leave-balance-title">Remaining</div><div class="leave-balance-value remaining">{rem} Days</div></div>', unsafe_allow_html=True)
    col_map = {c.lower().strip(): c for c in df_emp.columns}
    mgr_col = col_map.get("manager_code") or col_map.get("manager code")
    [cite_start]if not mgr_col: st.error("Manager Code column missing."); return [cite: 256]
    emp_row = df_emp[df_emp[col_map.get("employee_code") or col_map.get("employee code")].astype(str).str.replace('.0', '', regex=False) == user_code]
    manager_code = str(emp_row.iloc[0][mgr_col]).strip().replace(".0", "") if not emp_row.empty else None
    [cite_start]if not manager_code: st.warning("No manager assigned."); return [cite: 257]
    with st.form("leave_form"):
        s, e, t, r = st.date_input("Start"), st.date_input("End"), st.selectbox("Type", ["Annual", "Sick", "Emergency", "Unpaid"]), st.text_area("Reason")
        if st.form_submit_button("Submit"):
            if e < s: st.error("Invalid dates.")
            else:
                [cite_start]new_row = pd.DataFrame([{"Employee Code": user_code, "Manager Code": manager_code, "Start Date": pd.Timestamp(s), "End Date": pd.Timestamp(e), "Leave Type": t, "Reason": r, "Status": "Pending", "Decision Date": None, "Comment": ""}]) [cite: 259, 260, 261]
                if save_leaves_data(pd.concat([leaves_df, new_row], ignore_index=True)):
                    [cite_start]st.success("✅ Submitted."); add_notification(manager_code, "", f"New leave from {user_code}"); st.balloons() [cite: 262]
    user_leaves = leaves_df[leaves_df["Employee Code"].astype(str) == user_code].copy()
    if not user_leaves.empty:
        [cite_start]user_leaves["Start Date"], user_leaves["End Date"] = pd.to_datetime(user_leaves["Start Date"]).dt.strftime("%d-%m-%Y"), pd.to_datetime(user_leaves["End Date"]).dt.strftime("%d-%m-%Y") [cite: 263]
        st.dataframe(user_leaves[["Start Date", "End Date", "Leave Type", "Status", "Comment"]], use_container_width=True)

def build_team_hierarchy_recursive(df, manager_code, manager_title="AM"):
    [cite_start]ec, en, mc, tc = "Employee Code", "Employee Name", "Manager Code", "Title" [cite: 264]
    if not all(col in df.columns for col in [ec, en, mc, tc]): return {}
    [cite_start]df = df.copy(); df[ec] = df[ec].astype(str).str.strip().str.replace('.0', '', regex=False); df[mc] = df[mc].astype(str).str.strip().str.replace('.0', '', regex=False) [cite: 265]
    mgr_row = df[df[ec] == str(manager_code)]
    if mgr_row.empty: return {}
    curr_title = str(mgr_row.iloc[0][tc]).strip().upper()
    subs = df[df[mc] == str(manager_code)]
    [cite_start]if curr_title == "BUM": subs = subs[subs[tc].str.upper().isin(["AM", "DM"])] [cite: 266]
    elif curr_title == "AM": subs = subs[subs[tc].str.upper() == "DM"]
    elif curr_title == "DM": subs = subs[subs[tc].str.upper() == "MR"]
    [cite_start]node = {"Manager": f"{mgr_row.iloc[0][en]} ({curr_title})", "Manager Code": str(manager_code), "Team": [], "Summary": {"AM": 0, "DM": 0, "MR": 0, "Total": 0}} [cite: 267]
    for _, sub in subs.iterrows():
        child = build_team_hierarchy_recursive(df, sub[ec], sub[tc])
        if not child:
            st_child = sub[tc].upper()
            [cite_start]leaf = {"Manager": f"{sub[en]} ({st_child})", "Manager Code": str(sub[ec]), "Team": [], "Summary": {"AM": 1 if st_child == "AM" else 0, "DM": 1 if st_child == "DM" else 0, "MR": 1 if st_child == "MR" else 0, "Total": 1}} [cite: 268, 269]
            node["Team"].append(leaf)
        else: node["Team"].append(child)
    [cite_start]def collect_desc(start): [cite: 270]
        desc, stack = set(), [str(start)]
        while stack:
            curr = stack.pop(); direct = df[df[mc] == curr]
            for _, r in direct.iterrows():
                [cite_start]if r[ec] not in desc: desc.add(r[ec]); [cite: 271] [cite_start]stack.append(r[ec]) [cite: 272]
        return list(desc)
    all_d = collect_desc(manager_code)
    if all_d:
        d_df = df[df[ec].isin(all_d)]
        node["Summary"]["AM"], node["Summary"]["DM"], node["Summary"]["MR"] = int((d_df[tc].str.upper() == "AM").sum()), int((d_df[tc].str.upper() == "DM").sum()), int((d_df[tc].str.upper() == "MR").sum())
        node["Summary"]["Total"] = sum(node["Summary"].values())
    [cite_start]return node [cite: 273]

def page_my_team(user, role="AM"):
    st.subheader("My Team Structure")
    [cite_start]user_code = next((str(v).strip().replace(".0", "") for k, v in user.items() if k == "Employee Code"), None) [cite: 278]
    df = st.session_state.get("df", pd.DataFrame())
    [cite_start]hierarchy = build_team_hierarchy_recursive(df, user_code, role.upper()) [cite: 279, 280]
    if not hierarchy: st.info("Structure not found."); return
    [cite_start]ic, cl = {"BUM": "🏢", "AM": "👨‍💼", "DM": "👩‍💼", "MR": "🧑‍⚕️"}, {"BUM": "#05445E", "AM": "#05445E", "DM": "#0A5C73", "MR": "#dc2626"} [cite: 281]
    def render_tree(n, l=0, last=False):
        [cite_start]summary = " | ".join([f"{icon} {n['Summary'][r]} {r}" for r, icon in [("AM", "🟢"), ("DM", "🔵"), ("MR", "🟣")] if n['Summary'][r] > 0]) + f" | 🔢 {n['Summary']['Total']} Total" [cite: 285, 286]
        m_info, m_code = n.get("Manager", "Unknown"), n.get("Manager Code", "N/A")
        [cite_start]r_part = m_info.split("(")[-1].split(")")[0].strip() if "(" in m_info else "MR" [cite: 287]
        [cite_start]pref = ("    " * (l - 1) + ("└── " if last else "├── ")) if l > 0 else "" [cite: 288]
        st.markdown(f'<div class="team-node"><div class="team-node-header"><span style="color: {cl.get(r_part, "#2E2E2E")};">{pref}{ic.get(r_part, "👤")} <strong>{m_info}</strong> (Code: {m_code})</span><span class="team-node-summary">{summary}</span></div>', unsafe_allow_html=True)
        if n.get("Team"):
            st.markdown('<div class="team-node-children">', unsafe_allow_html=True)
            [cite_start]for i, c in enumerate(n["Team"]): render_tree(c, l + 1, i == len(n["Team"]) - 1) [cite: 289]
            st.markdown('</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
    render_tree(hierarchy, 0, True)

def page_directory(user):
    st.subheader("Company Structure")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty: return
    [cite_start]cols_to_show = ["Employee Code", "Employee Name", "Manager Name", "Title", "Mobile", "Department", "E-Mail", "Address as 702 bricks"] [cite: 292]
    col_map = {c.lower().strip(): c for c in df.columns}
    [cite_start]final_cols = [col_map[v] for n in cols_to_show for v in [n.lower().replace(' ', '_'), n.lower().replace(' ', ''), n.lower(), n] if v in col_map] [cite: 293, 294]
    c1, c2 = st.columns(2)
    [cite_start]s_name, s_code = c1.text_input("Name"), c2.text_input("Code") [cite: 295]
    f_df = df.copy()
    if s_name:
        [cite_start]name_col = next((c for c in df.columns if c.lower().replace(" ", "_") in ["employee_name", "name", "full_name"]), None) [cite: 296]
        if name_col: f_df = f_df[f_df[name_col].astype(str).str.contains(s_name, case=False, na=False)]
    if s_code:
        [cite_start]code_col = next((c for c in df.columns if c.lower().replace(" ", "_") in ["employee_code", "code", "emp_code"]), None) [cite: 297]
        if code_col: f_df = f_df[f_df[code_col].astype(str).str.contains(s_code, case=False, na=False)]
    if final_cols:
        [cite_start]st.dataframe(f_df[final_cols].copy(), use_container_width=True) [cite: 298, 299]

def load_hr_queries(): return load_json_file(HR_QUERIES_FILE_PATH, default_columns=["ID", "Employee Code", "Employee Name", "Subject", "Message", "Reply", "Status", "Date Sent", "Date Replied"])
def save_hr_queries(df):
    df = df.copy()
    for c in ["Date Sent", "Date Replied"]:
        if c in df.columns: df[c] = pd.to_datetime(df[c], errors="coerce").astype(str)
    [cite_start]if "ID" in df.columns: [cite: 300]
        df["ID"] = pd.to_numeric(df["ID"], errors="coerce")
        if df["ID"].isna().any():
            mx = int(df["ID"].max(skipna=True)) if not df["ID"].isna().all() else 0
            [cite_start]for i in df[df["ID"].isna()].index: mx += 1; df.at[i, "ID"] = mx [cite: 301]
        df["ID"] = df["ID"].astype(int)
    return save_json_file(df, HR_QUERIES_FILE_PATH)

def load_hr_requests(): return load_json_file(HR_REQUESTS_FILE_PATH, default_columns=["ID", "HR Code", "Employee Code", "Employee Name", "Request", "File Attached", "Status", "Response", "Response File", "Date Sent", "Date Responded"])
def save_hr_requests(df):
    df = df.copy()
    for c in ["Date Sent", "Date Responded"]:
        if c in df.columns: df[c] = pd.to_datetime(df[c], errors="coerce").astype(str)
    [cite_start]if "ID" in df.columns: [cite: 302]
        df["ID"] = pd.to_numeric(df["ID"], errors="coerce")
        if df["ID"].isna().any():
            mx = int(df["ID"].max(skipna=True)) if not df["ID"].isna().all() else 0
            [cite_start]for i in df[df["ID"].isna()].index: mx += 1; df.at[i, "ID"] = mx [cite: 303]
        df["ID"] = df["ID"].astype(int)
    return save_json_file(df, HR_REQUESTS_FILE_PATH)

def save_request_file(f, ec, rid):
    os.makedirs("hr_request_files", exist_ok=True)
    fn = f"req_{rid}_emp_{ec}.{f.name.split('.')[-1].lower()}"
    with open(os.path.join("hr_request_files", fn), "wb") as out: out.write(f.getbuffer())
    return fn

def save_response_file(f, ec, rid):
    os.makedirs("hr_response_files", exist_ok=True)
    fn = f"resp_{rid}_emp_{ec}.{f.name.split('.')[-1].lower()}"
    [cite_start]with open(os.path.join("hr_response_files", fn), "wb") as out: out.write(f.getbuffer()) [cite: 304]
    return fn

def page_ask_employees(user):
    st.subheader("📤 Ask Employees")
    [cite_start]df = st.session_state.get("df", pd.DataFrame()) [cite: 305]
    if df.empty: st.error("No data."); return
    col_map = {c.lower().strip(): c for c in df.columns}
    [cite_start]c_col = next((col_map[opt] for opt in ["employee_code", "employee code", "code"] if opt in col_map), None) [cite: 306]
    [cite_start]n_col = next((col_map[opt] for opt in ["employee_name", "employee name", "name"] if opt in col_map), None) [cite: 307]
    if not c_col or not n_col: st.error("Columns missing."); return
    st.markdown("### 🔍 Search Employee")
    [cite_start]search = st.text_input("Search...") [cite: 308]
    opts = df[[c_col, n_col]].copy()
    opts["Display"] = opts[n_col] + " (Code: " + opts[c_col].astype(str) + ")"
    [cite_start]if search: opts = opts[opts[n_col].str.contains(search, case=False, na=False) | opts[c_col].astype(str).str.contains(search, case=False, na=False)] [cite: 309]
    if opts.empty: st.warning("No matches."); return
    [cite_start]sel_row = opts.iloc[0] if len(opts) == 1 else opts[opts["Display"] == st.selectbox("Select", opts["Display"].tolist())].iloc[0] [cite: 310]
    st.success(f"Selected: {sel_row[n_col]}")
    req, up = st.text_area("Request"), st.file_uploader("File")
    if st.button("Send Request"):
        [cite_start]if not req.strip(): st.warning("Empty request."); return [cite: 311]
        hr_c, r_df = str(user.get("Employee Code", "N/A")).replace(".0", ""), load_hr_requests()
        nid = int(r_df["ID"].max()) + 1 if not r_df.empty else 1
        fn = save_request_file(up, sel_row[c_col], nid) if up else ""
        [cite_start]nr = pd.DataFrame([{"ID": nid, "HR Code": hr_c, "Employee Code": sel_row[c_col], "Employee Name": sel_row[n_col], "Request": req.strip(), "File Attached": fn, "Status": "Pending", "Response": "", "Response File": "", "Date Sent": pd.Timestamp.now(), "Date Responded": pd.NaT}]) [cite: 312, 313]
        save_hr_requests(pd.concat([r_df, nr], ignore_index=True))
        [cite_start]add_notification(sel_row[c_col], "", f"HR request (ID: {nid})"); st.success("Sent!"); st.rerun() [cite: 314]

def page_request_hr(user):
    st.subheader("📥 Request HR")
    user_code, r_df = str(user.get("Employee Code", "N/A")).replace(".0", ""), load_hr_requests()
    [cite_start]if r_df.empty: st.info("No requests."); return [cite: 315]
    u_reqs = r_df[r_df["Employee Code"].astype(str) == user_code].sort_values("Date Sent", ascending=False).reset_index(drop=True)
    if u_reqs.empty: st.info("No requests for you."); return
    for i, r in u_reqs.iterrows():
        st.markdown(f"### 📄 ID: {r['ID']}"); st.write(f"**Request:** {r['Request']}")
        [cite_start]ds = r.get("Date Sent") [cite: 316]
        [cite_start]st.write(f"**Date Sent:** {pd.to_datetime(ds).strftime('%d-%m-%Y %H:%M') if pd.notna(ds) else 'N/A'}") [cite: 317]
        fa = r.get("File Attached")
        if pd.notna(fa) and str(fa).strip():
            fp = os.path.join("hr_request_files", fa)
            if os.path.exists(fp):
                [cite_start]with open(fp, "rb") as f: st.download_button("📥 Attached File", f, file_name=fa, key=f"dl_req_{i}") [cite: 318]
        if r["Status"] == "Completed":
            [cite_start]st.success("✅ Completed.") [cite: 319]
            rf = r.get("Response File")
            if pd.notna(rf) and str(rf).strip():
                rp = os.path.join("hr_response_files", rf)
                if os.path.exists(rp):
                    [cite_start]with open(rp, "rb") as f: st.download_button("📥 Your Response", f, file_name=rf, key=f"dl_resp_{i}") [cite: 320]
            continue
        [cite_start]st.markdown("---") [cite: 321]
        rt, rf_up = st.text_area("Response", key=f"rt_{i}"), st.file_uploader("File", key=f"rf_{i}")
        if st.button("Submit Response", key=f"sb_{i}"):
            if not rt.strip() and not rf_up: st.warning("Provide text or file."); continue
            [cite_start]r_df.loc[r_df["ID"] == r["ID"], ["Response", "Status", "Date Responded"]] = [rt.strip(), "Completed", pd.Timestamp.now()] [cite: 322]
            if rf_up: r_df.loc[r_df["ID"] == r["ID"], "Response File"] = save_response_file(rf_up, user_code, r["ID"])
            [cite_start]save_hr_requests(r_df); add_notification("", "HR", f"Emp {user_code} response (ID {r['ID']})"); st.success("Sent!"); st.rerun() [cite: 323]

def page_recruitment(user):
    st.subheader("👥 Recruitment Management")
    [cite_start]if user.get("Title", "").upper() != "HR": st.error("HR only."); return [cite: 324]
    st.markdown(f'<div style="background-color:white; padding:12px; border-radius:8px; border:1px solid #05445E; margin-bottom:20px;"><h4>📝 Candidate Application Form</h4><p>Share this link: <a href="{GOOGLE_FORM_RECRUITMENT_LINK}" target="_blank">👉 Apply</a></p></div>', unsafe_allow_html=True)
    t_cv, t_db = st.tabs(["📄 CV Candidates", "📊 Recruitment Database"])
    with t_cv:
        [cite_start]up_cv, c_name = st.file_uploader("CV", type=["pdf", "doc", "docx"]), st.text_input("Name") [cite: 325]
        if up_cv and st.button("✅ Save CV"):
            try:
                fn = save_recruitment_cv(up_cv); st.success(f"Saved: {fn}")
                [cite_start]if c_name: add_notification("", "HR", f"New CV: {c_name}") [cite: 326]
                st.rerun()
            except Exception as e: st.error(f"Error: {e}")
        st.markdown("---")
        [cite_start]cvs = sorted(os.listdir(RECRUITMENT_CV_DIR), reverse=True) if os.path.exists(RECRUITMENT_CV_DIR) else [] [cite: 327]
        for cv in cvs:
            [cite_start]c1, c2 = st.columns([4, 1]); [cite: 328]
            [cite_start]c1.markdown(f"📄 `{cv}`"); [cite: 329]
            with c2:
                with open(os.path.join(RECRUITMENT_CV_DIR, cv), "rb") as f: st.download_button("📥", f, file_name=cv, key=f"dl_{cv}")
        if st.button("📦 Download ZIP"):
            z = "all_cvs.zip"
            with zipfile.ZipFile(z, 'w') as zipf:
                for cv in cvs: zipf.write(os.path.join(RECRUITMENT_CV_DIR, cv), cv)
            [cite_start]with open(z, "rb") as f: st.download_button("ZIP", f, file_name="Recruitment_CVs.zip"); [cite: 330]
    with t_db:
        up_db = st.file_uploader("Upload Google Form Data", type=["xlsx"])
        if up_db:
            try:
                [cite_start]ndf = pd.read_excel(up_db); st.session_state["rec_p"] = ndf.copy(); st.success("Loaded."); st.dataframe(ndf.head(10)) [cite: 331]
                [cite_start]if st.button("✅ Replace Database"): save_json_file(ndf, RECRUITMENT_DATA_FILE); st.success("Updated!"); st.rerun() [cite: 332]
            except Exception as e: st.error(f"Error: {e}")
        db = load_json_file(RECRUITMENT_DATA_FILE)
        if not db.empty:
            [cite_start]st.dataframe(db, use_container_width=True) [cite: 333]
            [cite_start]buf = BytesIO(); [cite: 334]
            with pd.ExcelWriter(buf, engine="openpyxl") as writer: db.to_excel(writer, index=False)
            st.download_button("📥 Download Database", data=buf.getvalue(), file_name="Recruitment_Data.xlsx")

def page_settings(user):
    st.subheader("⚙️ System Settings")
    [cite_start]if user.get("Title", "").upper() != "HR": st.error("HR only."); return [cite: 335]
    t3, t4 = st.tabs(["🧾 Templates", "💾 Backup"])
    with t3:
        [cite_start]up_t = st.file_uploader("Salary Template", type=["xlsx"]) [cite: 336]
        if up_t:
            with open("salary_template.xlsx", "wb") as f: f.write(up_t.getbuffer())
            st.success("Uploaded.")
        [cite_start]up_l = st.file_uploader("Logo", type=["png", "jpg"]) [cite: 337]
        if up_l:
            with open("logo.jpg", "wb") as f: f.write(up_l.getbuffer())
            st.success("Logo updated.")
    with t4:
        if st.button("Create Backup"):
            [cite_start]bn = f"backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.zip" [cite: 338]
            with zipfile.ZipFile(bn, "w") as z:
                for f in [DEFAULT_FILE_PATH, LEAVES_FILE_PATH, NOTIFICATIONS_FILE_PATH, HR_QUERIES_FILE_PATH, HR_REQUESTS_FILE_PATH, SALARIES_FILE_PATH]:
                    [cite_start]if os.path.exists(f): z.write(f) [cite: 339]
                if os.path.exists("employee_photos"):
                    [cite_start]for p in os.listdir("employee_photos"): z.write(os.path.join("employee_photos", p)) [cite: 340]
            [cite_start]with open(bn, "rb") as f: st.download_button("📥 Download ZIP", f, file_name=bn) [cite: 341]

def page_dashboard(user):
    st.subheader("Dashboard")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty: st.info("No data."); return
    [cite_start]cm = {c.lower(): c for c in df.columns} [cite: 342]
    d_col, h_col = cm.get("department"), cm.get("hire date") or cm.get("hire_date")
    nh = 0
    if h_col:
        try:
            df[h_col] = pd.to_datetime(df[h_col], errors="coerce")
            nh = df[df[h_col] >= (pd.Timestamp.now() - pd.Timedelta(days=30))].shape[0]
        [cite_start]except: nh = 0 [cite: 343]
    c1, c2, c3 = st.columns(3)
    c1.metric("Total", df.shape[0]); c2.metric("Depts", df[d_col].nunique() if d_col else 0); c3.metric("New Hires", nh)
    if d_col:
        [cite_start]dc = df[d_col].fillna("Unknown").value_counts().reset_index() [cite: 344]
        dc.columns = ["Department", "Count"]; st.table(dc)
    [cite_start]buf = BytesIO(); [cite: 345]
    with pd.ExcelWriter(buf, engine="openpyxl") as w: df.to_excel(w, index=False)
    st.download_button("Download All Excel", data=buf.getvalue(), file_name="employees.xlsx")
    if st.button("Push to GitHub"):
        s, p = save_and_maybe_push(df, actor=user.get("Employee Name","HR"))
        if s:
            if p: st.success("Pushed.")
            elif GITHUB_TOKEN: st.warning("GitHub fail.")
            [cite_start]else: st.info("Token missing.") [cite: 346]

def page_reports(user):
    st.subheader("Reports")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty: st.info("No data."); return
    st.dataframe(df.head(200), use_container_width=True)
    [cite_start]buf = BytesIO(); [cite: 347]
    with pd.ExcelWriter(buf, engine="openpyxl") as w: df.to_excel(w, index=False)
    st.download_button("Export (Excel)", data=buf.getvalue(), file_name="report.xlsx")

def page_hr_inbox(user):
    st.subheader("📬 HR Inbox")
    h_df = load_hr_queries()
    if h_df.empty: st.info("No messages."); return
    [cite_start]try: h_df["ds_dt"] = pd.to_datetime(h_df["Date Sent"], errors="coerce"); h_df = h_df.sort_values("ds_dt", ascending=False).reset_index(drop=True) [cite: 348]
    except: h_df = h_df.reset_index(drop=True)
    for i, r in h_df.iterrows():
        [cite_start]ec, en, sb, ms, st_val = str(r.get('Employee Code', '')), r.get('Employee Name', ''), r.get('Subject', ''), r.get("Message", ''), r.get('Status', '') [cite: 349]
        dt = pd.to_datetime(r.get("Date Sent")).strftime('%d-%m-%Y %H:%M') if pd.notna(r.get("Date Sent")) else ""
        [cite_start]st.markdown(f'<div class="hr-message-card"><div class="hr-message-title">📌 {sb if sb else "No Subject"}</div><div class="hr-message-meta">👤 {en} — {ec} | 🕒 {dt} | 🏷️ {st_val}</div><div class="hr-message-body">{ms}</div>', unsafe_allow_html=True) [cite: 350, 351]
        if r.get("Reply"): st.markdown(f"**Existing reply:**\n{r['Reply']}")
        c1, c2 = st.columns([1, 4])
        [cite_start]if c1.button("Close", key=f"c_{i}"): [cite: 352]
            h_df.at[i, "Status"], h_df.at[i, "Date Replied"] = "Closed", pd.Timestamp.now()
            [cite_start]save_hr_queries(h_df); st.success("Closed."); st.rerun() [cite: 353]
        rt = st.text_area("Reply", key=f"r_{i}")
        cl1, cl2, cl3 = st.columns([2, 2, 1])
        [cite_start]if cl1.button("Send Reply", key=f"s_{i}"): [cite: 354]
            [cite_start]h_df.at[i, ["Reply", "Status", "Date Replied"]] = [rt, "Replied", pd.Timestamp.now()] [cite: 355]
            [cite_start]save_hr_queries(h_df); add_notification(ec, "", f"HR reply: {sb}"); st.success("Sent!"); st.rerun() [cite: 356]
        [cite_start]if cl2.button("Mark Closed", key=f"mc_{i}"): [cite: 357]
            h_df.at[i, ["Status", "Date Replied"]] = ["Closed", pd.Timestamp.now()]
            [cite_start]save_hr_queries(h_df); st.rerun() [cite: 358]
        [cite_start]if cl3.button("Delete", key=f"d_{i}"): [cite: 359]
            save_hr_queries(h_df.drop(i).reset_index(drop=True)); st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)

def page_ask_hr(user):
    st.subheader("💬 Ask HR")
    [cite_start]if user is None: st.error("Login required."); return [cite: 360]
    [cite_start]u_c = next((str(v).strip().replace(".0", "") for k, v in user.items() if k.lower().replace(" ", "").replace("_", "") in ["employeecode", "employee_code"]), None) [cite: 361]
    u_n = next((str(v).strip() for k, v in user.items() if k.lower().replace(" ", "").replace("_", "") in ["employeename", "employee_name", "name"]), u_c)
    h_df = load_hr_queries()
    with st.form("ask_hr_form"):
        [cite_start]sb, ms = st.text_input("Subject"), st.text_area("Message") [cite: 362]
        if st.form_submit_button("Send"):
            if not sb.strip() or not ms.strip(): st.warning("Required.")
            else:
                [cite_start]nr = pd.DataFrame([{"Employee Code": u_c, "Employee Name": u_n, "Subject": sb.strip(), "Message": ms.strip(), "Reply": "", "Status": "Pending", "ID": (int(h_df["ID"].max()) + 1) if not h_df.empty else 1, "Date Sent": pd.Timestamp.now(), "Date Replied": pd.NaT}]) [cite: 363, 364]
                [cite_start]if save_hr_queries(pd.concat([h_df, nr], ignore_index=True)): [cite: 365]
                    [cite_start]add_notification("", "HR", f"New ask from {u_n}"); st.success("Sent!"); st.rerun() [cite: 366, 367]
    u_msgs = h_df[h_df["Employee Code"].astype(str) == u_c].sort_values("Date Sent", ascending=False)
    for i, r in u_msgs.iterrows():
        [cite_start]st.markdown(f'<div class="hr-message-card"><div class="hr-message-title">📌 {r["Subject"]}</div><div class="hr-message-meta">🏷️ {r["Status"]}</div><div class="hr-message-body">{r["Message"]}</div></div>', unsafe_allow_html=True) [cite: 368]
        [cite_start]if r.get("Reply") and str(r["Reply"]).strip(): [cite: 369]
            [cite_start]st.markdown(f'<div style="background-color:#e0f2fe; padding:10px; border-radius:6px;">{r["Reply"]}</div>', unsafe_allow_html=True) [cite: 370, 371]

def main():
    if "df" not in st.session_state: ensure_session_df()
    if "logged_in" not in st.session_state: st.session_state["logged_in"], st.session_state["user"] = False, None
    if not st.session_state["logged_in"]:
        [cite_start]st.sidebar.markdown('<div class="sidebar-title">🔐 Login</div>', unsafe_allow_html=True) [cite: 372]
        with st.sidebar.form("login"):
            c, p = st.text_input("Code"), st.text_input("Pass", type="password")
            if st.form_submit_button("Login"):
                [cite_start]df = st.session_state.get("df", pd.DataFrame()) [cite: 373]
                [cite_start]if df.empty: st.error("Data missing.") [cite: 374]
                else:
                    u = login(df, c, p)
                    [cite_start]if u: st.session_state["logged_in"], st.session_state["user"] = True, u; st.rerun() [cite: 375]
                    else: st.error("Fail.")
        [cite_start]if st.sidebar.button("🔑 Password Reset"): st.session_state["show_fp"] = True; st.rerun() [cite: 376]
        if st.session_state.get("show_fp"): page_forgot_password()
        return
    [cite_start]u = st.session_state["user"]; ut = str(u.get("Title", "")).strip().upper() [cite: 377]
    is_hr, is_bum, is_am, is_dm, is_mr, is_sp = ut=="HR", ut=="BUM", ut=="AM", ut=="DM", ut=="MR", ut in ["ASSOCIATE COMPLIANCE", "FIELD COMPLIANCE SPECIALIST", "COMPLIANCE MANAGER"]
    [cite_start]if is_hr: pages = ["Dashboard", "Reports", "HR Manager", "HR Inbox", "Employee Photos", "Ask Employees", "Recruitment", "🎓 Employee Development (HR View)", "Notifications", "Structure", "Salary Monthly", "Salary Report", "Settings"] [cite: 378]
    elif is_bum: pages = ["My Profile", "Team Leaves", "🎓 Team Development", "Ask HR", "Request HR", "Notifications", "Structure", "Salary Monthly"]
    [cite_start]elif is_am or is_dm: pages = ["My Profile", "🎓 Team Development", "Ask HR", "Request HR", "Notifications", "Structure", "Salary Monthly"] [cite: 379]
    elif is_mr: pages = ["My Profile", "🚀 IDB", "🌱 Self Development", "Notify Compliance", "Ask HR", "Request HR", "Notifications", "Structure", "Salary Monthly"]
    [cite_start]elif is_sp: pages = ["My Profile", "Leave Request", "Ask HR", "Request HR", "Notifications", "Structure", "Salary Monthly", "📋 Report Compliance"] [cite: 380]
    else: pages = ["My Profile", "Ask HR", "Request HR", "Notifications", "Structure", "Salary Monthly"]
    st.sidebar.markdown('<div class="sidebar-title">HR SYSTEM</div>', unsafe_allow_html=True)
    cur = st.sidebar.radio("Go to", pages); un = get_unread_count(u)
    if un > 0: st.sidebar.markdown(f'<div class="notification-bell">{un}</div>', unsafe_allow_html=True)
    st.sidebar.markdown("---")
    [cite_start]st.sidebar.markdown(f"👤 {u.get('Employee Name')}\n\n🔖 {ut}\n\n🆔 {u.get('Employee Code')}") [cite: 381]
    if st.sidebar.button("🚪 Logout"): st.session_state["logged_in"] = False; st.rerun()
    if cur == "Dashboard": page_dashboard(u)
    elif cur == "Reports": page_reports(u)
    [cite_start]elif cur == "HR Manager": page_hr_manager(u) if is_hr else st.error("HR only.") [cite: 382, 383]
    elif cur == "HR Inbox": page_hr_inbox(u) if is_hr else st.error("HR only.")
    [cite_start]elif cur == "Employee Photos": page_employee_photos(u) if is_hr else st.error("HR only.") [cite: 384]
    elif cur == "Ask Employees": page_ask_employees(u) if is_hr else st.error("HR only.")
    [cite_start]elif cur == "Recruitment": page_recruitment(u) if is_hr else st.error("HR only.") [cite: 385]
    elif cur == "🎓 Employee Development (HR View)": page_hr_development(u) if is_hr else st.error("HR only.")
    [cite_start]elif cur == "🎓 Team Development": page_manager_development(u) if (is_bum or is_am or is_dm) else st.error("Managers only.") [cite: 386, 387]
    elif cur == "My Profile": page_my_profile(u)
    [cite_start]elif cur == "Team Leaves": page_manager_leaves(u) if (is_bum or is_am or is_dm) else st.error("Managers only.") [cite: 388]
    elif cur == "Leave Request": page_leave_request(u)
    elif cur == "Ask HR": page_ask_hr(u)
    elif cur == "Request HR": page_request_hr(u)
    [cite_start]elif cur == "Notify Compliance": page_notify_compliance(u) if is_mr else st.error("MR only.") [cite: 389]
    [cite_start]elif cur == "📋 Report Compliance": page_report_compliance(u) if (is_sp or is_bum or is_am or is_dm) else st.error("Auth only.") [cite: 390]
    elif cur == "🚀 IDB": page_idb_mr(u) if is_mr else st.error("MR only.")
    [cite_start]elif cur == "🌱 Self Development": page_self_development(u) if is_mr else st.error("MR only.") [cite: 391]
    elif cur == "Notifications": page_notifications(u)
    elif cur == "Structure": page_directory(u)
    elif cur == "Salary Monthly": page_salary_monthly(u)
    [cite_start]elif cur == "Salary Report": page_salary_report(u) if is_hr else st.error("HR only.") [cite: 392]
    elif cur == "Settings": page_settings(u) if is_hr else st.error("HR only.")

if __name__ == "__main__": main()
