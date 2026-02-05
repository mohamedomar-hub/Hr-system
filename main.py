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
#  🔐 NEW: For salary encryption 
from cryptography.fernet import Fernet, InvalidToken
import hashlib

# ============================
#  COMPLIANCE MESSAGES FILE PATH 
# ============================
COMPLIANCE_MESSAGES_FILE = "compliance_messages.json"
# ============================
#  IDB REPORTS FILE PATH 
# ============================
IDB_REPORTS_FILE = "idb_reports.json"
# ============================
#  SALARY ENCRYPTION SETUP (Secure: from Streamlit Secrets) 
# ============================
SALARY_SECRET_KEY = st.secrets.get("SALARY_SECRET_KEY")
if not SALARY_SECRET_KEY:
    st.error("❌ Missing SALARY_SECRET_KEY in Streamlit Secrets.")
    st.stop()

def get_fernet_from_secret(secret: str) -> Fernet:
    key = hashlib.sha256(secret.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(key) 
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
         if not encrypted_str or pd.isna(encrypted_str):
            return 0.0
        # Try to decode as base64 first (indicating it's encrypted)
    try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_str.encode())
            decrypted = fernet_salary.decrypt(encrypted_bytes)
            return float(decrypted.decode())
        except Exception:
            #  If decoding fails, assume it's plain text (e.g., transitional file)
            return float(encrypted_str)
    except (InvalidToken, ValueError, Exception):
        return 0.0

# ============================
#  🆕 FUNCTION: Load & Save Compliance Messages
# ============================
def load_compliance_messages():
    return load_json_file(COMPLIANCE_MESSAGES_FILE, default_columns=[
        "ID", "MR Code", "MR Name", "Compliance Recipient", "Compliance Code",
        "Manager Code", "Manager Name", "Message", "Timestamp", "Status"
    ])

def save_compliance_messages(df):
    df = df.copy()
     if "Timestamp" in df.columns:
        df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce").astype(str)
    if "ID" in df.columns:
        df["ID"] = pd.to_numeric(df["ID"], errors="coerce")
        if df["ID"].isna().any():
            existing_max = int(df["ID"].max()) if not df["ID"].isna().all() else 0
            for idx in df[df["ID"].isna()].index:
                existing_max += 1
                 df.at[idx, "ID"] = existing_max
        df["ID"] = df["ID"].astype(int)
    return save_json_file(df, COMPLIANCE_MESSAGES_FILE)

# ============================
#  🆕 FUNCTION: Sanitize employee data (APPLY YOUR 3 RULES)
# ============================
def sanitize_employee_data(df: pd.DataFrame) -> pd.DataFrame:
    """
    Applies the following rules:
    1.  Drop 'annual_leave_balance' column if exists.
    2. Drop 'monthly_salary' column if exists.
    3.  Hide 'E-Mail' for anyone NOT in ['BUM', 'AM', 'DM'].
    """
    df = df.copy()
    # Rule 1 & 2: drop sensitive columns if present
    sensitive_columns_to_drop = ['annual_leave_balance', 'monthly_salary']
    for col in sensitive_columns_to_drop:
        if col in df.columns:
            df = df.drop(columns=[col])
    # Rule 3: hide email except for BUM, AM, DM
    if 'E-Mail' in df.columns and 'Title' in df.columns:
        allowed_titles = {'BUM', 'AM', 'DM'}
         mask = ~df['Title'].astype(str).str.upper().isin(allowed_titles)
        df.loc[mask, 'E-Mail'] = ""  # blank out, not delete column
    return df

# ============================
#  🆕 FUNCTION: Load & Save IDB Reports (FIXED: Added Employee Name) [: 9]
# ============================
def load_idb_reports():
    return load_json_file(IDB_REPORTS_FILE, default_columns=[
        "Employee Code", "Employee Name", "Selected Departments", "Strengths", "Development Areas", "Action Plan", "Updated At"
    ])

def save_idb_report(employee_code, employee_name, selected_deps, strengths, development, action):
    reports = load_idb_reports()
    now = pd.Timestamp.now().isoformat()
    new_row = {
         "Employee Code": employee_code, 
        "Employee Name": employee_name,  # ✅ FIXED: Added Employee Name
        "Selected Departments": selected_deps,
        "Strengths": strengths,
        "Development Areas": development,
        "Action Plan": action,
        "Updated At": now
    }
    # إذا كان التقرير موجودًا، نستبدله
    reports = reports[reports["Employee Code"] != employee_code]
     reports = pd.concat([reports, pd.DataFrame([new_row])], ignore_index=True) 
    return save_json_file(reports, IDB_REPORTS_FILE)

# ============================
#  Load Configuration from config.json 
# ============================
def load_config():
    default_config = {
        "file_paths": {
            "employees": "employees.json",
            "leaves": "leaves.json",
            "notifications": "notifications.json",
            "hr_queries": "hr_queries.json",
            "hr_requests": "hr_requests.json",
             "salaries": "salaries.json", 
            "recruitment_data": "recruitment_data.json"
        },
        "github": {
            "repo_owner": "mohamedomar-hub",
            "repo_name": "hr-system",
            "branch": "main"
        },
        "recruitment": {
             "cv_dir": "recruitment_cvs", 
            "google_form_link": "https://docs.google.com/forms/e/1FAIpQLSccvOVVSrKDRAF-4rOt0N_rEr8SmQ2F6cVRSwk7RGjMoRhpLQ/viewform"
        },
        "system": {
            "logo_path": "logo.jpg",
            "default_annual_leave_days": 21
        }
    }
    try:
        with open("config.json", "r", encoding="utf-8") as f:
             user_config = json.load(f) [: 14]
        def deep_merge(a, b):
            for k, v in b.items():
                if isinstance(v, dict) and k in a and isinstance(a[k], dict):
                    deep_merge(a[k], v)
                else:
                     a[k] = v [: 15]
            return a
        return deep_merge(default_config, user_config)
    except FileNotFoundError:
         st.warning("config.json not found. Using default settings.")
        return default_config
    except Exception as e:
        st.error(f"Error loading config.json: {e}. Using defaults.")
        return default_config

CONFIG = load_config()
# ============================
#  Configuration from CONFIG [: 16]
# ============================
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
#  🔐 Secure Password Management (bcrypt-based)
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
         emp_code = str(row.get("Employee Code", "")).strip().replace(".0", "")
        pwd = str(row.get("Password", "")).strip()
        if emp_code and pwd and emp_code not in hashes:
            hashes[emp_code] = hash_password(pwd)
    save_password_hashes(hashes)
# ============================
#  JSON File Helpers (REPLACES EXCEL) — ✅ MODIFIED TO ENCRYPT SALARIES BEFORE SAVING [: 18]
# ============================
def load_json_file(filepath, default_columns=None):
    if os.path.exists(filepath):
        try:
             with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            df = pd.DataFrame(data)
            # 🆕 Apply sanitization immediately on load
            return sanitize_employee_data(df)
        except Exception:
            return pd.DataFrame(columns=default_columns) if default_columns else pd.DataFrame()
    else:
         if default_columns:
            return pd.DataFrame(columns=default_columns)
        return pd.DataFrame()
def save_json_file(df, filepath):
    try:
        # 🆕 Sanitize BEFORE saving
        df_sanitized = sanitize_employee_data(df)
        # 🔒 Encrypt sensitive salary columns BEFORE saving (even locally)
        sensitive_cols = ["Basic Salary", "KPI Bonus", "Deductions", "Net Salary"]
        df_copy = df_sanitized.copy()
         for col in sensitive_cols:
            if col in df_copy.columns:
                df_copy[col] = df_copy[col].apply(encrypt_salary_value)
        # Save encrypted version to disk
        data = df_copy.where(pd.notnull(df_copy), None).to_dict(orient='records')
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
         return True
    except Exception:
        return False
# ============================
#  Styling - Modern Light Mode CSS (Updated per your request)
# ============================
st.set_page_config(page_title="HRAS — Averroes Admin", page_icon="👥", layout="wide")
hide_streamlit_style = """
<style>
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
 div[data-testid="stDeployButton"] { display: none; }
</style>
"""
st.markdown(hide_streamlit_style, unsafe_allow_html=True)
#  ✅ تم دمج التنسيق الجديد للـ Sidebar بالكامل وإصلاح ألوان الإحصائيات
updated_css = """
<style>
/* ========== COLORS SYSTEM ========== */
:root {
 --primary: #05445E;
--secondary: #0A5C73;
--sky-blue: #1E88E5; /* أزرق سماوي */
--hover-red: #dc2626; /* أحمر للهوفر */
--text-main: #2E2E2E;
--text-muted: #6B7280;
--card-bg: #FFFFFF;
 --soft-bg: #F2F6F8;
--border-soft: #E5E7EB;
}

/* ========== TOP PROFILE CARD ========== */
.profile-card-top {
    background: linear-gradient(135deg, var(--primary), var(--secondary));
     color: white !important;
    padding: 18px;
    border-radius: 12px;
    margin-bottom: 20px;
    text-align: center;
    box-shadow: 0 4px 10px rgba(0,0,0,0.2);
     border: 1px solid rgba(255,255,255,0.1);
}
.profile-card-top h4 { color: white !important; margin: 0; font-size: 1.15rem; font-weight: 700; }
 .profile-card-top p { color: white !important; margin: 4px 0; font-size: 1.15rem; font-weight: 700; }

/* ========== SIDEBAR NAVIGATION BOXES ========== */
[data-testid="stSidebar"] .stRadio div[role="radiogroup"] {
     gap: 12px;
    padding-top: 10px;
}
[data-testid="stSidebar"] .stRadio div[role="radiogroup"] label {
    background-color: var(--sky-blue) !important;
    border-radius: 10px !important;
     padding: 12px 20px !important;
    margin-bottom: 2px !important;
    transition: all 0.3s ease-in-out !important;
    border: none !important;
    display: block !important;
     width: 100% !important;
}
[data-testid="stSidebar"] .stRadio div[role="radiogroup"] label div[data-testid="stMarkdownContainer"] p {
    color: #FFFFFF !important;
    font-weight: 600 !important;
     font-size: 1rem !important;
    text-align: center;
}
[data-testid="stSidebar"] .stRadio div[role="radiogroup"] label:hover {
    background-color: var(--hover-red) !important;
     transform: scale(1.03);
}
[data-testid="stSidebar"] .stRadio div[role="radiogroup"] label div[role="presentation"] {
     display: none !important;
}
[data-testid="stSidebar"] .stRadio div[role="radiogroup"] label[data-checked="true"] {
    background-color: var(--primary) !important;
     border: 2px solid white !important;
}

/* ========== GENERAL TEXT & CARDS ========== */
 html, body, p, span, .stMarkdown p { color: #2E2E2E !important; }
 h1, h2, h3, h4, h5 { color: var(--primary) !important; font-weight: 600; }

/* إصلاح أرقام الإحصائيات (st.metric) */
[data-testid="stMetricValue"] {
     color: #2E2E2E !important;
}
[data-testid="stMetricLabel"] p {
    color: var(--primary) !important;
    font-weight: bold;
}

.hr-message-card { 
     background-color: #FFFFFF;
    border-left: 5px solid var(--primary); 
    padding: 15px; 
    margin: 10px 0; 
    border-radius: 10px;
     box-shadow: 0 4px 12px rgba(0,0,0,0.08);
}

.stButton > button { 
    background-color: #1E88E5 !important;
    color: white !important; 
    border: none !important; 
     font-weight: 600;
    padding: 0.5rem 1rem; 
    border-radius: 6px; 
}
.stButton > button:hover { background-color: #dc2626 !important; }

 [data-testid="stAppViewContainer"] { background-color: #F2F2F2 !important; }

[data-testid="stSidebar"] .stMarkdown p:not(.profile-card-top p) { font-weight: 500; }
</style>
"""
st.markdown(updated_css, unsafe_allow_html=True)
# ============================
#  ✅ MODIFIED: External Password Change Page (No Login Required)
# ============================
def page_forgot_password():
    st.subheader("🔐 Change Password (No Login Required)")
    st.info("Enter your Employee Code. If your password was reset by HR, you can set a new one directly.")
    with st.form("external_password_change"):
        emp_code = st.text_input("Employee Code")
        new_pwd = st.text_input("New Password", type="password")
        confirm_pwd = st.text_input("Confirm New Password", type="password")
         submitted = st.form_submit_button("Set New Password")
    if submitted:
            if not emp_code.strip() or not new_pwd or not confirm_pwd:
                st.error("All fields are required.")
            elif new_pwd != confirm_pwd:
                st.error("New password and confirmation do not match.")
            else:
                 emp_code_clean = emp_code.strip().replace(".0", "")
                hashes = load_password_hashes()
                df = st.session_state.get("df", pd.DataFrame())
                if df.empty:
                     st.error("Employee data not loaded.")
                    return
                col_map = {c.lower().strip(): c for c in df.columns}
                code_col = col_map.get("employee_code") or col_map.get("employee code")
                if not code_col:
                     st.error("Employee code column not found in dataset.")
                    return
                df[code_col] = df[code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
                if emp_code_clean not in df[code_col].values:
                     st.error("Employee code not found in the company database.")
                    return
                hashes[emp_code_clean] = hash_password(new_pwd)
                save_password_hashes(hashes)
                 st.success("✅ Your password has been set successfully. You can now log in.")
                add_notification("", "HR", f"Employee {emp_code_clean} set a new password after reset.")
                st.rerun()
# ============================
#  Photo & Recruitment Helpers
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
def save_recruitment_cv(uploaded_file):
    os.makedirs(RECRUITMENT_CV_DIR, exist_ok=True)
    ext = uploaded_file.name.split(".")[-1].lower()
    if ext not in ["pdf", "doc", "docx"]:
        raise ValueError("Only PDF or DOC/DOCX files allowed for CV.")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"cv_{timestamp}.{ext}"
    filepath = os.path.join(RECRUITMENT_CV_DIR, filename)
    with open(filepath, "wb") as f:
         f.write(uploaded_file.getbuffer())
    return filename
# ============================
#  GitHub helpers (JSON version)
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
            data = json.loads(file_content.decode('utf-8'))
            df = pd.DataFrame(data)
            return sanitize_employee_data(df)
        else:
            return pd.DataFrame()
    except Exception:
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
    except Exception:
        return None
def upload_json_to_github(filepath, data_list, commit_message):
    if not GITHUB_TOKEN:
        return False
     try:
        df_temp = pd.DataFrame(data_list)
        df_sanitized = sanitize_employee_data(df_temp)
        data_list_sanitized = df_sanitized.to_dict(orient='records')
        sensitive_cols = ["Basic Salary", "KPI Bonus", "Deductions", "Net Salary"]
        data_list_copy = [row.copy() for row in data_list_sanitized]
        for item in data_list_copy:
            for col in sensitive_cols:
                 if col in item and item[col] is not None:
                    if isinstance(item[col], str):
                        try:
                            base64.urlsafe_b64decode(item[col].encode())
                             continue
                        except Exception:
                            item[col] = encrypt_salary_value(item[col])
                    else:
                         item[col] = encrypt_salary_value(item[col])
        json_content = json.dumps(data_list_copy, ensure_ascii=False, indent=2).encode('utf-8')
        file_content_b64 = base64.b64encode(json_content).decode("utf-8")
        url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{filepath}"
        sha = get_file_sha(filepath)
        payload = {"message": commit_message, "content": file_content_b64, "branch": BRANCH}
        if sha:
            payload["sha"] = sha
         put_resp = requests.put(url, headers=github_headers(), json=payload, timeout=60)
        return put_resp.status_code in (200, 201)
    except Exception:
        return False
# ============================
#  Helpers
# ============================
def ensure_session_df():
    if "df" not in st.session_state:
        df_loaded = load_employee_data_from_github()
        if not df_loaded.empty:
            st.session_state["df"] = df_loaded
        else:
             st.session_state["df"] = load_json_file(FILE_PATH)
# ============================
#  Login & Save Helpers
# ============================
def login(df, code, password):
    if df is None or df.empty:
        return None
    col_map = {c.lower().strip(): c for c in df.columns}
    code_col = col_map.get("employee_code") or col_map.get("employee code")
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
    return save_json_file(df, FILE_PATH)
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
        "Employee Code", "Manager Code", "Start Date", "End Date",
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
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors="coerce").dt.strftime("%Y-%m-%d")
    return save_json_file(df, LEAVES_FILE_PATH)
# ============================
#  Notifications System
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
    new_row = pd.DataFrame([{
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
        (notifications["Recipient Title"].astype(str) .str.upper() == user_title)
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
def format_relative_time(ts):
    if not ts or pd.isna(ts):
        return "N/A"
    try:
        dt = pd.to_datetime(ts)
         now = pd.Timestamp.now()
        diff = now - dt
        seconds = int(diff.total_seconds())
        if seconds < 60:
            return "الآن"
        elif seconds < 3600:
            return f"قبل {seconds // 60} دقيقة"
        elif seconds < 86400:
             return f"قبل {seconds // 3600} ساعة"
        else:
            return dt.strftime("%d-%m-%Y")
    except Exception:
        return str(ts)
# ============================
#  page_notifications
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
         if key == "Employee Code":
            user_code = str(val).strip().replace(".0", "")
        if key == "Title":
            user_title = str(val).strip().upper()
    if not user_code and not user_title:
        return
    user_notifs = notifications[
        (notifications["Recipient Code"].astype(str) == user_code) |
        (notifications["Recipient Title"].astype(str) .str.upper() == user_title)
    ].copy()
    if user_notifs.empty:
        st.info("No notifications for you.")
        return
    user_notifs = user_notifs.sort_values("Timestamp", ascending=False).reset_index(drop=True)
    filter_option = st.radio(
        "Filter notifications:",
        ["All", "Unread", "Read"],
        index=1,
        horizontal=True,
        key="notif_filter"
    )
    if filter_option == "Unread":
         filtered_notifs = user_notifs[~user_notifs["Is Read"]]
    elif filter_option == "Read":
        filtered_notifs = user_notifs[user_notifs["Is Read"]]
    else:
        filtered_notifs = user_notifs.copy()
    if not user_notifs[user_notifs["Is Read"] == False].empty:
        col1, col2 = st.columns([4, 1])
        with col2:
            if st.button("✅ Mark all as read", key="mark_all_read_btn"):
                 mark_all_as_read(user)
                st.success("All notifications marked as read.")
                st.rerun()
    if filtered_notifs.empty:
        st.info(f"No {filter_option.lower()} notifications.")
        return
    for idx, row in filtered_notifs.iterrows():
        if "approved" in str(row["Message"]).lower():
            icon = "✅"
             color = "#059669"
            bg_color = "#f0fdf4"
        elif "rejected" in str(row["Message"]).lower():
            icon = "❌"
            color = "#dc2626"
            bg_color = "#fef2f2"
        else:
             icon = "📝"
            color = "#05445E"
            bg_color = "#f8fafc"
        status_badge = "✅" if row["Is Read"] else "🆕"
        time_formatted = format_relative_time(row["Timestamp"])
        st.markdown(f"""
 <div style="background-color: {bg_color}; border-left: 5px solid {color}; padding: 15px; margin: 10px 0; border-radius: 10px; box-shadow: 0 4px 12px rgba(0,0,0,0.08);">
 <div style="display: flex; justify-content: space-between; align-items: flex-start;">
<div style="display: flex; align-items: center; gap: 10px; flex: 1;">
<span style="font-size: 1.3rem; color: {color};">{icon}</span>
<div>
 <div style="color: {color}; font-weight: bold; font-size: 1.05rem;"> {status_badge} {row['Message']} </div>
<div style="color: #666666; font-size: 0.9rem; margin-top: 4px;"> • {time_formatted} </div>
</div>
</div>
</div>
</div>
""", unsafe_allow_html=True)
        st.markdown("---")
# ============================
#  page_manager_leaves — Fully Implemented & FIXED
# ============================
def page_manager_leaves(user):
    st.subheader("📅 Team Leave Requests")
    manager_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    if not manager_code:
        st.error("Your Employee Code not found.")
        return
    leaves_df = load_leaves_data()
    if leaves_df.empty:
        st.info("No leave requests in the system.")
         return
    leaves_df["Manager Code"] = leaves_df["Manager Code"].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
    team_leaves = leaves_df[leaves_df["Manager Code"] == manager_code].copy()
    if team_leaves.empty:
        st.info("No leave requests from your team.")
        return
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
             st.markdown(f"**Employee**: {emp_display} | **Dates**: {row['Start Date']} → {row['End Date']} | **Type**: {row['Leave Type']}")
            st.write(f"**Reason**: {row['Reason']}")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("✅ Approve", key=f"app_{idx}_{row['Employee Code']}"):
                     leaves_df.at[leaves_df[leaves_df["Manager Code"] == manager_code].index[leaves_df[leaves_df["Manager Code"] == manager_code]["Employee Code"] == row["Employee Code"]].tolist()[idx], "Status"] = "Approved"
                    leaves_df.at[leaves_df[leaves_df["Manager Code"] == manager_code].index[leaves_df[leaves_df["Manager Code"] == manager_code]["Employee Code"] == row["Employee Code"]].tolist()[idx], "Decision Date"] = pd.Timestamp.now()
                    save_leaves_data(leaves_df)
                    add_notification(row['Employee Code'], "", "Your leave request has been approved!")
                     st.success("Approved!")
                    st.rerun()
            with col2:
                if st.button("❌ Reject", key=f"rej_{idx}_{row['Employee Code']}"):
                    comment = st.text_input("Comment (optional)", key=f"com_{idx}_{row['Employee Code']}")
                     leaves_df.at[leaves_df[leaves_df["Manager Code"] == manager_code].index[leaves_df[leaves_df["Manager Code"] == manager_code]["Employee Code"] == row["Employee Code"]].tolist()[idx], "Status"] = "Rejected"
                    leaves_df.at[leaves_df[leaves_df["Manager Code"] == manager_code].index[leaves_df[leaves_df["Manager Code"] == manager_code]["Employee Code"] == row["Employee Code"]].tolist()[idx], "Decision Date"] = pd.Timestamp.now()
                    leaves_df.at[leaves_df[leaves_df["Manager Code"] == manager_code].index[leaves_df[leaves_df["Manager Code"] == manager_code]["Employee Code"] == row["Employee Code"]].tolist()[idx], "Comment"] = comment
                     save_leaves_data(leaves_df)
                     msg = f"Your leave request was rejected. Comment: {comment}" if comment else "Your leave request was rejected."
                    add_notification(row['Employee Code'], "", msg)
                    st.success("Rejected!")
                    st.rerun()
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
        buf = BytesIO()
        with pd.ExcelWriter(buf, engine="openpyxl") as writer:
            all_leaves[["Employee Name", "Start Date", "End Date", "Leave Type", "Status", "Comment"]].to_excel(writer, index=False)
        buf.seek(0)
        st.download_button(
            "📥 Download Full Team Leave History",
             data=buf,
            file_name=f"Team_Leaves_{manager_code}.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
    else:
        st.info("No leave history for your team.")
# ============================
#  Salary Monthly Page
# ============================
def page_salary_monthly(user):
    st.subheader("Monthly Salaries")
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    try:
        if not os.path.exists(SALARIES_FILE_PATH):
             st.error(f"❌ File '{SALARIES_FILE_PATH}' not found.")
            return
        salary_df = load_json_file(SALARIES_FILE_PATH)
        if salary_df.empty:
            st.info("No salary data available.")
            return
        required_columns = ["Employee Code", "Month", "Basic Salary", "KPI Bonus", "Deductions"]
         missing_cols = [c for c in required_columns if c not in salary_df.columns]
        if missing_cols:
            st.error(f"❌ Missing columns: {missing_cols}")
            return
        salary_df["Employee Code"] = (
            salary_df["Employee Code"]
            .astype(str)
            .str.strip()
             .str.replace(".0", "", regex=False)
        )
        user_salaries = salary_df[salary_df["Employee Code"] == user_code].copy()
        if user_salaries.empty:
            st.info(f"🚫 No salary records found for you (Code: {user_code}).")
            return
        for col in ["Basic Salary", "KPI Bonus", "Deductions"]:
            user_salaries[col] = user_salaries[col].apply(decrypt_salary_value)
         user_salaries["Net Salary"] = (
            user_salaries["Basic Salary"]
            + user_salaries["KPI Bonus"]
            - user_salaries["Deductions"]
        )
        user_salaries = user_salaries.reset_index(drop=True)
        if st.button("📊 Show All Details"):
            st.session_state["show_all_details"] = not st.session_state.get("show_all_details", False)
        if st.session_state.get("show_all_details", False):
             st.markdown("### All Salary Records")
            st.dataframe(
                user_salaries[["Month", "Basic Salary", "KPI Bonus", "Deductions", "Net Salary"]],
                use_container_width=True
            )
        for idx, row in user_salaries.iterrows():
             month = row["Month"]
            btn_key = f"show_details_{month}_{idx}"
            if st.button(f"Show Details for {month}", key=btn_key):
                st.session_state[f"salary_details_{month}"] = row.to_dict()
        for idx, row in user_salaries.iterrows():
            month = row["Month"]
            details_key = f"salary_details_{month}"
             if st.session_state.get(details_key):
                details = st.session_state[details_key]
                card = f"""
 <div style="background-color:#f0fdf4; padding:14px; border-radius:10px; margin-bottom:10px; box-shadow:0 4px 8px rgba(0,0,0,0.05);">
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
                with pd.ExcelWriter(output, engine="openpyxl") as writer:
                     pd.DataFrame([details]).to_excel(
                        writer, index=False, sheet_name=f"Salary_{month}"
                    )
                output.seek(0)
                st.download_button(
                     f"📥 Download Salary Slip for {month}",
                    data=output,
                    file_name=f"Salary_{user_code}_{month}.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )
             if st.button(f"Hide Details for {month}", key=f"hide_{month}"):
                del st.session_state[details_key]
                st.rerun()
    except Exception as e:
        st.error(f"❌ Error loading salary  {e}")
# ============================
#  Salary Report Page — Encrypt on Upload
# ============================
def page_salary_report(user):
    st.subheader("Salary Report")
     st.info("Upload the monthly salary sheet. HR can save it to update the system for all employees.")
    uploaded_file = st.file_uploader("Upload Salary Excel File (.xlsx)", type=["xlsx"])
    if uploaded_file:
        try:
            new_salary_df = pd.read_excel(uploaded_file)
            required_cols = ["Employee Code", "Month", "Basic Salary", "KPI Bonus", "Deductions"]
            if not all(col in new_salary_df.columns for col in required_cols):
                 st.error("Missing required columns. Must include: Employee Code, Month, Basic Salary, KPI Bonus, Deductions.")
                return
            cols_to_encrypt = ["Basic Salary", "KPI Bonus", "Deductions"]
            for col in cols_to_encrypt:
                new_salary_df[col] = new_salary_df[col].apply(encrypt_salary_value)
             if "Net Salary" in new_salary_df.columns:
                new_salary_df["Net Salary"] = new_salary_df["Net Salary"].apply(encrypt_salary_value)
            st.session_state["uploaded_salary_df_preview"] = new_salary_df.copy()
             st.success("File loaded and encrypted. Preview below (values appear as encrypted strings).")
            st.dataframe(new_salary_df.head(50), use_container_width=True)
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Replace In-Memory Salary Dataset with Uploaded File"):
                    save_json_file(new_salary_df, SALARIES_FILE_PATH)
                     st.session_state["salary_df"] = new_salary_df.copy()
                    st.success("✅ Salary data encrypted and saved locally.")
            with col2:
                if st.button("Preview only (do not replace)"):
                    st.info("Preview shown above.")
         except Exception as e:
            st.error(f"Failed to process uploaded file: {e}")
    st.markdown("---")
    st.markdown("### Save & Push Salary Report to GitHub")
    if st.button("Save current salary dataset locally and push to GitHub"):
        current_salary_df = st.session_state.get("salary_df")
        if current_salary_df is None:
            current_salary_df = load_json_file(SALARIES_FILE_PATH)
        if current_salary_df is None:
             st.error(f"Could not load salary data from {SALARIES_FILE_PATH}. Upload a file first.") [: 108, 109]
            return
        saved = save_json_file(current_salary_df, SALARIES_FILE_PATH)
        pushed_to_github = False
        if saved and GITHUB_TOKEN:
            data_list = current_salary_df.where(pd.notnull(current_salary_df), None).to_dict(orient='records')
            pushed_to_github = upload_json_to_github(SALARIES_FILE_PATH, data_list, f"Update salary report via HR by {user.get('Employee Name', 'HR')}")
        if saved:
             if pushed_to_github:
                st.success("✅ Salary data saved and pushed to GitHub.")
            else:
                if GITHUB_TOKEN:
                    st.warning("✅ Saved locally, but GitHub push failed.")
                 else:
                    st.info("✅ Saved locally. GitHub token not configured.")
        else:
            st.error("❌ Failed to save locally.")
    st.markdown("---")
    st.markdown("### Current Salary Data (Encrypted View)")
    current_salary_df = st.session_state.get("salary_df")
    if current_salary_df is None:
        current_salary_df = load_json_file(SALARIES_FILE_PATH)
    if current_salary_df is not None:
         st.session_state["salary_df"] = current_salary_df
    if current_salary_df is not None and not current_salary_df.empty:
        st.dataframe(current_salary_df.head(100), use_container_width=True)
        buf = BytesIO()
        with pd.ExcelWriter(buf, engine="openpyxl") as writer:
            current_salary_df.to_excel(writer, index=False, sheet_name="Salaries")
        buf.seek(0)
        st.download_button(
            "Download Current Encrypted Salary Data",
             data=buf,
            file_name="Salaries.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
    else:
        st.info("No salary data available.")
# ============================
#  HR Manager — UPDATED with Password Reset Feature
# ============================
def page_hr_manager(user):
    st.subheader("HR Manager")
    st.info("Upload new employee sheet, manage employees, and perform administrative actions.")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
         st.error("Employee data not loaded.")
        return
    st.markdown("### 🔑 Reset Employee Password")
     st.warning("This will invalidate the current password. The employee must use 'Change Password (No Login)' to set a new one.")
    with st.form("reset_password_form"):
        emp_code_reset = st.text_input("Enter Employee Code to Reset Password")
        reset_submitted = st.form_submit_button("🔐 Reset Password")
        if reset_submitted:
            if not emp_code_reset.strip():
                st.error("Please enter a valid Employee Code.")
             else:
                emp_code_clean = emp_code_reset.strip().replace(".0", "")
                hashes = load_password_hashes()
                if emp_code_clean in hashes:
                    del hashes[emp_code_clean]
                    save_password_hashes(hashes)
                     st.success(f"✅ Password for Employee {emp_code_clean} has been reset. Employee must set a new password using the external link.")
                    add_notification(emp_code_clean, "", "Your password was reset by HR. Please set a new password using the 'Change Password (No Login)' link on the login page.")
                else:
                     col_map = {c.lower().strip(): c for c in df.columns}
                    code_col = col_map.get("employee_code") or col_map.get("employee code")
                    if code_col:
                        df[code_col] = df[code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
                         if emp_code_clean in df[code_col].values:
                             st.success(f"✅ Employee {emp_code_clean} marked for password reset. They can now set a new password.")
                            add_notification(emp_code_clean, "", "Your account is ready for a new password. Use the 'Change Password (No Login)' link.")
                        else:
                             st.error("Employee code not found in company database.")
                    else:
                        st.error("Employee code column not found.")
    st.markdown("---")
    st.markdown("### 📊 HR: Detailed Leave Report for All Employees")
    leaves_df_all = load_leaves_data()
    df_emp_global = st.session_state.get("df", pd.DataFrame())
    if not df_emp_global.empty and not leaves_df_all.empty:
         col_map = {c.lower().strip(): c for c in df_emp_global.columns}
        emp_code_col = col_map.get("employee_code") or col_map.get("employee code")
        emp_name_col = col_map.get("employee_name") or col_map.get("employee name") or col_map.get("name")
        mgr_code_col = col_map.get("manager_code") or col_map.get("manager code")
        if emp_code_col and emp_name_col and mgr_code_col:
            leaves_df_all["Employee Code"] = leaves_df_all["Employee Code"].astype(str).str.strip()
            leaves_df_all["Manager Code"] = leaves_df_all["Manager Code"].astype(str).str.strip()
             df_emp_global[emp_code_col] = df_emp_global[emp_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
            df_emp_global[mgr_code_col] = df_emp_global[mgr_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
            leaves_with_names = leaves_df_all.merge(
                df_emp_global[[emp_code_col, emp_name_col]].rename(columns={emp_code_col: "Employee Code", emp_name_col: "Employee Name"}),
                on="Employee Code", how="left"
            )
             leaves_with_names = leaves_with_names.merge(
                df_emp_global[[emp_code_col, emp_name_col]].rename(columns={emp_code_col: "Manager Code", emp_name_col: "Manager Name"}),
                on="Manager Code", how="left"
            )
            leaves_with_names["Start Date"] = pd.to_datetime(leaves_with_names["Start Date"]).dt.strftime("%d-%m-%Y")
            leaves_with_names["End Date"] = pd.to_datetime(leaves_with_names["End Date"]).dt.strftime("%d-%m-%Y")
             leaves_with_names["Annual Balance"] = 21
            leaves_with_names["Used Days"] = 0
            leaves_with_names["Remaining Days"] = 21
            unique_employees = leaves_with_names["Employee Code"].unique()
            for emp_code in unique_employees:
                _, used, remaining = calculate_leave_balance(emp_code, leaves_df_all)
                 mask = leaves_with_names["Employee Code"] == emp_code
                leaves_with_names.loc[mask, "Used Days"] = used
                leaves_with_names.loc[mask, "Remaining Days"] = remaining
            st.dataframe(leaves_with_names[[
                "Employee Name", "Employee Code", "Start Date", "End Date", "Leave Type", "Status", "Comment", "Manager Name", "Manager Code", "Annual Balance", "Used Days", "Remaining Days"
             ]], use_container_width=True)
        else:
            st.warning("Required columns (Employee Code, Employee Name, Manager Code) not found in employee data for detailed report.")
    else:
        st.info("No employee or leave data available for the detailed report.")
    st.markdown("---")
    st.markdown("### Upload Employees Excel (will replace current dataset)")
    uploaded_file = st.file_uploader("Upload Excel file (.xlsx) to replace the current employees dataset", type=["xlsx"])
     if uploaded_file:
        try:
            new_df = pd.read_excel(uploaded_file)
            new_df = sanitize_employee_data(new_df)
            st.session_state["uploaded_df_preview"] = new_df.copy()
             st.success("File loaded and sanitized. Preview below.")
            st.dataframe(new_df.head(50), use_container_width=True)
            st.markdown("**Note:** Uploading will replace the current dataset in-memory.")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Replace In-Memory Dataset with Uploaded File"):
                     st.session_state["df"] = new_df.copy()
                    initialize_passwords_from_data(new_df.to_dict(orient='records'))
                    st.success("In-memory dataset replaced and password hashes updated.")
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
                                 st.run_code = None
                            else:
                                if GITHUB_TOKEN:
                                     st.run_code = None
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
    st.markdown("---")
    st.warning("🛠️ **Clear All Test Data** (Use BEFORE going live!)")
    if st.button("🗑️ Clear Leaves, HR Messages, Notifications & Photos"):
        try:
             test_files = [LEAVES_FILE_PATH, HR_QUERIES_FILE_PATH, NOTIFICATIONS_FILE_PATH, HR_REQUESTS_FILE_PATH, SALARIES_FILE_PATH]
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
# ============================
#  🆕 PAGE: Notify Compliance (for MR only)
# ============================
def page_notify_compliance(user):
    st.subheader("📨 Notify Compliance Team")
    st.info("Use this form to notify the Compliance team about delays, absences, or other operational issues.")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.error("Employee data not loaded.")
         return
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    emp_code_col = "Employee Code"
    mgr_code_col = "Manager Code"
    emp_name_col = "Employee Name"
    if not all(col in df.columns for col in [emp_code_col, mgr_code_col, emp_name_col]):
        st.error(f"❌ Required columns missing: {emp_code_col}, {mgr_code_col}, {emp_name_col}")
        return
    df[emp_code_col] = df[emp_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
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
            manager_name = mgr_row.iloc[0].get(emp_name_col, "N/A")
    st.markdown(f"**Your Manager**: {manager_name} (Code: {manager_code})")
    compliance_titles = {
        "ASSOCIATE COMPLIANCE",
         "FIELD COMPLIANCE SPECIALIST",
        "COMPLIANCE MANAGER"
    }
    df["Title_upper"] = df["Title"].astype(str).str.upper()
    compliance_df = df[df["Title_upper"].isin(compliance_titles)].copy()
    df.drop(columns=["Title_upper"], inplace=True, errors="ignore")
    if compliance_df.empty:
        st.warning("No Compliance officers found in the system.")
        return
    compliance_options = {}
    for _, row in compliance_df.iterrows():
        name = row.get(emp_name_col, "Unknown")
        code = row.get(emp_code_col, "N/A")
         compliance_options[f"{name} (Code: {code})"] = {"name": name, "code": code}
    selected_option = st.selectbox("Select Compliance Officer", list(compliance_options.keys()))
    recipient_data = compliance_options[selected_option]
    recipient_name = recipient_data["name"]
    recipient_code = recipient_data["code"]
    message = st.text_area("Your Message", height=120, placeholder="Example: I was delayed today due to traffic...")
    if st.button("📤 Send to Compliance"):
        if not message.strip():
            st.warning("Please write a message.")
        else:
             messages_df = load_compliance_messages()
            new_id = int(messages_df["ID"].max()) + 1 if not messages_df.empty else 1
            new_row = pd.DataFrame([{
                "ID": new_id,
                "MR Code": user_code,
                 "MR Name": user.get("Employee Name", user_code),
                "Compliance Recipient": recipient_name,
                "Compliance Code": recipient_code,
                "Manager Code": manager_code,
                "Manager Name": manager_name,
                "Message": message.strip(),
                 "Timestamp": pd.Timestamp.now(),
                "Status": "Pending"
            }])
            messages_df = pd.concat([messages_df, new_row], ignore_index=True)
            if save_compliance_messages(messages_df):
                for title in compliance_titles:
                     add_notification("", title, f"New message from MR {user_code}")
                if manager_code != "N/A" and manager_code != user_code:
                    add_notification(manager_code, "", f"New compliance message from your team member {user_code}")
                st.success("✅ Your message has been sent to Compliance and your manager.")
             else:
                st.error("❌ Failed to send message.")
# ============================
#  🆕 PAGE: Report Compliance (for Compliance team + Managers)
# ============================
def page_report_compliance(user):
    st.subheader("📋 Report Compliance")
    st.info("Messages sent by MRs regarding delays, absences, or compliance issues.")
    messages_df = load_compliance_messages()
    if messages_df.empty:
        st.info("No compliance messages yet.")
        return
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
         st.error("Employee data not loaded.") [: 166]
        return
    title_val = str(user.get("Title", "")).strip().upper()
    is_compliance = title_val in {"ASSOCIATE COMPLIANCE", "FIELD COMPLIANCE SPECIALIST", "COMPLIANCE MANAGER"}
    is_manager = title_val in {"AM", "DM"}
    if not is_compliance and is_manager:
        user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
        hierarchy = build_team_hierarchy_recursive(df, user_code, title_val)
        if hierarchy:
            def collect_all_team_codes(node, codes_set):
                 if node: [: 167]
                    codes_set.add(node.get("Manager Code", ""))
                    for child in node.get("Team", []):
                        collect_all_team_codes(child, codes_set)
             return codes_set
            team_codes = set()
            collect_all_team_codes(hierarchy, team_codes)
            team_codes.add(user_code)  # أضف كود المستخدم نفسه
            messages_df = messages_df[
                messages_df["MR Code"].astype(str).isin(team_codes)
            ].copy()
    messages_df = messages_df.sort_values("Timestamp", ascending=False).reset_index(drop=True)
     messages_df["Date"] = pd.to_datetime(messages_df["Timestamp"]).dt.strftime("%d-%m-%Y %H:%M")
    display_df = messages_df[[
        "Date", "MR Name", "MR Code", "Message", "Compliance Recipient", "Manager Name"
    ]].rename(columns={
        "Date": "Date & Time",
        "MR Name": "Employee Name",
        "MR Code": "Employee Code",
        "Message": "Reason",
        "Compliance Recipient": "Sent To Compliance",
        "Manager Name": "Team Manager"
     })
    st.dataframe(display_df, use_container_width=True)
    buf = BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as writer:
        display_df.to_excel(writer, index=False)
    buf.seek(0)
    st.download_button(
        "📥 Download Report (Excel)",
        data=buf,
        file_name="Compliance_Report.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
# ============================
#  🚀 صفحة IDB – Individual Development Blueprint (NEW)
# ============================
def page_idb_mr(user):
    st.subheader("🚀 IDB – Individual Development Blueprint")
     st.markdown("""
<div style="background-color:#f0fdf4; padding:12px; border-radius:8px; border-left:4px solid #059669;">
<p style="color:#05445E; font-weight:bold;">We want you to always aim higher — your success matters to us.</p>
</div>
""", unsafe_allow_html=True)
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    user_name = user.get("Employee Name", user_code)
    departments = ["Sales", "Marketing", "HR", "SFE", "Distribution", "Market Access"]
    reports = load_idb_reports()
    existing = reports[reports["Employee Code"] == user_code]
    if not existing.empty:
        row = existing.iloc[0]
         selected_deps = eval(row["Selected Departments"]) if isinstance(row["Selected Departments"], str) else row["Selected Departments"]
        strengths = eval(row["Strengths"]) if isinstance(row["Strengths"], str) else row["Strengths"]
        development = eval(row["Development Areas"]) if isinstance(row["Development Areas"], str) else row["Development Areas"]
        action = row["Action Plan"]
    else:
        selected_deps = []
        strengths = ["", "", ""]
        development = ["", "", ""]
        action = ""
    with st.form("idb_form"):
         st.markdown("### 🔍 Select Target Departments (Max 2)")
        selected = st.multiselect(
            "Choose up to 2 departments you're interested in:",
            options=departments,
            default=selected_deps
        )
        if len(selected) > 2:
             st.warning("⚠️ You can select a maximum of 2 departments.")
        st.markdown("### 💪 Area of Strength (3 points)")
        strength_inputs = []
        for i in range(3):
            val = strengths[i] if i < len(strengths) else ""
            strength_inputs.append(st.text_input(f"Strength {i+1}", value=val, key=f"str_{i}"))
        st.markdown("### 📈 Area of Development (3 points)")
        dev_inputs = []
         for i in range(3):
            val = development[i] if i < len(development) else ""
            dev_inputs.append(st.text_input(f"Development {i+1}", value=val, key=f"dev_{i}"))
        st.markdown("### 🤝 Action Plan (Agreed with your manager)")
        action_input = st.text_area("Action", value=action, height=100)
        submitted = st.form_submit_button("💾 Save IDB Report")
        if submitted:
             if len(selected) > 2:
                st.error("You cannot select more than 2 departments.")
            else:
                success = save_idb_report(
                    user_code,
                    user_name,
                     selected,
                    [s.strip() for s in strength_inputs if s.strip()],
                    [d.strip() for d in dev_inputs if d.strip()],
                    action_input.strip()
                 )
                if success:
                    st.success("✅ IDB Report saved successfully!")
                    add_notification("", "HR", f"MR {user_name} ({user_code}) updated their IDB report.")
                     add_notification("", "DM", f"MR {user_name} ({user_code}) updated their IDB report.")
                    add_notification("", "AM", f"MR {user_name} ({user_code}) updated their IDB report.")
                    add_notification("", "BUM", f"MR {user_name} ({user_code}) updated their IDB report.")
                    st.rerun()
                else:
                     st.error("❌ Failed to save report.")
    if not existing.empty:
        st.markdown("### 📊 Your Current IDB Report")
        display_data = {
            "Field": [
                "Selected Departments",
                 "Strength 1", "Strength 2", "Strength 3",
                "Development 1", "Development 2", "Development 3",
                "Action Plan",
                "Updated At"
            ],
            "Value": [
                ", ".join(selected_deps),
                 *(strengths + [""] * (3 - len(strengths))),
                *(development + [""] * (3 - len(development))),
                action,
                existing.iloc[0]["Updated At"]
            ]
        }
         display_df = pd.DataFrame(display_data)
        st.table(display_df)
        buf = BytesIO()
        with pd.ExcelWriter(buf, engine="openpyxl") as writer:
            display_df.to_excel(writer, index=False, sheet_name="IDB_Report")
        buf.seek(0)
        st.download_button(
            "📥 Download IDB Report (Excel)",
            data=buf,
             file_name=f"IDB_{user_code}.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
# ============================
#  🌱 صفحة Self Development (NEW)
# ============================
def page_self_development(user):
    st.subheader("🌱 Self Development")
    st.markdown("""
 <div style="background-color:#e0f2fe; padding:16px; border-radius:10px; text-align:center; margin-bottom:20px;">
<h3 style="color:#05445E;">We always want you at your best — your success matters to us.<br>
Share your journey to success with us.</h3>
</div>
""", unsafe_allow_html=True)
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    uploaded_cert = st.file_uploader("Upload your certification (PDF, JPG, PNG)", type=["pdf", "jpg", "jpeg", "png"])
    cert_desc = st.text_input("Brief description (optional)", placeholder="e.g., Leadership Course, Excel Advanced...")
    if uploaded_cert and st.button("📤 Submit Certification"):
        os.makedirs("certifications", exist_ok=True)
        ext = uploaded_cert.name.split(".")[-1].lower()
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
         filename = f"cert_{user_code}_{timestamp}.{ext}"
        filepath = os.path.join("certifications", filename)
        with open(filepath, "wb") as f:
            f.write(uploaded_cert.getbuffer())
        cert_log = load_json_file("certifications_log.json", default_columns=["Employee Code", "File", "Description", "Uploaded At"])
        new_log = pd.DataFrame([{
            "Employee Code": user_code,
            "File": filename,
             "Description": cert_desc,
            "Uploaded At": pd.Timestamp.now().isoformat()
        }])
        cert_log = pd.concat([cert_log, new_log], ignore_index=True)
        save_json_file(cert_log, "certifications_log.json")
        add_notification("", "HR", f"MR {user_code} uploaded a new certification.")
        st.success("✅ Certification submitted to HR!")
        st.rerun()
# ============================
#  🎓 صفحة عرض التطوير (HR Development View) (NEW)
# ============================
def page_hr_development(user):
     st.subheader("🎓 Employee Development (HR View)")
    tab_idb, tab_certs = st.tabs(["📋 IDB Reports", "📜 Certifications"])
    with tab_idb:
        idb_df = load_idb_reports()
        if not idb_df.empty:
            if "Employee Name" not in idb_df.columns:
                df = st.session_state.get("df", pd.DataFrame())
                if not df.empty:
                     col_map = {c.lower().strip(): c for c in df.columns}
                    emp_code_col = col_map.get("employee_code") or col_map.get("employee code")
                    emp_name_col = col_map.get("employee_name") or col_map.get("employee name") or col_map.get("name")
                    if emp_code_col and emp_name_col:
                         df[emp_code_col] = df[emp_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
                        idb_df["Employee Code"] = idb_df["Employee Code"].astype(str).str.strip()
                        idb_df = idb_df.merge(
                             df[[emp_code_col, emp_name_col]].rename(columns={emp_code_col: "Employee Code", emp_name_col: "Employee Name"}),
                            on="Employee Code",
                            how="left"
                        )
             idb_df["Selected Departments"] = idb_df["Selected Departments"].apply(
                lambda x: ", ".join(eval(x)) if isinstance(x, str) else ", ".join(x)
            )
            idb_df["Strengths"] = idb_df["Strengths"].apply(
                 lambda x: "; ".join(eval(x)) if isinstance(x, str) else "; ".join(x)
            )
            idb_df["Development Areas"] = idb_df["Development Areas"].apply(
                lambda x: "; ".join(eval(x)) if isinstance(x, str) else "; ".join(x)
            )
            display_cols = ["Employee Code", "Employee Name", "Selected Departments", "Strengths", "Development Areas", "Action Plan", "Updated At"]
             st.dataframe(idb_df[display_cols], use_container_width=True)
            buf = BytesIO()
            with pd.ExcelWriter(buf, engine="openpyxl") as writer:
                idb_df.to_excel(writer, index=False)
            buf.seek(0)
            st.download_button("📥 Download IDB Reports", data=buf, file_name="HR_IDB_Reports.xlsx")
        else:
             st.info("📭 No IDB reports yet.")
    with tab_certs:
        cert_log = load_json_file("certifications_log.json")
        if not cert_log.empty:
            st.dataframe(cert_log, use_container_width=True)
            for idx, row in cert_log.iterrows():
                filepath = os.path.join("certifications", row["File"])
                 if os.path.exists(filepath):
                    with open(filepath, "rb") as f:
                        file_bytes = f.read()
                    st.download_button(
                        label=f"📥 Download {row['File']}",
                         data=file_bytes,
                        file_name=row["File"],
                        mime="application/octet-stream",
                        key=f"dl_cert_{idx}"
                     ) [: 198]
        else:
            st.info("📭 No certifications uploaded.")
# ============================
#  🎓 صفحة عرض التطوير للمديرين (DM, AM, BUM) - NEW PAGE
# ============================
def page_manager_development(user):
    st.subheader("🎓 Team Development (Manager View)")
    st.markdown("""
 <div style="background-color:#e0f2fe; padding:12px; border-radius:8px; border-left:4px solid #05445E; margin-bottom:20px;">
<p style="color:#05445E; font-weight:bold;">View your team's development reports and certifications.</p>
</div>
""", unsafe_allow_html=True)
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    user_title = str(user.get("Title", "")).strip().upper()
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.error("Employee data not loaded.")
        return
    hierarchy = build_team_hierarchy_recursive(df, user_code, user_title)
    def collect_all_team_codes(node, codes_set):
        if node:
            codes_set.add(node.get("Manager Code", ""))
             for child in node.get("Team", []):
                collect_all_team_codes(child, codes_set)
        return codes_set
    team_codes = set()
    collect_all_team_codes(hierarchy, team_codes)
    team_codes.add(user_code)  # أضف كود المستخدم نفسه
    st.info(f"👥 Your team includes {len(team_codes)} members")
    tab_idb, tab_certs = st.tabs(["📋 IDB Reports", "📜 Certifications"])
    with tab_idb:
        idb_df = load_idb_reports()
         if not idb_df.empty:
            idb_df = idb_df[idb_df["Employee Code"].astype(str).isin(team_codes)].copy()
            if not idb_df.empty:
                if "Employee Name" not in idb_df.columns:
                    if not df.empty:
                         col_map = {c.lower().strip(): c for c in df.columns}
                        emp_code_col = col_map.get("employee_code") or col_map.get("employee code")
                        emp_name_col = col_map.get("employee_name") or col_map.get("employee name") or col_map.get("name")
                        if emp_code_col and emp_name_col:
                             df[emp_code_col] = df[emp_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
                            idb_df["Employee Code"] = idb_df["Employee Code"].astype(str).str.strip()
                            idb_df = idb_df.merge(
                                 df[[emp_code_col, emp_name_col]].rename(columns={emp_code_col: "Employee Code", emp_name_col: "Employee Name"}),
                                on="Employee Code",
                                how="left"
                             )
                idb_df["Selected Departments"] = idb_df["Selected Departments"].apply(
                    lambda x: ", ".join(eval(x)) if isinstance(x, str) else ", ".join(x)
                )
                 idb_df["Strengths"] = idb_df["Strengths"].apply(
                     lambda x: "; ".join(eval(x)) if isinstance(x, str) else "; ".join(x)
                )
                idb_df["Development Areas"] = idb_df["Development Areas"].apply(
                    lambda x: "; ".join(eval(x)) if isinstance(x, str) else "; ".join(x)
                )
                 display_cols = ["Employee Code", "Employee Name", "Selected Departments", "Strengths", "Development Areas", "Action Plan", "Updated At"]
                st.dataframe(idb_df[display_cols], use_container_width=True)
                buf = BytesIO()
                with pd.ExcelWriter(buf, engine="openpyxl") as writer:
                    idb_df.to_excel(writer, index=False)
                 buf.seek(0)
                st.download_button(
                    "📥 Download Team IDB Reports",
                    data=buf,
                    file_name=f"Team_IDB_{user_code}.xlsx",
                     mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )
            else:
                st.info("📭 No IDB reports from your team yet.")
        else:
            st.info("📭 No IDB reports yet.")
    with tab_certs:
        cert_log = load_json_file("certifications_log.json")
         if not cert_log.empty:
            cert_log = cert_log[cert_log["Employee Code"].astype(str).isin(team_codes)].copy()
            if not cert_log.empty:
                st.dataframe(cert_log, use_container_width=True)
                for idx, row in cert_log.iterrows():
                    filepath = os.path.join("certifications", row["File"])
                     if os.path.exists(filepath):
                        with open(filepath, "rb") as f:
                            file_bytes = f.read()
                         st.download_button(
                            label=f"📥 Download {row['File']}",
                            data=file_bytes,
                            file_name=row["File"],
                             mime="application/octet-stream",
                            key=f"dl_cert_mgr_{idx}"
                        )
            else:
                 st.info("📭 No certifications from your team yet.")
        else:
            st.info("📭 No certifications uploaded.")
# ============================
#  Remaining Page Functions (unchanged)
# ============================
def render_logo_and_title():
    pass  # لا تفعل شيء
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
    cols_per_row = 4
    cols = st.columns(cols_per_row)
    for i, filename in enumerate(sorted(photo_files)):
        col = cols[i % cols_per_row]
        filepath = os.path.join("employee_photos", filename)
        emp_code = filename.rsplit(".", 1)[0]
        emp_name = code_to_name.get(emp_code, "Unknown")
         with col:
            st.image(filepath, use_column_width=True)
            st.caption(f"{emp_code}<br>{emp_name}", unsafe_allow_html=True)
            with open(filepath, "rb") as f:
                st.download_button("📥 Download", f, file_name=filename, key=f"dl_{filename}")
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
    for key, val in user.items():
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
    tab1, tab2 = st.tabs(["Profile Data", "Personal Photo"])
    with tab1:
        st.dataframe(row.reset_index(drop=True), use_container_width=True)
         buf = BytesIO()
        with pd.ExcelWriter(buf, engine="openpyxl") as writer:
            row.to_excel(writer, index=False, sheet_name="MyProfile")
        buf.seek(0)
        st.download_button("Download My Profile (Excel)", data=buf, file_name="my_profile.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    with tab2:
        emp_code_clean = None
        for key, val in user.items():
            if key.lower().replace(" ", "").replace("_", "") in ["employeecode", "employee_code"]:
                 emp_code_clean = str(val).strip().replace(".0", "")
                break
        if emp_code_clean:
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
    st.markdown("---")
    st.markdown("### 🔐 Change Your Password")
    with st.form("change_password_form"):
        current_pwd = st.text_input("Current Password", type="password")
        new_pwd = st.text_input("New Password", type="password")
        confirm_pwd = st.text_input("Confirm New Password", type="password")
        pwd_submitted = st.form_submit_button("Change Password")
        if pwd_submitted:
            if not current_pwd or not new_pwd or not confirm_pwd:
                 st.error("All fields are required.")
            elif new_pwd != confirm_pwd:
                st.error("New password and confirmation do not match.")
            else:
                hashes = load_password_hashes()
                 user_code_clean = str(user.get("Employee Code", "")).strip().replace(".0", "")
                stored_hash = hashes.get(user_code_clean)
                if stored_hash and verify_password(current_pwd, stored_hash):
                    hashes[user_code_clean] = hash_password(new_pwd)
                    save_password_hashes(hashes)
                     st.success("✅ Your password has been updated successfully.")
                    add_notification("", "HR", f"Employee {user_code_clean} changed their password.")
                else:
                    st.error("❌ Current password is incorrect.")
def calculate_leave_balance(user_code, leaves_df):
    annual_balance = DEFAULT_ANNUAL_LEAVE
    user_approved_leaves = leaves_df[
        (leaves_df["Employee Code"].astype(str)  == str(user_code)) &
        (leaves_df["Status"] == "Approved")
    ].copy()
    if user_approved_leaves.empty:
        used_days = 0
    else:
        user_approved_leaves["Start Date"] = pd.to_datetime(user_approved_leaves["Start Date"])
        user_approved_leaves["End Date"] = pd.to_datetime(user_approved_leaves["End Date"])
        user_approved_leaves["Leave Days"] = (user_approved_leaves["End Date"] - user_approved_leaves["Start Date"]).dt.days
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
    leaves_df = load_leaves_data()
    annual_balance, used_days, remaining_days = calculate_leave_balance(user_code, leaves_df)
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
                 else: [: 245]
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
def build_team_hierarchy_recursive(df, manager_code, manager_title="AM"):
    emp_code_col = "Employee Code"
     emp_name_col = "Employee Name"
    mgr_code_col = "Manager Code"
    title_col = "Title"
    required_cols = [emp_code_col, emp_name_col, mgr_code_col, title_col]
    if not all(col in df.columns for col in required_cols):
        missing = [col for col in required_cols if col not in df.columns]
        st.warning(f"Missing required columns: {missing}")
        return {}
    df = df.copy()
    df[emp_code_col] = df[emp_code_col].astype(str).str.strip().str.replace('.0', '', regex=False)
     df[mgr_code_col] = df[mgr_code_col].astype(str).str.strip().str.replace('.0', '', regex=False)
    df[title_col] = df[title_col].astype(str).str.strip().str.upper()
    mgr_row = df[df[emp_code_col] == str(manager_code)]
    if mgr_row.empty:
        st.warning(f"Manager with code {manager_code} not found in data.")
        return {}
    mgr_name = mgr_row.iloc[0][emp_name_col]
    current_title = mgr_row.iloc[0][title_col]
    if current_title == "BUM":
        subordinate_types = ["AM", "DM"]
    elif current_title == "AM":
        subordinate_types = ["DM"]
    elif current_title == "DM":
         subordinate_types = ["MR"] [: 249]
    else:
        subordinate_types = []
    direct_subs = df[df[mgr_code_col] == str(manager_code)]
    if subordinate_types:
        direct_subs = direct_subs[direct_subs[title_col].isin(subordinate_types)]
    node = {
        "Manager": f"{mgr_name} ({current_title})",
        "Manager Code": str(manager_code),
        "Team": [],
        "Summary": {"AM": 0, "DM": 0, "MR": 0, "Total": 0}
     } [: 250]
    for _, sub_row in direct_subs.iterrows():
        sub_code = sub_row[emp_code_col]
        sub_title = sub_row[title_col]
        child_node = build_team_hierarchy_recursive(df, sub_code, sub_title)
        if not child_node:
            leaf_node = {
                "Manager": f"{sub_row.get(emp_name_col, sub_code)} ({sub_title})",
                 "Manager Code": str(sub_code),
                "Team": [],
                "Summary": {"AM": 0, "DM": 0, "MR": 0, "Total": 0}
            }
            if sub_title == "AM":
                leaf_node["Summary"]["AM"] = 1
             elif sub_title == "DM":
                leaf_node["Summary"]["DM"] = 1
            elif sub_title == "MR":
                leaf_node["Summary"]["MR"] = 1
            leaf_node["Summary"]["Total"] = sum(leaf_node["Summary"].values())
            node["Team"].append(leaf_node)
        else:
            node["Team"].append(child_node)
     def collect_descendants_codes(start_code):
        descendants = set()
        stack = [str(start_code)]
        while stack:
            cur = stack.pop()
            direct = df[df[mgr_code_col] == str(cur)]
            for _, r in direct.iterrows():
                code = r[emp_code_col]
                 title = r[title_col]
                if code not in descendants:
                    descendants.add(code)
                    if title in ["AM", "DM", "BUM"]:
                         stack.append(code)
        return list(descendants)
    all_desc = collect_descendants_codes(manager_code)
    if all_desc:
        desc_df = df[df[emp_code_col].isin(all_desc)]
        node["Summary"]["AM"] = int((desc_df[title_col] == "AM").sum())
        node["Summary"]["DM"] = int((desc_df[title_col] == "DM").sum())
        node["Summary"]["MR"] = int((desc_df[title_col] == "MR").sum())
        node["Summary"]["Total"] = node["Summary"]["AM"] + node["Summary"]["DM"] + node["Summary"]["MR"]
    else:
         node["Summary"] = {"AM":0, "DM":0, "MR":0, "Total":0}
    return node
def send_full_leaves_report_to_hr(leaves_df, df_emp, out_path="HR_Leaves_Report.xlsx"):
    try:
        df_emp_local = df_emp.copy()
    except Exception:
        df_emp_local = pd.DataFrame()
    col_map = {c.lower().strip(): c for c in df_emp_local.columns} if not df_emp_local.empty else {}
    emp_code_col = col_map.get("employee_code") or col_map.get("employee code") or "Employee Code"
    emp_name_col = col_map.get("employee_name") or col_map.get("employee name") or col_map.get("name") or "Employee Name"
    leaves = leaves_df.copy()
    if "Employee Code" in leaves.columns:
         leaves["Employee Code"] = leaves["Employee Code"].astype(str).str.strip()
    if "Manager Code" in leaves.columns:
        leaves["Manager Code"] = leaves["Manager Code"].astype(str).str.strip()
    if emp_code_col in df_emp_local.columns and emp_name_col in df_emp_local.columns:
        df_emp_local[emp_code_col] = df_emp_local[emp_code_col].astype(str).str.strip().str.replace('.0', '', regex=False)
        leaves = leaves.merge(
            df_emp_local[[emp_code_col, emp_name_col]].rename(columns={emp_code_col: "Employee Code", emp_name_col: "Employee Name"}),
            on="Employee Code", how="left"
        )
         leaves = leaves.merge(
            df_emp_local[[emp_code_col, emp_name_col]].rename(columns={emp_code_col: "Manager Code", emp_name_col: "Manager Name"}),
            on="Manager Code", how="left"
        )
    else:
        leaves["Employee Name"] = leaves.get("Employee Code", "")
        if "Manager Code" in leaves.columns:
            leaves["Manager Name"] = leaves.get("Manager Code", "")
     if "Start Date" in leaves.columns:
        leaves["Start Date"] = pd.to_datetime(leaves["Start Date"], errors="coerce").dt.strftime("%d-%m-%Y")
    if "End Date" in leaves.columns:
        leaves["End Date"] = pd.to_datetime(leaves["End Date"], errors="coerce").dt.strftime("%d-%m-%Y")
    export_cols = [c for c in ["Employee Name", "Employee Code", "Start Date", "End Date", "Leave Type", "Status", "Comment", "Manager Name", "Manager Code"] if c in leaves.columns]
    report_df = leaves[export_cols].copy()
    try:
        with pd.ExcelWriter(out_path, engine="openpyxl") as writer:
             report_df.to_excel(writer, index=False)
        try:
            add_notification("", "HR", f"Full leaves report generated: {out_path}")
        except Exception:
            pass
        return True, out_path
    except Exception as e:
        return False, str(e)
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
     hierarchy = build_team_hierarchy_recursive(df, user_code, role.upper())
    if not hierarchy:
         st.info(f"Could not build team structure for your code: {user_code}. Check your manager assignment or title.")
        return
    ROLE_ICONS = { "BUM": "🏢", "AM": "👨‍💼", "DM": "👩‍💼", "MR": "🧑‍⚕️" }
    ROLE_COLORS = { "BUM": "#05445E", "AM": "#05445E", "DM": "#0A5C73", "MR": "#dc2626" }
    st.markdown("""
<style>
.team-node {
background-color: #FFFFFF;
border-left: 5px solid var(--primary); 
padding: 15px;
margin: 8px 0;
border-radius: 10px;
box-shadow: 0 4px 12px rgba(0,0,0,0.08);
}
.team-node-header {
display: flex;
justify-content: space-between;
align-items: center;
font-weight: 600;
color: #05445E;
margin-bottom: 8px;
}
.team-node-summary { font-size: 0.9rem; color: #666666; margin-top: 4px; }
.team-node-children { margin-left: 20px; margin-top: 8px; }
.team-member { display: flex; align-items: center; padding: 6px 12px; background-color: #f8fafc; border-radius: 4px; margin: 4px 0; font-size: 0.95rem; }
 .team-member-icon { margin-right: 8px; font-size: 1.1rem; } [: 264]
</style>
""", unsafe_allow_html=True)
    user_title = role.upper()
    if user_title == "BUM":
        st.markdown("### Team Structure Summary")
        col1, col2, col3 = st.columns(3)
        with col1: st.markdown(f'<div class="team-structure-card"><div class="team-structure-title">AM Count</div><div class="team-structure-value am">{hierarchy["Summary"]["AM"]}</div></div>', unsafe_allow_html=True)
        with col2: st.markdown(f'<div class="team-structure-card"><div class="team-structure-title">DM Count</div><div class="team-structure-value dm">{hierarchy["Summary"]["DM"]}</div></div>', unsafe_allow_html=True)
        with col3: st.markdown(f'<div class="team-structure-card"><div class="team-structure-title">MR Count</div><div class="team-structure-value mr">{hierarchy["Summary"]["MR"]}</div></div>', unsafe_allow_html=True)
    elif user_title == "AM":
         st.markdown("### Team Structure Summary")
        col1, col2 = st.columns(2)
        with col1: st.markdown(f'<div class="team-structure-card"><div class="team-structure-title">DM Count</div><div class="team-structure-value dm">{hierarchy["Summary"]["DM"]}</div></div>', unsafe_allow_html=True)
        with col2: st.markdown(f'<div class="team-structure-card"><div class="team-structure-title">MR Count</div><div class="team-structure-value mr">{hierarchy["Summary"]["MR"]}</div></div>', unsafe_allow_html=True)
    def render_tree(node, level=0, is_last_child=False):
        if not node: return
        summary_parts = []
        if node["Summary"]["AM"] > 0: summary_parts.append(f"🟢 {node['Summary']['AM']} AM")
         if node["Summary"]["DM"] > 0: summary_parts.append(f"🔵 {node['Summary']['DM']} DM")
        if node["Summary"]["MR"] > 0: summary_parts.append(f"🟣 {node['Summary']['MR']} MR")
         summary_str = " | ".join(summary_parts) if summary_parts else "No direct reports"
        manager_info, manager_code = node.get("Manager", "Unknown"), node.get("Manager Code", "N/A")
        role = "MR"
        if "(" in manager_info: role = manager_info.split("(")[-1].replace(")", "").strip()
        icon, color = ROLE_ICONS.get(role, "👤"), ROLE_COLORS.get(role, "#2E2E2E")
        prefix = ("│   " * (level - 1) + ("└── " if is_last_child else "├── ")) if level > 0 else ""
         st.markdown(f'<div class="team-node"><div class="team-node-header"><span style="color: {color};">{prefix}{icon} <strong>{manager_info}</strong> (Code: {manager_code})</span><span class="team-node-summary">{summary_str}</span></div>', unsafe_allow_html=True)
        if node.get("Team"):
            st.markdown('<div class="team-node-children">', unsafe_allow_html=True)
            for i, child in enumerate(node["Team"]): render_tree(child, level + 1, i == len(node["Team"]) - 1)
            st.markdown('</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
    render_tree(hierarchy, 0, True)
def page_directory(user):
    st.subheader("Company Structure")
    df = st.session_state.get("df", pd.DataFrame())
     if df.empty:
        st.info("Employee data not loaded.")
        return
    st.info("Search and filter employees below.")
    COLUMNS_TO_SHOW = ["Employee Code", "Employee Name", "Manager Name", "Title", "Mobile", "Department", "E-Mail", "Address as 702 bricks"]
    col_map = {c.lower().strip(): c for c in df.columns}
    final_columns = [col_map[v] for n in COLUMNS_TO_SHOW for v in [n.lower().replace(' ', '_'), n.lower().replace(' ', ''), n.lower(), n] if v in col_map]
    c1, c2 = st.columns(2)
     search_name, search_code = c1.text_input("Search by Employee Name"), c2.text_input("Search by Employee Code")
    filtered_df = df.copy()
    if search_name:
        name_col = next((c for c in df.columns if c.lower().replace(" ", "_") in ["employee_name", "name", "full_name"]), None)
        if name_col: filtered_df = filtered_df[filtered_df[name_col].astype(str).str.contains(search_name, case=False, na=False)]
    if search_code:
        code_col = next((c for c in df.columns if c.lower().replace(" ", "_") in ["employee_code", "code", "emp_code"]), None)
        if code_col: filtered_df = filtered_df[filtered_df[code_col].astype(str).str.contains(search_code, case=False, na=False)]
     if final_columns:
        st.dataframe(filtered_df[final_columns].copy(), use_container_width=True)
    else:
        st.error("Column mapping failed.")
def load_hr_queries(): return load_json_file(HR_QUERIES_FILE_PATH, default_columns=["ID", "Employee Code", "Employee Name", "Subject", "Message", "Reply", "Status", "Date Sent", "Date Replied"])
def save_hr_queries(df):
    df = df.copy()
    for c in ["Date Sent", "Date Replied"]:
        if c in df.columns: df[c] = pd.to_datetime(df[c], errors="coerce").astype(str)
    if "ID" in df.columns:
        df["ID"] = pd.to_numeric(df["ID"], errors="coerce")
        if df["ID"].isna().any():
             existing_max = int(df["ID"].max(skipna=True)) if not df["ID"].isna().all() else 0
            for idx in df[df["ID"].isna()].index:
                existing_max += 1
                df.at[idx, "ID"] = existing_max
        df["ID"] = df["ID"].astype(int)
    return save_json_file(df, HR_QUERIES_FILE_PATH)
 def load_hr_requests(): return load_json_file(HR_REQUESTS_FILE_PATH, default_columns=["ID", "HR Code", "Employee Code", "Employee Name", "Request", "File Attached", "Status", "Response", "Response File", "Date Sent", "Date Responded"])
def save_hr_requests(df):
    df = df.copy()
    for c in ["Date Sent", "Date Responded"]:
        if c in df.columns: df[c] = pd.to_datetime(df[c], errors="coerce").astype(str)
    if "ID" in df.columns:
        df["ID"] = pd.to_numeric(df["ID"], errors="coerce")
        if df["ID"].isna().any():
            existing_max = int(df["ID"].max(skipna=True)) if not df["ID"].isna().all() else 0
            for idx in df[df["ID"].isna()].index:
                 existing_max += 1
                df.at[idx, "ID"] = existing_max
        df["ID"] = df["ID"].astype(int)
    return save_json_file(df, HR_REQUESTS_FILE_PATH)
def save_request_file(f, code, rid):
    os.makedirs("hr_request_files", exist_ok=True)
    fn = f"req_{rid}_emp_{code}.{f.name.split('.')[-1].lower()}"
    with open(os.path.join("hr_request_files", fn), "wb") as out: out.write(f.getbuffer())
    return fn
def save_response_file(f, code, rid):
    os.makedirs("hr_response_files", exist_ok=True)
    fn = f"resp_{rid}_emp_{code}.{f.name.split('.')[-1].lower()}"
     with open(os.path.join("hr_response_files", fn), "wb") as out: out.write(f.getbuffer())
    return fn
# ============================
#  🆕 PAGE: ASK EMPLOYEES (HR) — UPDATED 
# ============================
def page_ask_employees(user):
    st.subheader("📤 Ask Employees")
    st.info("💡 Select a department first, then choose an employee to send them a private request or message.")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.warning("Employee data not loaded.")
        return
    # Column mapping
    col_map = {c.lower().strip(): c for c in df.columns}
    dept_col = col_map.get("department")
    name_col = col_map.get("employee_name") or col_map.get("name") or col_map.get("employee name")
    code_col = col_map.get("employee_code") or col_map.get("employee code")
    if not all([dept_col, name_col, code_col]):
        st.error("❌ Required columns missing: Department, Employee Name, or Employee Code")
        return
    # Clean data
    df[code_col] = df[code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
    # Dependent Dropdowns
    c1, c2 = st.columns(2)
    depts = sorted(df[dept_col].dropna().unique().tolist())
    selected_dept = c1.selectbox("🏢 Select Department", depts)
    filtered_df = df[df[dept_col] == selected_dept]
    emp_options = filtered_df.apply(lambda r: f"{r[name_col]} (Code: {r[code_col]})", axis=1).tolist()
    selected_emp_str = c2.selectbox("👤 Select Employee", emp_options)
    # Extract recipient info
    target_code = selected_emp_str.split("(Code: ")[-1].replace(")", "")
    target_name = selected_emp_str.split(" (Code:")[0]
    # Message fields
    req_text = st.text_area("📝 Request Details", height=150, placeholder="Type your request or instructions here...")
    up_files = st.file_uploader("📎 Attach Files (Any format supported)", accept_multiple_files=True)
    if st.button("🚀 Submit Ask"):
        if not req_text.strip():
            st.error("❌ Please write a message.")
        else:
            r_df = load_hr_requests()
            nid = int(r_df["ID"].max()) + 1 if not r_df.empty else 1
            hr_c = str(user.get("Employee Code", "HR")).replace(".0", "")
            # Save files
            saved_filenames = []
            if up_files:
                os.makedirs("hr_request_files", exist_ok=True)
                for f in up_files:
                    fn = f"req_{nid}_{target_code}_{f.name}"
                    with open(os.path.join("hr_request_files", fn), "wb") as out: out.write(f.getbuffer())
                    saved_filenames.append(fn)
            # Add request row
            nr = pd.DataFrame([{
                "ID": nid,
                "HR Code": hr_c,
                "Employee Code": target_code,
                "Employee Name": target_name,
                "Request": req_text.strip(),
                "File Attached": ",".join(saved_filenames),
                "Status": "Pending",
                "Response": "",
                "Response File": "",
                "Date Sent": pd.Timestamp.now().isoformat(),
                "Date Responded": None
            }])
            if save_hr_requests(pd.concat([r_df, nr], ignore_index=True)):
                add_notification(target_code, "", f"📬 New HR Request (ID: {nid})")
                st.success(f"✅ Your message has been sent successfully to {target_name}!")
                st.balloons()
                st.rerun()
            else:
                st.error("❌ Failed to save request.")
# ============================
# 🆕 PAGE: REQUEST HR (Employees) — UPDATED
# ============================
def page_request_hr(user):
    st.subheader("📥 Request HR")
    st.info("Below are the messages and requests sent to you from the HR department. You can reply and attach files if needed.")
    user_code = str(user.get("Employee Code", "N/A")).replace(".0", "")
    r_df = load_hr_requests()
    if r_df.empty:
        st.info("📭 No messages from HR yet.")
        return
    u_reqs = r_df[r_df["Employee Code"].astype(str) == user_code].sort_values("Date Sent", ascending=False).reset_index(drop=True)
    if u_reqs.empty:
        st.info("📭 No messages for you.")
        return
    for idx, row in u_reqs.iterrows():
        status_color = "#f59e0b" if row["Status"] == "Pending" else "#10b981"
        with st.container():
            st.markdown(f"""
<div class="hr-message-card" style="border-left-color: {status_color};">
<div style="display: flex; justify-content: space-between; align-items: center;">
<span class="hr-message-title">📄 Message ID: {row['ID']}</span>
<span style="color: {status_color}; font-weight: bold; background: #f9fafb; padding: 2px 8px; border-radius: 4px;">{row['Status']}</span>
</div>
<div class="hr-message-body"><b>From HR:</b> {row['Request']}</div>
<small>📅 Sent: {pd.to_datetime(row['Date Sent']).strftime('%d-%m-%Y %H:%M') if pd.notna(row['Date Sent']) else "N/A"}</small>
</div>
""", unsafe_allow_html=True)
            # HR Attachments
            if row["File Attached"]:
                f_list = str(row["File Attached"]).split(",")
                for fn in f_list:
                    fp = os.path.join("hr_request_files", fn)
                    if os.path.exists(fp):
                        with open(fp, "rb") as f: st.download_button(f"📥 Download HR Attachment: {fn}", f, file_name=fn, key=f"dl_hr_f_{row['ID']}_{fn}")
            # Action Area
            if row["Status"] == "Pending":
                with st.expander("✍️ Write your response"):
                    rt = st.text_area("Your Answer", key=f"resp_t_{idx}")
                    up_f = st.file_uploader("Attach Files (Optional)", key=f"resp_f_{idx}", accept_multiple_files=True)
                    if st.button("🚀 Submit Message", key=f"sub_btn_{idx}"):
                        if not rt.strip() and not up_f:
                            st.warning("⚠️ Please provide an answer or a file.")
                        else:
                            saved_resp_files = []
                            if up_f:
                                os.makedirs("hr_response_files", exist_ok=True)
                                for rf in up_f:
                                    rfn = f"resp_{row['ID']}_{user_code}_{rf.name}"
                                    with open(os.path.join("hr_response_files", rfn), "wb") as out: out.write(rf.getbuffer())
                                    saved_resp_files.append(rfn)
                            # Update records
                            r_df.loc[r_df["ID"] == row["ID"], ["Response", "Status", "Date Responded", "Response File"]] = [rt.strip(), "Completed", pd.Timestamp.now().isoformat(), ",".join(saved_resp_files)]
                            save_hr_requests(r_df)
                            add_notification("", "HR", f"✅ Emp {user_code} responded to HR Request ID: {row['ID']}")
                            st.success("✅ Your reply has been sent successfully!")
                            st.rerun()
            else:
                st.success("✅ Responded")
                st.write(f"**Your Answer:** {row['Response']}")
                if row["Response File"]:
                    st.write("📎 **Your Attachments:**")
                    rf_list = str(row["Response File"]).split(",")
                    for rfn in rf_list:
                        st.caption(f"✅ {rfn}")
# ============================
#  page_hr_inbox — UPDATED 
# ============================
def page_hr_inbox(user):
    st.subheader("📬 HR Inbox")
    tab1, tab2 = st.tabs(["💬 Employee Inquiries", "📩 Responses to HR Requests"])
    with tab1:
        hr_df = load_hr_queries()
        if hr_df.empty:
            st.info("No inquiries yet.")
        else:
            try:
                hr_df["Date Sent_dt"] = pd.to_datetime(hr_df["Date Sent"], errors="coerce")
                hr_df = hr_df.sort_values("Date Sent_dt", ascending=False).reset_index(drop=True)
            except: hr_df = hr_df.reset_index(drop=True)
            for idx, row in hr_df.iterrows():
                ec, en, sb, ms, st_val = str(row.get('Employee Code', '')), row.get('Employee Name', ''), row.get('Subject', ''), row.get("Message", ''), row.get('Status', '')
                dt = pd.to_datetime(row.get("Date Sent")).strftime('%d-%m-%Y %H:%M') if pd.notna(row.get("Date Sent")) else ""
                # Status colors
                status_color = "#f59e0b" if st_val == "Pending" else "#10b981" if st_val == "Replied" else "#6b7280"
                st.markdown(f"""
<div class="hr-message-card" style="border-left-color: {status_color};">
<div class="hr-message-title" style="color: #05445E;">📌 {sb if sb else "No Subject"}</div>
<div style="display: flex; justify-content: space-between; margin: 5px 0;">
<span style="color: #05445E; font-weight: 500;">👤 {en} — {ec}</span>
<span style="color: {status_color}; font-weight: bold; font-size: 0.9rem;">{st_val}</span>
</div>
<div class="hr-message-body" style="color: #2E2E2E;">{ms}</div>
<small style="color: #6b7280;">🕒 {dt}</small>
</div>
""", unsafe_allow_html=True)
                if row.get("Reply"): st.markdown(f"**🟢 HR Reply:**\n{row['Reply']}")
                c1, c2 = st.columns([1, 4])
                if c1.button("🗂️ Close", key=f"cl_q_{idx}"):
                    hr_df.at[idx, ["Status", "Date Replied"]] = ["Closed", pd.Timestamp.now()]
                    save_hr_queries(hr_df)
                    st.success("Closed."); st.rerun()
                rt = st.text_area("✍️ Write reply", key=f"r_q_{idx}", height=100)
                col1, col2, col3 = st.columns([2, 2, 1])
                if col1.button("✅ Send Reply", key=f"sr_q_{idx}") and rt.strip():
                    hr_df.at[idx, ["Reply", "Status", "Date Replied"]] = [rt, "Replied", pd.Timestamp.now()]
                    save_hr_queries(hr_df)
                    add_notification(ec, "", f"HR replied to: {sb}")
                    st.success("Sent!"); st.rerun()
                if col3.button("🗑️ Delete", key=f"di_q_{idx}"):
                    save_hr_queries(hr_df.drop(idx).reset_index(drop=True))
                    st.success("Deleted!"); st.rerun()
                st.markdown("---")
    with tab2:
        req_df = load_hr_requests()
        resps = req_df[req_df["Status"] == "Completed"].sort_values("Date Responded", ascending=False)
        if resps.empty:
            st.info("No responses from employees yet.")
        else:
            for idx, row in resps.iterrows():
                st.markdown(f"""
<div class="hr-message-card" style="border-left-color: #10b981;">
<div style="color: #05445E; font-weight: bold;">✅ Response from: {row['Employee Name']} ({row['Employee Code']})</div>
<div style="background: #f3f4f6; padding: 10px; border-radius: 8px; margin: 8px 0;">
<small><b>HR Original Request:</b> {row['Request']}</small>
</div>
<div style="color: #2E2E2E;"><b>Answer:</b> {row['Response']}</div>
<small>🕒 Received: {pd.to_datetime(row['Date Responded']).strftime('%d-%m-%Y %H:%M') if pd.notna(row['Date Responded']) else "N/A"}</small>
</div>
""", unsafe_allow_html=True)
                if row["Response File"]:
                    for fn in str(row["Response File"]).split(","):
                        fp = os.path.join("hr_response_files", fn)
                        if os.path.exists(fp):
                            with open(fp, "rb") as f: st.download_button(f"📥 Download {fn}", f, file_name=fn, key=f"hr_dl_resp_{idx}_{fn}")
                st.markdown("---")
# ============================
#  Recruitment Management 
# ============================
def page_recruitment(user):
    st.subheader("👥 Recruitment Management")
    if user.get("Title", "").upper() != "HR": return
    st.markdown(f'<div style="background-color:white; padding:12px; border-radius:8px; border:1px solid #05445E; margin-bottom:20px;"><h4>📝 Candidate Application Form</h4><a href="{GOOGLE_FORM_RECRUITMENT_LINK}" target="_blank">👉 Apply via Google Form</a></div>', unsafe_allow_html=True)
    t_cv, t_db = st.tabs(["📄 CV Candidates", "📊 Recruitment Database"])
    with t_cv:
        up_cv, c_name = st.file_uploader("Upload CV", type=["pdf", "doc", "docx"]), st.text_input("Candidate Name")
        if up_cv and st.button("✅ Save CV"):
             fn = save_recruitment_cv(up_cv);
            st.success(f"Saved: `{fn}`")
             if c_name: add_notification("", "HR", f"New CV: {c_name}");
            st.rerun()
        cv_files = sorted(os.listdir(RECRUITMENT_CV_DIR), reverse=True) if os.path.exists(RECRUITMENT_CV_DIR) else []
        for cv in cv_files:
            c1, c2 = st.columns([4, 1])
            c1.markdown(f"📄 `{cv}`")
            with c2:
                with open(os.path.join(RECRUITMENT_CV_DIR, cv), "rb") as f: st.download_button("📥", f, file_name=cv, key=f"dl_{cv}")
    with t_db:
         up_db = st.file_uploader("Upload Google Forms Excel", type=["xlsx"])
        if up_db:
            ndf = pd.read_excel(up_db);
            st.dataframe(ndf.head(10))
            if st.button("✅ Replace Database"): save_json_file(ndf, RECRUITMENT_DATA_FILE); st.success("Updated!");
            st.rerun()
        db_df = load_json_file(RECRUITMENT_DATA_FILE)
        if not db_df.empty:
            st.dataframe(db_df, use_container_width=True)
            buf = BytesIO();
            with pd.ExcelWriter(buf, engine="openpyxl") as w: db_df.to_excel(w, index=False)
            st.download_button("📥 Download Database", data=buf.getvalue(), file_name="Recruitment_Data.xlsx")
# ============================
#  System Settings [: 291]
# ============================
def page_settings(user):
    st.subheader("⚙️ System Settings")
    if user.get("Title", "").upper() != "HR": return
    t3, t4 = st.tabs(["🧾 Templates", "💾 Backup"])
    with t3:
        up_t = st.file_uploader("Salary Template", type=["xlsx"])
        if up_t:
            with open("salary_template.xlsx", "wb") as f: f.write(up_t.getbuffer())
            st.success("Template updated.")
        up_l = st.file_uploader("Logo", type=["png", "jpg", "jpeg"])
        if up_l:
            with open("logo.jpg", "wb") as f: f.write(up_l.getbuffer())
            st.success("Logo updated.")
    with t4:
        if st.button("Create Backup Zip"):
            bn = f"backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
            with zipfile.ZipFile(bn, "w") as z:
                for f in [DEFAULT_FILE_PATH, LEAVES_FILE_PATH, NOTIFICATIONS_FILE_PATH, HR_QUERIES_FILE_PATH, HR_REQUESTS_FILE_PATH, SALARIES_FILE_PATH]:
                    if os.path.exists(f): z.write(f)
                if os.path.exists("employee_photos"):
                    for p in os.listdir("employee_photos"): z.write(os.path.join("employee_photos", p))
            with open(bn, "rb") as f: st.download_button("📥 Download Backup ZIP", f, file_name=bn)
# ============================
#  Dashboard [: 294]
# ============================
def page_dashboard(user):
    st.subheader("Dashboard")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty: return
    cm = {c.lower(): c for c in df.columns}
    d_col, h_col = cm.get("department"), cm.get("hire date") or cm.get("hire_date")
    total, depts, hires = df.shape[0], (df[d_col].nunique() if d_col else 0), 0
    if h_col:
        try:
            df[h_col] = pd.to_datetime(df[h_col], errors="coerce")
            hires = df[df[h_col] >= (pd.Timestamp.now() - pd.Timedelta(days=30))].shape[0]
        except: hires = 0
    c1, c2, c3 = st.columns(3)
    c1.metric("Total Employees", total);
    c2.metric("Departments", depts); c3.metric("New Hires (30 days)", hires)
    if d_col:
        dc = df[d_col].fillna("Unknown").value_counts().reset_index();
        dc.columns = ["Department", "Count"]
        st.table(dc.sort_values("Count", ascending=False).reset_index(drop=True))
    buf = BytesIO();
    with pd.ExcelWriter(buf, engine="openpyxl") as w: df.to_excel(w, index=False)
    st.download_button("Download Full Employees Excel", data=buf.getvalue(), file_name="employees_export.xlsx")
    if st.button("Save & Push current dataset to GitHub"):
        s, p = save_and_maybe_push(df, actor=user.get("Employee Name","HR"))
        if s: st.success("Saved!");
        if p: st.success("Pushed!")
# ============================
#  Reports [: 299]
# ============================
def page_reports(user):
    st.subheader("Reports")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty: return
    st.dataframe(df.head(200), use_container_width=True)
    buf = BytesIO();
    with pd.ExcelWriter(buf, engine="openpyxl") as w: df.to_excel(w, index=False)
    st.download_button("Export Report Data (Excel)", data=buf.getvalue(), file_name="report_employees.xlsx")
# ============================
#  page_ask_hr [: 300]
# ============================
def page_ask_hr(user):
    st.subheader("💬 Ask HR")
    u_c = str(user.get("Employee Code", "")).replace(".0", "")
    u_n = user.get("Employee Name", u_c)
    hr_df = load_hr_queries()
    with st.form("ask_hr"):
        sb, ms = st.text_input("Subject"), st.text_area("Message")
        if st.form_submit_button("Send to HR") and sb.strip() and ms.strip():
            nr = pd.DataFrame([{"Employee Code": u_c, "Employee Name": u_n, "Subject": sb.strip(), "Message": ms.strip(), "Reply": "", "Status": "Pending", "ID": (int(hr_df["ID"].max()) + 1) if not hr_df.empty else 1, "Date Sent": pd.Timestamp.now(), "Date Replied": pd.NaT}])
            if save_hr_queries(pd.concat([hr_df, nr], ignore_index=True)):
                add_notification("", "HR", f"New message from {u_n}");
                st.success("Sent!"); st.rerun()
    u_msgs = hr_df[hr_df["Employee Code"].astype(str) == u_c].sort_values("Date Sent", ascending=False)
    for i, r in u_msgs.iterrows():
        dt = pd.to_datetime(r["Date Sent"]).strftime('%d-%m-%Y %H:%M') if pd.notna(r["Date Sent"]) else ""
        st.markdown(f'<div class="hr-message-card"><div class="hr-message-title">📌 {r["Subject"]}</div><div class="hr-message-meta">🕒 {dt} | 🏷️ {r["Status"]}</div><div class="hr-message-body">{r["Message"]}</div></div>', unsafe_allow_html=True)
        if r.get("Reply"): st.markdown(f"**HR Reply:**\n<div style='background-color:#e0f2fe; padding:10px; border-radius:6px;'>{r['Reply']}</div>", unsafe_allow_html=True)
# ============================
# Main App Logic - MODIFIED SIDEBAR NAVIGATION [ : 308]
# ============================
def main():
    render_logo_and_title()
    if "df" not in st.session_state: ensure_session_df()
    if "logged_in" not in st.session_state: st.session_state["logged_in"], st.session_state["user"] = False, None
    if not st.session_state["logged_in"]:
        st.sidebar.markdown('<div class="sidebar-title">🔐 Login</div>', unsafe_allow_html=True)
        with st.sidebar.form("login"):
            code, passw = st.text_input("Employee Code"), st.text_input("Password", type="password")
            if st.form_submit_button("Login"):
                df = st.session_state.get("df", pd.DataFrame())
                if df.empty:
                    st.error("Data missing.")
                else:
                    u = login(df, code, passw)
                    if u:
                        st.session_state["logged_in"], st.session_state["user"] = True, u;
                        st.rerun()
                    else: st.error("Invalid credentials.")
        if st.sidebar.button("🔑 Forgot Password"): st.session_state["show_fp"] = True;
        if st.session_state.get("show_fp"): page_forgot_password()
        return
    user = st.session_state["user"];
    ut = str(user.get("Title", "")).strip().upper()
    is_hr, is_bum, is_am, is_dm, is_mr, is_sp = ut=="HR", ut=="BUM", ut=="AM", ut=="DM", ut=="MR", ut in ["ASSOCIATE COMPLIANCE", "FIELD COMPLIANCE SPECIALIST", "COMPLIANCE MANAGER"]
    if is_hr: pages = ["Dashboard", "Reports", "HR Manager", "HR Inbox", "Employee Photos", "Ask Employees", "Recruitment", "🎓 Employee Development (HR View)", "Notifications", "Structure", "Salary Monthly", "Salary Report", "Settings"]
    elif is_bum: pages = ["My Profile", "Team Leaves", "🎓 Team Development", "Ask HR", "Request HR", "Notifications", "Structure", "Salary Monthly"]
    elif is_am or is_dm: pages = ["My Profile", "🎓 Team Development", "Ask HR", "Request HR", "Notifications", "Structure", "Salary Monthly"]
    elif is_mr: pages = ["My Profile", "🚀 IDB – Individual Development Blueprint", "🌱 Self Development", "Notify Compliance", "Ask HR", "Request HR", "Notifications", "Structure", "Salary Monthly"]
    elif is_sp: pages = ["My Profile", "Leave Request", "Ask HR", "Request HR", "Notifications", "Structure", "Salary Monthly", "📋 Report Compliance"]
    else: pages = ["My Profile", "Ask HR", "Request HR", "Notifications", "Structure", "Salary Monthly"]
    # Profile Card
    st.sidebar.markdown(f'<div class="profile-card-top"><h4>👤 {user.get("Employee Name")}</h4><p>🔖 {ut}</p><p>🆔 {user.get("Employee Code")}</p></div>', unsafe_allow_html=True)
    st.sidebar.markdown('<div class="sidebar-title">👥 Navigation</div>', unsafe_allow_html=True)
    cur_p = st.sidebar.radio("Go to", pages, index=0);
    unread = get_unread_count(user)
    if unread > 0: st.sidebar.markdown(f'<div class="notification-bell">{unread}</div>', unsafe_allow_html=True)
    st.sidebar.markdown("---")
    if st.sidebar.button("🚪 Logout"):
        st.session_state["logged_in"] = False;
        st.session_state["user"] = None; st.rerun()
    # Routing
    if cur_p == "Dashboard": page_dashboard(user)
    elif cur_p == "Reports": page_reports(user)
    elif cur_p == "HR Manager": page_hr_manager(user) if is_hr else st.error("Denied.")
    elif cur_p == "HR Inbox": page_hr_inbox(user) if is_hr else st.error("Denied.")
    elif cur_p == "Employee Photos": page_employee_photos(user) if is_hr else st.error("Denied.")
    elif cur_p == "Ask Employees": page_ask_employees(user) if is_hr else st.error("Denied.")
    elif cur_p == "Recruitment": page_recruitment(user) if is_hr else st.error("Denied.")
    elif cur_p == "🎓 Employee Development (HR View)": page_hr_development(user) if is_hr else st.error("Denied.")
    elif cur_p == "🎓 Team Development": page_manager_development(user) if (is_bum or is_am or is_dm) else st.error("Denied.")
    elif cur_p == "My Profile": page_my_profile(user)
    elif cur_p == "Team Leaves": page_manager_leaves(user) if (is_bum or is_am or is_dm) else st.error("Denied.")
    elif cur_p == "Leave Request": page_leave_request(user)
    elif cur_p == "Ask HR": page_ask_hr(user)
    elif cur_p == "Request HR": page_request_hr(user)
    elif cur_p == "Notify Compliance": page_notify_compliance(user) if is_mr else st.error("Denied.")
    elif cur_p == "📋 Report Compliance": page_report_compliance(user) if (is_sp or is_bum or is_am or is_dm) else st.error("Denied.")
    elif cur_p == "🚀 IDB – Individual Development Blueprint": page_idb_mr(user) if is_mr else st.error("Denied.")
    elif cur_p == "🌱 Self Development": page_self_development(user) if is_mr else st.error("Denied.")
    elif cur_p == "Notifications": page_notifications(user)
    elif cur_p == "Structure": page_directory(user)
    elif cur_p == "Salary Monthly": page_salary_monthly(user)
    elif cur_p == "Salary Report": page_salary_report(user) if is_hr else st.error("Denied.")
    elif cur_p == "Settings": page_settings(user) if is_hr else st.error("Denied.")
if __name__ == "__main__":
    main()
