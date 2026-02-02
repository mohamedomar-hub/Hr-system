# hr_system_with_config_json.py — FULLY CONVERTED TO JSON (ALL FIXES APPLIED) + BUTTON TEXT & FILE UPLOAD MODIFICATIONS + SIDEBAR BUTTONS + COMMUNICATION FIX
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
# HR QUERIES FILE PATH
# ============================
HR_QUERIES_FILE = "hr_queries.json"

# ============================
# HR REQUESTS FILE PATH
# ============================
HR_REQUESTS_FILE = "hr_requests.json"

# ============================
# SALARY ENCRYPTION SETUP (Secure: from Streamlit Secrets)
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
            # If decoding fails, assume it's plain text (e.g., transitional file)
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
# 🆕 FUNCTION: Load & Save HR Queries (FIXED: No sanitize_employee_data + Success Flags)
# ============================
def load_hr_queries():
    return load_json_file(HR_QUERIES_FILE, default_columns=[
        "Employee Code", "Employee Name", "Subject", "Message", "Reply", "Status", "Date Sent", "Date Replied"
    ])

def save_hr_queries(df):
    df = df.copy()
    if "Date Sent" in df.columns:
        df["Date Sent"] = pd.to_datetime(df["Date Sent"], errors="coerce").astype(str)
    if "Date Replied" in df.columns:
        df["Date Replied"] = pd.to_datetime(df["Date Replied"], errors="coerce").astype(str)
    if "ID" in df.columns:
        df["ID"] = pd.to_numeric(df["ID"], errors="coerce")
        if df["ID"].isna().any():
            existing_max = int(df["ID"].max(skipna=True)) if not df["ID"].isna().all() else 0
            for idx in df[df["ID"].isna()].index:
                existing_max += 1
                df.at[idx, "ID"] = existing_max
        df["ID"] = df["ID"].astype(int)
    # ✅ FIXED: Save directly without applying sanitize_employee_data
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(HR_QUERIES_FILE) if os.path.dirname(HR_QUERIES_FILE) else ".", exist_ok=True)
        data = df.where(pd.notnull(df), None).to_dict(orient='records')
        with open(HR_QUERIES_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        st.error(f"❌ Save failed: {str(e)}")
        st.error(f"💡 Check: 1) Write permissions 2) Disk space 3) File not locked by another process")
        return False

# ============================
# 🆕 FUNCTION: Load & Save HR Requests
# ============================
def load_hr_requests():
    return load_json_file(HR_REQUESTS_FILE, default_columns=[
        "ID", "HR Code", "Employee Code", "Employee Name", "Request", "File Attached", "Status", "Response", "Response File", "Date Sent", "Date Responded"
    ])

def save_hr_requests(df):
    return save_json_file(df, HR_REQUESTS_FILE)

# ============================
# 🆕 FUNCTION: Save Request File
# ============================
def save_request_file(uploaded_file, emp_code, req_id):
    os.makedirs("hr_request_files", exist_ok=True)
    ext = uploaded_file.name.split(".")[-1].lower()
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"req_{emp_code}_{req_id}_{timestamp}.{ext}"
    filepath = os.path.join("hr_request_files", filename)
    with open(filepath, "wb") as f:
        f.write(uploaded_file.getbuffer())
    return filename

# ============================
# 🆕 FUNCTION: Save Response File
# ============================
def save_response_file(uploaded_file, emp_code, req_id):
    os.makedirs("hr_response_files", exist_ok=True)
    ext = uploaded_file.name.split(".")[-1].lower()
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"resp_{emp_code}_{req_id}_{timestamp}.{ext}"
    filepath = os.path.join("hr_response_files", filename)
    with open(filepath, "wb") as f:
        f.write(uploaded_file.getbuffer())
    return filename

# ============================
# 🆕 FUNCTION: Sanitize employee data (APPLY YOUR 4 RULES + Private Email)
# ============================
def sanitize_employee_data(df: pd.DataFrame) -> pd.DataFrame:
    """
    Applies the following rules:
    1. Drop 'annual_leave_balance' column if exists.
    2. Drop 'monthly_salary' column if exists.
    3. Hide 'E-Mail' for anyone NOT in ['BUM', 'AM', 'DM'].
    4. Keep 'Private Email' column but hide it from general display (will be shown only in My Profile)
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
    # Rule 4: Private Email is kept in the dataframe but will be controlled manually in display
    # We do NOT hide it here because we need it accessible for My Profile page
    return df

# ============================
# 🆕 FUNCTION: Load & Save IDB Reports (FIXED: Added Employee Name)
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
            "google_form_link": "https://docs.google.com/forms/d/e/1FAIpQLSccvOVVSrKDRAF-4rOt0N_rEr8SmQ2F6cVRSwk7RGjMoRhpLQ/viewform"
        },
        "system": {
            "logo_path": "logo.jpg",
            "default_annual_leave_days": 21
        }
    }
    try:
        with open("config.json", "r", encoding="utf-8") as f:
            user_config = json.load(f)
        def deep_merge(a, b):
            for k, v in b.items():
                if isinstance(v, dict) and k in a and isinstance(a[k], dict):
                    deep_merge(a[k], v)
                else:
                    a[k] = v
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
# Configuration from CONFIG
# ============================
DEFAULT_FILE_PATH = CONFIG["file_paths"]["employees"]
LEAVES_FILE_PATH = CONFIG["file_paths"]["leaves"]
NOTIFICATIONS_FILE_PATH = CONFIG["file_paths"]["notifications"]
HR_QUERIES_FILE_PATH = CONFIG["file_paths"]["hr_queries"]
HR_REQUESTS_FILE_PATH = CONFIG["file_paths"]["hr_requests"]
SALARIES_FILE_PATH = CONFIG["file_paths"]["salaries"]
# LOGO_PATH = CONFIG["system"]["logo_path"]  # ← تم حذف هذا السطر
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
# 🔐 Secure Password Management (bcrypt-based)
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
# JSON File Helpers (REPLACES EXCEL) — ✅ MODIFIED TO ENCRYPT SALARIES BEFORE SAVING
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
        # Ensure directory exists
        os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else ".", exist_ok=True)
        # Save encrypted version to disk
        data = df_copy.where(pd.notnull(df_copy), None).to_dict(orient='records')
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        st.error(f"Save error: {str(e)}")
        return False

# ============================
# Styling - Modern Light Mode CSS (Updated per your request) - ✅ ENHANCED SIDEBAR BUTTONS
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

# ✅ تم دمج التعديلات: توحيد لون نصوص الأزرار + تحسين مظهر File Upload + SIDEBAR BUTTONS
updated_css = """
<style>
/* ========== COLORS SYSTEM ========== */
:root {
    --primary: #05445E;
    --secondary: #0A5C73;
    --accent-blue: #3B82F6;
    --accent-blue-light: #BFDBFE;
    --text-main: #2E2E2E;
    --text-muted: #6B7280;
    --card-bg: #FFFFFF;
    --soft-bg: #F2F6F8;
    --border-soft: #E5E7EB;
    --file-upload-bg: #FFFFFF;
    --file-upload-border: #E5E7EB;
    --file-upload-hover: #F9FAFB;
}
/* ========== GENERAL TEXT ========== */
html, body, p, span, label {
    color: var(--text-main) !important;
}
/* ========== HEADERS ========== */
h1, h2, h3, h4, h5 {
    color: var(--primary) !important;
    font-weight: 600;
}
/* ========== SIDEBAR USER NAME ========== */
section[data-testid="stSidebar"] h4,
section[data-testid="stSidebar"] h5,
section[data-testid="stSidebar"] p {
    color: #FFFFFF !important;
    font-weight: 600;
}
/* ========== INPUT LABELS ========== */
label {
    color: var(--primary) !important;
    font-weight: 500;
}
/* ========== CARDS ========== */
.card {
    background-color: var(--card-bg);
    border-radius: 16px;
    padding: 18px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.06);
    border: 1px solid var(--border-soft);
}
/* ========== INFO TEXT (No data, help text) ========== */
.info-text {
    color: var(--text-muted) !important;
    font-size: 14px;
}
/* ========== SECTION HEADER BOX ========== */
.section-box {
    background-color: var(--soft-bg);
    padding: 14px 20px;
    border-radius: 14px;
    margin: 25px 0 15px 0;
}
/* إضافات ضرورية للوظائف */
.sidebar-title {
    font-size: 1.4rem;
    font-weight: bold;
    color: #FFFFFF;
    text-align: center;
    margin-bottom: 10px;
    text-shadow: 0 2px 4px rgba(0,0,0,0.3);
}
.hr-message-card {
    background-color: #FFFFFF;
    border-left: 4px solid var(--primary);
    padding: 12px;
    margin: 10px 0;
    border-radius: 8px;
    box-shadow: 0 2px 6px rgba(0,0,0,0.05);
}
.hr-message-title {
    color: var(--primary);
    font-weight: bold;
    font-size: 1.1rem;
}
.hr-message-meta {
    color: #666666;
    font-size: 0.9rem;
    margin: 4px 0;
}
.hr-message-body {
    color: var(--text-main) !important;
    margin-top: 6px;
}
.leave-balance-card,
.team-structure-card {
    background-color: #FFFFFF !important;
    border-radius: 8px;
    padding: 12px;
    text-align: center;
    border: 1px solid #E6E6E6;
    box-shadow: 0 2px 6px rgba(0,0,0,0.05);
}
.leave-balance-title,
.team-structure-title {
    color: #666666;
    font-size: 0.9rem;
}
.leave-balance-value,
.team-structure-value {
    color: var(--primary);
    font-size: 1.4rem;
    font-weight: bold;
    margin-top: 4px;
}
.leave-balance-value.used {
    color: #dc2626;
}
.leave-balance-value.remaining {
    color: #059669;
}
.team-structure-value.am { color: var(--primary); }
.team-structure-value.dm { color: var(--secondary); }
.team-structure-value.mr { color: #dc2626; }
.notification-bell {
    position: absolute;
    top: 20px;
    right: 20px;
    background-color: #ef4444;
    color: white;
    width: 24px;
    height: 24px;
    border-radius: 50%;
    display: flex;
    justify-content: center;
    align-items: center;
    font-weight: bold;
    font-size: 0.8rem;
    z-index: 100;
}
/* ========== SIDEBAR BUTTONS - SKY BLUE WITH WHITE TEXT ========== */
section[data-testid="stSidebar"] div[data-testid="stVerticalBlock"] > div:first-child {
    padding: 0 !important;
}
section[data-testid="stSidebar"] div[data-testid="stVerticalBlock"] button {
    background-color: var(--accent-blue) !important;
    color: white !important;
    border: none !important;
    font-weight: 600 !important;
    padding: 0.8rem 1rem !important;
    border-radius: 8px !important;
    text-align: left !important;
    margin: 4px 0 !important;
    width: 100% !important;
    box-shadow: 0 2px 4px rgba(59, 130, 246, 0.2) !important;
    transition: all 0.3s ease !important;
    height: auto !important;
    min-height: 45px !important;
}
section[data-testid="stSidebar"] div[data-testid="stVerticalBlock"] button:hover {
    background-color: #2563eb !important;
    color: white !important;
    box-shadow: 0 3px 6px rgba(59, 130, 246, 0.3) !important;
    transform: translateY(-1px) !important;
}
section[data-testid="stSidebar"] div[data-testid="stVerticalBlock"] button:active {
    background-color: #1d4ed8 !important;
    transform: translateY(0) !important;
}
section[data-testid="stSidebar"] div[data-testid="stVerticalBlock"] button:disabled {
    opacity: 0.6 !important;
    background-color: #93c5fd !important;
}
/* Ensure all text elements inside sidebar buttons are white */
section[data-testid="stSidebar"] div[data-testid="stVerticalBlock"] button,
section[data-testid="stSidebar"] div[data-testid="stVerticalBlock"] button *,
section[data-testid="stSidebar"] div[data-testid="stVerticalBlock"] button span,
section[data-testid="stSidebar"] div[data-testid="stVerticalBlock"] button div,
section[data-testid="stSidebar"] div[data-testid="stVerticalBlock"] button p,
section[data-testid="stSidebar"] div[data-testid="stVerticalBlock"] button label {
    color: white !important !important;
    font-weight: 600 !important;
}
/* ========== BUTTONS - ALL TEXT WHITE ========== */
/* الأزرار الرئيسية - نص أبيض واضح */
.stButton > button {
    background-color: var(--primary) !important;
    color: white !important;
    border: none !important;
    font-weight: 600 !important;
    padding: 0.6rem 1.2rem !important;
    border-radius: 8px !important;
    text-shadow: 0 1px 2px rgba(0,0,0,0.2) !important;
    box-shadow: 0 3px 6px rgba(5, 68, 94, 0.25) !important;
    transition: all 0.3s ease !important;
    min-height: 42px !important;
    font-size: 15px !important;
}
/* ضمان أن جميع العناصر الداخلية للزر تكون بيضاء - شامل */
.stButton > button,
.stButton > button *,
.stButton > button span,
.stButton > button div,
.stButton > button p,
.stButton > button label,
.stButton > button .stMarkdown,
.stButton > button .stText {
    color: white !important !important;
    text-shadow: 0 1px 2px rgba(0,0,0,0.2) !important;
    font-weight: 600 !important;
    font-size: 15px !important;
}
/* عند التمرير بالفأرة - أحمر مع نص أبيض */
.stButton > button:hover {
    background-color: #dc2626 !important;
    color: white !important !important;
    box-shadow: 0 4px 8px rgba(220, 38, 38, 0.35) !important;
    transform: translateY(-2px) !important;
}
/* ضمان بقاء النص أبيض عند التمرير */
.stButton > button:hover,
.stButton > button:hover *,
.stButton > button:hover span,
.stButton > button:hover div,
.stButton > button:hover p,
.stButton > button:hover label,
.stButton > button:hover .stMarkdown,
.stButton > button:hover .stText {
    color: white !important !important;
    text-shadow: 0 1px 3px rgba(0,0,0,0.3) !important;
}
/* للزر المُعطَّل - نص أبيض فاتح */
.stButton > button:disabled {
    opacity: 0.7 !important;
    color: #f8f9fa !important !important;
    background-color: #9CA3AF !important;
}
.stButton > button:disabled,
.stButton > button:disabled *,
.stButton > button:disabled span,
.stButton > button:disabled div,
.stButton > button:disabled p {
    color: #f8f9fa !important !important;
}
/* ========== FILE UPLOADER - IMPROVED APPEARANCE (FIXED) ========== */
/* تحسين مظهر رفع الملفات */
.stFileUploader {
    width: 100% !important;
}
.stFileUploader > div {
    background-color: var(--file-upload-bg) !important;
    border: 2px dashed var(--file-upload-border) !important;
    border-radius: 10px !important;
    padding: 25px !important;
    transition: all 0.3s ease !important;
    color: var(--text-main) !important;
    background-image: linear-gradient(135deg, #f8fafc 0%, #e0f2fe 100%) !important;
}
/* عند التمرير على منطقة رفع الملفات */
.stFileUploader > div:hover {
    border-color: var(--accent-blue) !important;
    background-color: var(--file-upload-hover) !important;
    box-shadow: 0 4px 12px rgba(59, 130, 246, 0.15) !important;
    transform: scale(1.02) !important;
}
/* نص منطقة رفع الملفات */
.stFileUploader > div > section > p {
    color: var(--text-main) !important;
    font-size: 15px !important;
    font-weight: 500 !important;
    text-align: center !important;
    margin: 8px 0 !important;
}
/* أيقونة رفع الملفات */
.stFileUploader > div > section > svg {
    color: var(--accent-blue) !important;
    margin: 0 auto !important;
    display: block !important;
    width: 48px !important;
    height: 48px !important;
}
/* عند اختيار ملف - الخلفية تصبح زرقاء فاتحة */
.stFileUploader [data-testid="stFileUploaderDropzone"] {
    background-color: #dbeafe !important;
    border-color: var(--accent-blue) !important;
}
/* نص الملف المختار */
.stFileUploader [data-testid="stFileUploaderFileName"] {
    color: var(--primary) !important;
    font-weight: 600 !important;
    font-size: 14px !important;
}
/* زر إزالة الملف */
.stFileUploader [data-testid="stFileUploaderRemoveBtn"] {
    color: #dc2626 !important;
}
/* زر "Browse files" - تغيير لون النص والخلفية */
.stFileUploader [data-testid="baseButton-secondary"] {
    background-color: var(--accent-blue) !important;
    color: white !important;
    border: none !important;
    font-weight: 600 !important;
    padding: 0.6rem 1.2rem !important;
    border-radius: 8px !important;
    text-shadow: 0 1px 2px rgba(0,0,0,0.2) !important;
    box-shadow: 0 3px 6px rgba(59, 130, 246, 0.25) !important;
    min-height: 42px !important;
    font-size: 15px !important;
}
.stFileUploader [data-testid="baseButton-secondary"]:hover {
    background-color: #2563eb !important;
    color: white !important;
    box-shadow: 0 4px 8px rgba(59, 130, 246, 0.35) !important;
    transform: translateY(-2px) !important;
}
/* تأكيد تغيير لون نصوص الأزرار إلى الأبيض */
.stButton > button,
.stFileUploader [data-testid="baseButton-secondary"],
.stFileUploader > div > button {
    background-color: var(--primary) !important;
    color: white !important !important;
    border: none !important;
    font-weight: 600 !important;
    padding: 0.6rem 1.2rem !important;
    border-radius: 8px !important;
    text-shadow: 0 1px 2px rgba(0,0,0,0.2) !important;
    box-shadow: 0 3px 6px rgba(5, 68, 94, 0.25) !important;
    transition: all 0.3s ease !important;
    min-height: 42px !important;
    font-size: 15px !important;
}
/* عند التمرير على الأزرار */
.stButton > button:hover,
.stFileUploader [data-testid="baseButton-secondary"]:hover,
.stFileUploader > div > button:hover {
    background-color: #dc2626 !important;
    color: white !important !important;
    box-shadow: 0 4px 8px rgba(220, 38, 38, 0.35) !important;
    transform: translateY(-2px) !important;
}
/* الخلفية العامة */
[data-testid="stAppViewContainer"] {
    background-color: #F2F2F2 !important;
}
/* ضمان وضوح جميع النصوص */
body, .stApp, .stMarkdown, .stText, .stDataFrame, .stTable, .stSelectbox, .stTextInput, .stDateInput, .stTextArea {
    color: var(--text-main) !important;
}
/* تحسين الجداول */
table, td, th {
    color: var(--text-main) !important;
    background-color: #FFFFFF !important;
}
/* حقول الإدخال */
input[type="text"], input[type="password"], input[type="number"], textarea {
    color: var(--text-main) !important;
    background-color: #FFFFFF !important;
    border: 1px solid #E6E6E6 !important;
}
/* علامات التبويب */
.stTabs [data-baseweb="tab-list"] button {
    color: var(--text-main) !important;
}
.stTabs [data-baseweb="tab-panel"] {
    color: var(--text-main) !important;
    background-color: #FFFFFF !important;
}
/* إخفاء عناصر Streamlit */
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
div[data-testid="stDeployButton"] { display: none; }
</style>
"""
st.markdown(updated_css, unsafe_allow_html=True)

# ============================
# ✅ MODIFIED: External Password Change Page (No Login Required)
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
                # ✅ التحقق من وجود الموظف في ملف employees.json (وليس secure_passwords.json)
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
                # ✅ الآن: نسمح بإنشاء باسورد جديد بغض النظر عن وجود الهاش أو لا
                hashes[emp_code_clean] = hash_password(new_pwd)
                save_password_hashes(hashes)
                st.success("✅ Your password has been set successfully. You can now log in.")
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
    # Remove old photos for this employee
    for old_file in os.listdir("employee_photos"):
        if old_file.startswith(f"{emp_code_clean}."):
            os.remove(os.path.join("employee_photos", old_file))
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
# GitHub helpers (JSON version) — ✅ MODIFIED TO SANITIZE + ENCRYPT BEFORE UPLOAD
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
            # 🆕 Sanitize immediately after loading from GitHub
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
        # 🆕 Sanitize the data BEFORE encryption/upload
        df_temp = pd.DataFrame(data_list)
        df_sanitized = sanitize_employee_data(df_temp)
        data_list_sanitized = df_sanitized.to_dict(orient='records')
        # 🔒 Encrypt sensitive columns before uploading to GitHub
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
# Helpers
# ============================
def ensure_session_df():
    if "df" not in st.session_state:
        df_loaded = load_employee_data_from_github()
        if not df_loaded.empty:
            st.session_state["df"] = df_loaded
            initialize_passwords_from_data(df_loaded.to_dict(orient='records'))
        else:
            st.session_state["df"] = load_json_file(FILE_PATH)
            initialize_passwords_from_data(st.session_state["df"].to_dict(orient='records'))

# ============================
# Login & Save Helpers
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
        if key == "Employee Code":
            user_code = str(val).strip().replace(".0", "")
        if key == "Title":
            user_title = str(val).strip().upper()
    if not user_code and not user_title:
        return
    user_notifs = notifications[
        (notifications["Recipient Code"].astype(str) == user_code) |
        (notifications["Recipient Title"].astype(str).str.upper() == user_title)
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
<div style="
background-color: {bg_color};
border-left: 4px solid {color};
padding: 12px;
margin: 10px 0;
border-radius: 8px;
box-shadow: 0 2px 6px rgba(0,0,0,0.05);
">
<div style="display: flex; justify-content: space-between; align-items: flex-start;">
<div style="display: flex; align-items: center; gap: 10px; flex: 1;">
<span style="font-size: 1.3rem; color: {color};">{icon}</span>
<div>
<div style="color: {color}; font-weight: bold; font-size: 1.05rem;">
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
# 🆕 ADDITION: page_manager_leaves — Fully Implemented & FIXED
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
    # Filter team leaves using Manager Code (ensure consistent string format)
    leaves_df["Manager Code"] = leaves_df["Manager Code"].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
    team_leaves = leaves_df[leaves_df["Manager Code"] == manager_code].copy()
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
        # ✅ Add Download Button for Full History
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
# Salary Monthly Page — **FIXED: Works for ALL employees + Better error handling**
# ============================
def page_salary_monthly(user):
    st.subheader("💰 My Monthly Salary")
    # 🔹 Normalize logged-in employee code
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    try:
        # 🔹 Load salaries JSON
        if not os.path.exists(SALARIES_FILE_PATH):
            st.error(f"❌ Salary data file not found. Please contact HR.")
            st.info("💡 HR must upload salary data first via 'Salary Report' page.")
            return
        salary_df = load_json_file(SALARIES_FILE_PATH)
        if salary_df.empty:
            st.info("📭 No salary data available yet. HR will upload your salary records soon.")
            return
        # 🔹 Ensure required columns
        required_columns = ["Employee Code", "Month", "Basic Salary", "KPI Bonus", "Deductions"]
        missing_cols = [c for c in required_columns if c not in salary_df.columns]
        if missing_cols:
            st.error(f"❌ Missing columns in salary file: {missing_cols}")
            st.info("💡 Please contact HR to fix the salary data format.")
            return
        # 🔹 Normalize Employee Code column BEFORE filtering
        salary_df["Employee Code"] = (
            salary_df["Employee Code"]
            .astype(str)
            .str.strip()
            .str.replace(".0", "", regex=False)
        )
        # 🔹 Filter salaries for current user
        user_salaries = salary_df[salary_df["Employee Code"] == user_code].copy()
        if user_salaries.empty:
            st.info(f"📭 No salary records found for you (Code: {user_code}).")
            st.info("💡 Please contact HR to ensure your salary data is uploaded.")
            return
        # 🔐 Decrypt numeric columns FIRST
        for col in ["Basic Salary", "KPI Bonus", "Deductions"]:
            user_salaries[col] = user_salaries[col].apply(decrypt_salary_value)
        # 🧮 Calculate Net Salary safely
        user_salaries["Net Salary"] = (
            user_salaries["Basic Salary"]
            + user_salaries["KPI Bonus"]
            - user_salaries["Deductions"]
        )
        # 🔹 Sort by Month (optional but nice)
        user_salaries = user_salaries.reset_index(drop=True)
        # 🔘 Toggle full table
        if st.button("📊 Show All Details"):
            st.session_state["show_all_details"] = not st.session_state.get("show_all_details", False)
        if st.session_state.get("show_all_details", False):
            st.markdown("### All Salary Records")
            st.dataframe(
                user_salaries[["Month", "Basic Salary", "KPI Bonus", "Deductions", "Net Salary"]],
                use_container_width=True
            )
        # 🔹 Per-month detailed cards
        for idx, row in user_salaries.iterrows():
            month = row["Month"]
            btn_key = f"show_details_{month}_{idx}"
            if st.button(f"📄 Show Details for {month}", key=btn_key):
                st.session_state[f"salary_details_{month}"] = row.to_dict()
        for idx, row in user_salaries.iterrows():
            month = row["Month"]
            details_key = f"salary_details_{month}"
            if st.session_state.get(details_key):
                details = st.session_state[details_key]
                card = f"""
<div style="background-color:#f0fdf4; padding:14px; border-radius:10px;
margin-bottom:10px; box-shadow:0 4px 8px rgba(0,0,0,0.05);">
<h4 style="color:#05445E;">Salary Details – {details['Month']}</h4>
<p style="color:#666666;">💰 Basic Salary:
<b style="color:#05445E;">{details['Basic Salary']:.2f}</b></p>
<p style="color:#666666;">🎯 KPI Bonus:
<b style="color:#05445E;">{details['KPI Bonus']:.2f}</b></p>
<p style="color:#666666;">📉 Deductions:
<b style="color:#dc2626;">{details['Deductions']:.2f}</b></p>
<hr style="border-color:#cbd5e1;">
<p style="color:#666666;">🧮 Net Salary:
<b style="color:#059669;">{details['Net Salary']:.2f}</b></p>
</div>
"""
                st.markdown(card, unsafe_allow_html=True)
                # 📥 Download salary slip
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
                if st.button(f".Hide Details for {month}", key=f"hide_{month}"):
                    del st.session_state[details_key]
                    st.rerun()
    except Exception as e:
        st.error(f"❌ Error loading salary data: {str(e)}")
        st.info("💡 Please contact HR or system administrator for assistance.")

# ============================
# Salary Report Page — Encrypt on Upload (HR ONLY)
# ============================
def page_salary_report(user):
    st.subheader("📤 Upload Salary Report (HR Only)")
    st.info("Upload the monthly salary sheet. This will update salary data for all employees.")
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
                if st.button("✅ Replace Salary Dataset"):
                    save_json_file(new_salary_df, SALARIES_FILE_PATH)
                    st.session_state["salary_df"] = new_salary_df.copy()
                    st.success("✅ Salary data encrypted and saved successfully!")
                    add_notification("", "HR", f"Salary report uploaded by {user.get('Employee Name', 'HR')}")
            with col2:
                if st.button("👀 Preview Only (No Save)"):
                    st.info("Preview shown above. No changes made.")
        except Exception as e:
            st.error(f"Failed to process uploaded file: {e}")
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
            "📥 Download Current Encrypted Salary Data",
            data=buf,
            file_name="Salaries.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
    else:
        st.info("📭 No salary data available yet.")

# ============================
# HR Manager — UPDATED with Password Reset Feature
# ============================
def page_hr_manager(user):
    st.subheader("⚙️ HR Manager")
    st.info("Upload new employee sheet, manage employees, and perform administrative actions.")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.error("Employee data not loaded.")
        return
    # ============================
    # 🔑 NEW: Reset Employee Password Section
    # ============================
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
                    # Even if not in hashes, if in employees.json, we treat it as reset
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
    # ============================
    # 📊 HR: Detailed Leave Report
    # ============================
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
    # ============================
    # Upload Employees Excel
    # ============================
    st.markdown("### Upload Employees Excel (will replace current dataset)")
    uploaded_file = st.file_uploader("Upload Excel file (.xlsx) to replace the current employees dataset", type=["xlsx"])
    if uploaded_file:
        try:
            new_df = pd.read_excel(uploaded_file)
            # 🆕 Apply sanitization immediately on upload
            new_df = sanitize_employee_data(new_df)
            st.session_state["uploaded_df_preview"] = new_df.copy()
            st.success("File loaded and sanitized. Preview below.")
            st.dataframe(new_df.head(50), use_container_width=True)
            st.markdown("**Note:** Uploading will replace the current dataset in-memory.")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("✅ Replace Dataset"):
                    st.session_state["df"] = new_df.copy()
                    # ✅ NEW: Re-initialize passwords from new data
                    initialize_passwords_from_data(new_df.to_dict(orient='records'))
                    st.success("✅ In-memory dataset replaced and password hashes updated.")
            with col2:
                if st.button("👀 Preview Only (No Save)"):
                    st.info("Preview shown above.")
        except Exception as e:
            st.error(f"Failed to read uploaded file: {e}")
    st.markdown("---")
    # ============================
    # Manage Employees (Edit / Delete)
    # ============================
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
                submitted_edit = st.form_submit_button("💾 Save Changes")
                if submitted_edit:
                    for k, v in updated.items():
                        if isinstance(v, datetime.date):
                            v = pd.Timestamp(v)
                        df.loc[df[code_col].astype(str) == str(selected_code).strip(), k] = v
                    st.session_state["df"] = df
                    saved, pushed = save_and_maybe_push(df, actor=user.get("Employee Name","HR"))
                    if saved:
                        st.success("✅ Employee updated and saved locally.")
                        if pushed:
                            st.success("✅ Changes pushed to GitHub.")
                        else:
                            if GITHUB_TOKEN:
                                st.warning("✅ Saved locally, but GitHub push failed.")
                            else:
                                st.info("✅ Saved locally. GitHub not configured.")
                    else:
                        st.error("❌ Failed to save changes locally.")
            st.markdown("#### Delete Employee")
            if st.button("⚠️ Initiate Delete"):
                st.session_state["delete_target"] = str(selected_code).strip()
            if st.session_state.get("delete_target") == str(selected_code).strip():
                st.warning(f"⚠️ You are about to delete employee with code: {selected_code}.")
                col_del1, col_del2 = st.columns(2)
                with col_del1:
                    if st.button("✅ Confirm Delete"):
                        st.session_state["df"] = df[df[code_col].astype(str) != str(selected_code).strip()].reset_index(drop=True)
                        saved, pushed = save_and_maybe_push(st.session_state["df"], actor=user.get("Employee Name","HR"))
                        st.session_state["delete_target"] = None
                        if saved:
                            st.success("✅ Employee deleted and dataset saved locally.")
                            if pushed:
                                st.success("✅ Deletion pushed to GitHub.")
                            else:
                                if GITHUB_TOKEN:
                                    st.warning("✅ Saved locally but GitHub push failed.")
                                else:
                                    st.info("✅ Saved locally. GitHub not configured.")
                        else:
                            st.error("❌ Failed to save after deletion.")
                with col_del2:
                    if st.button("❌ Cancel Delete"):
                        st.session_state["delete_target"] = None
                        st.info("Deletion cancelled.")
    st.markdown("---")
    # ============================
    # Save / Push Dataset
    # ============================
    st.markdown("### Save / Push Dataset")
    if st.button("💾 Save Current Dataset"):
        df_current = st.session_state.get("df", pd.DataFrame())
        saved, pushed = save_and_maybe_push(df_current, actor=user.get("Employee Name","HR"))
        if saved:
            if pushed:
                st.success("✅ Saved locally and pushed to GitHub.")
            else:
                if GITHUB_TOKEN:
                    st.warning("✅ Saved locally but GitHub push failed.")
                else:
                    st.info("✅ Saved locally. GitHub not configured.")
        else:
            st.error("❌ Failed to save dataset locally.")
    st.markdown("---")
    # ============================
    # Clear All Test Data
    # ============================
    st.warning("🛠️ **Clear All Test Data** (Use BEFORE going live!)")
    if st.button("🗑️ Clear Test Data"):
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
# 🆕 PAGE: Notify Compliance (for MR only)
# ============================
def page_notify_compliance(user):
    st.subheader("📨 Notify Compliance Team")
    st.info("Use this form to notify the Compliance team about delays, absences, or other operational issues.")
    # 1. جلب بيانات الموظفين
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.error("Employee data not loaded.")
        return
    # 2. تحديد مدير الـ MR (لعرضه كمرجع فقط)
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    # ✅ استخدم الأسماء الحرفية كما في ملف JSON
    emp_code_col = "Employee Code"
    mgr_code_col = "Manager Code"
    emp_name_col = "Employee Name"
    # ✅ تحقق من وجود الأعمدة
    if not all(col in df.columns for col in [emp_code_col, mgr_code_col, emp_name_col]):
        st.error(f"❌ Required columns missing: {emp_code_col}, {mgr_code_col}, {emp_name_col}")
        return
    # ✅ تنظيف أعمدة Employee Code و Manager Code
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
    # 3. جلب أسماء فريق Compliance (العناوين الثلاثة)
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
    # 4. نموذج الإرسال
    message = st.text_area("Your Message", height=120, placeholder="Example: I was delayed today due to traffic...")
    if st.button("📤 Send to Compliance"):
        if not message.strip():
            st.warning("Please write a message.")
        else:
            messages_df = load_compliance_messages()
            new_id = int(messages_df["ID"].max()) + 1 if not messages_df.empty else 1
            # ✅ رسالة واحدة تحتوي على بيانات الـ Compliance + المدير
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
                # ✅ إشعار لكل عناوين الـ Compliance
                for title in compliance_titles:
                    add_notification("", title, f"New message from MR {user_code}")
                # ✅ إشعار للمدير (إذا كان موجودًا)
                if manager_code != "N/A" and manager_code != user_code:
                    add_notification(manager_code, "", f"New compliance message from your team member {user_code}")
                # ✅ رسالة تأكيد فورية (بدون rerun)
                st.success("✅ Your message has been sent to Compliance and your manager.")
            else:
                st.error("❌ Failed to send message.")

# ============================
# 🆕 PAGE: Report Compliance (for Compliance team + Managers + DM, AM, BUM)
# ============================
def page_report_compliance(user):
    st.subheader("📋 Compliance Reports")
    st.info("Messages sent by MRs regarding delays, absences, or compliance issues.")
    messages_df = load_compliance_messages()
    if messages_df.empty:
        st.info("📭 No compliance messages yet.")
        return
    # جلب بيانات الموظفين
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.error("Employee data not loaded.")
        return
    # تحديد صلاحيات المستخدم
    title_val = str(user.get("Title", "")).strip().upper()
    is_compliance = title_val in {"ASSOCIATE COMPLIANCE", "FIELD COMPLIANCE SPECIALIST", "COMPLIANCE MANAGER"}
    is_manager = title_val in {"AM", "DM", "BUM"}
    # إذا كان المستخدم ليس من فريق Compliance، نطبق التصفية
    if not is_compliance and is_manager:
        user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
        # بناء شجرة الفريق
        hierarchy = build_team_hierarchy_recursive(df, user_code, title_val)
        if hierarchy:
            # جمع كود جميع أعضاء الفريق (بما فيهم MRs)
            def collect_all_team_codes(node, codes_set):
                if node:
                    codes_set.add(node.get("Manager Code", ""))
                    for child in node.get("Team", []):
                        collect_all_team_codes(child, codes_set)
                return codes_set
            team_codes = set()
            collect_all_team_codes(hierarchy, team_codes)
            team_codes.add(user_code)  # أضف كود المستخدم نفسه
            # تصفية الرسائل
            messages_df = messages_df[
                messages_df["MR Code"].astype(str).isin(team_codes)
            ].copy()
    # عرض الرسائل
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
    # زر تحميل Excel
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
# 🆕 PAGE: IDB - Individual Development Blueprint (for MR) - FIXED
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
                    user_name,  # ✅ FIXED: Added Employee Name
                    selected,
                    [s.strip() for s in strength_inputs if s.strip()],
                    [d.strip() for d in dev_inputs if d.strip()],
                    action_input.strip()
                )
                if success:
                    st.success("✅ IDB Report saved successfully!")
                    # ✅ FIXED: Send notification to HR + ALL managers (DM, AM, BUM)
                    add_notification("", "HR", f"MR {user_name} ({user_code}) updated their IDB report.")
                    add_notification("", "DM", f"MR {user_name} ({user_code}) updated their IDB report.")
                    add_notification("", "AM", f"MR {user_name} ({user_code}) updated their IDB report.")
                    add_notification("", "BUM", f"MR {user_name} ({user_code}) updated their IDB report.")
                    st.rerun()
                else:
                    st.error("❌ Failed to save report.")
    # عرض التقرير الحالي كجدول قابل للتنزيل
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
# 🆕 PAGE: Self Development (for MR)
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
        # حفظ ميتا بيانات في JSON
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
# 🆕 PAGE: HR Development View (for HR) - FIXED
# ============================
def page_hr_development(user):
    st.subheader("🎓 Employee Development (HR View)")
    tab_idb, tab_certs = st.tabs(["📋 IDB Reports", "📜 Certifications"])
    with tab_idb:
        idb_df = load_idb_reports()
        if not idb_df.empty:
            # ✅ FIXED: Add Employee Name if not exists
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
            # تحويل القوائم النصية إلى سلاسل
            idb_df["Selected Departments"] = idb_df["Selected Departments"].apply(
                lambda x: ", ".join(eval(x)) if isinstance(x, str) else ", ".join(x)
            )
            idb_df["Strengths"] = idb_df["Strengths"].apply(
                lambda x: "; ".join(eval(x)) if isinstance(x, str) else "; ".join(x)
            )
            idb_df["Development Areas"] = idb_df["Development Areas"].apply(
                lambda x: "; ".join(eval(x)) if isinstance(x, str) else "; ".join(x)
            )
            # عرض الأعمدة المطلوبة
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
                    # ✅ FIXED: Download with original file format
                    with open(filepath, "rb") as f:
                        file_bytes = f.read()
                    st.download_button(
                        label=f"📥 Download {row['File']}",
                        data=file_bytes,
                        file_name=row["File"],  # نفس اسم الملف الأصلي
                        mime="application/octet-stream",  # صيغة عامة تحافظ على نوع الملف
                        key=f"dl_cert_{idx}"
                    )
        else:
            st.info("📭 No certifications uploaded.")

# ============================
# 🆕 PAGE: Ask HR (for ALL employees) - FIXED with success messages
# ============================
def page_ask_hr(user):
    # ✅ NEW: Show success message from session state
    if st.session_state.get("ask_hr_success"):
        st.success("✅ Your message was sent to HR successfully!")
        del st.session_state["ask_hr_success"]
    if st.session_state.get("ask_hr_error"):
        st.error(st.session_state["ask_hr_error"])
        del st.session_state["ask_hr_error"]
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
        uploaded_file = st.file_uploader("Attach File (Optional)", type=["pdf", "doc", "docx", "jpg", "png", "xlsx"])
        submitted = st.form_submit_button("📤 Send to HR")
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
                    st.session_state["ask_hr_success"] = True  # ✅ Set success flag
                    add_notification("", "HR", f"New Ask HR from {user_name} ({user_code})")
                    st.rerun()
                else:
                    st.session_state["ask_hr_error"] = "❌ Failed to save message. Please try again."
                    st.rerun()
    st.markdown("### 📜 Your Previous Messages")
    if hr_df is None or hr_df.empty:
        st.info("📭 No messages found.")
        return
    try:
        hr_df["Date Sent_dt"] = pd.to_datetime(hr_df["Date Sent"], errors="coerce")
        my_msgs = hr_df[hr_df["Employee Code"].astype(str).str.strip() == str(user_code)].sort_values("Date Sent_dt", ascending=False)
    except Exception:
        my_msgs = hr_df[hr_df["Employee Code"].astype(str).str.strip() == str(user_code)]
    if my_msgs.empty:
        st.info("📭 You have not sent any messages yet.")
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
# 🆕 PAGE: HR Inbox (for HR) - FIXED with success messages
# ============================
def page_hr_inbox(user):
    # ✅ NEW: Show success message from session state
    if st.session_state.get("hr_inbox_success"):
        st.success(st.session_state["hr_inbox_success"])
        del st.session_state["hr_inbox_success"]
    if st.session_state.get("hr_inbox_error"):
        st.error(st.session_state["hr_inbox_error"])
        del st.session_state["hr_inbox_error"]
    st.subheader("📬 HR Inbox")
    st.markdown("View employee queries and reply to them here.")
    hr_df = load_hr_queries()
    if hr_df is None or hr_df.empty:
        st.info("📭 No Ask HR messages.")
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
        reply_text = st.text_area("✍️ Write reply here:", value="", key=f"reply_{idx}", height=120)
        col1, col2 = st.columns([2, 2])
        with col1:
            if st.button("✅ Send Reply", key=f"send_reply_{idx}"):
                try:
                    hr_df.at[idx, "Reply"] = reply_text
                    hr_df.at[idx, "Status"] = "Replied"
                    hr_df.at[idx, "Date Replied"] = pd.Timestamp.now()
                    if save_hr_queries(hr_df):  # ✅ Check save result
                        st.session_state["hr_inbox_success"] = "✅ Reply sent and employee notified."
                        add_notification(emp_code, "", f"HR replied to your message: {subj}")
                        st.rerun()
                    else:
                        st.session_state["hr_inbox_error"] = "❌ Failed to save reply."
                        st.rerun()
                except Exception as e:
                    st.session_state["hr_inbox_error"] = f"❌ Failed to send reply: {e}"
                    st.rerun()
        with col2:
            if st.button("🗑️ Mark as Closed", key=f"close_{idx}"):
                try:
                    hr_df.at[idx, "Status"] = "Closed"
                    hr_df.at[idx, "Date Replied"] = pd.Timestamp.now()
                    if save_hr_queries(hr_df):
                        st.session_state["hr_inbox_success"] = "✅ Message marked as closed."
                        st.rerun()
                    else:
                        st.session_state["hr_inbox_error"] = "❌ Failed to close message."
                        st.rerun()
                except Exception as e:
                    st.session_state["hr_inbox_error"] = f"❌ Failed to close message: {e}"
                    st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)
        st.markdown("---")

# ============================
# 🆕 PAGE: Ask Employees (for HR) - FIXED: Messages now reach employees + Success/Error Handling
# ============================
def page_ask_employees(user):
    st.subheader("📤 Ask Employees")
    st.info("🔍 Select department, then select employee to send a message.")
    
    # ✅ عرض رسائل النجاح/الخطأ من Session State
    if st.session_state.get("ask_employees_success"):
        st.success(st.session_state["ask_employees_success"])
        del st.session_state["ask_employees_success"]
    if st.session_state.get("ask_employees_error"):
        st.error(st.session_state["ask_employees_error"])
        del st.session_state["ask_employees_error"]
    
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.error("Employee data not loaded.")
        return
    col_map = {c.lower().strip(): c for c in df.columns}
    code_col = col_map.get("employee_code") or col_map.get("employee code")
    name_col = col_map.get("employee_name") or col_map.get("employee name") or col_map.get("name")
    dept_col = col_map.get("department")
    if not code_col or not name_col:
        st.error("Could not find required columns.")
        return
    df[code_col] = df[code_col].astype(str).str.strip()
    df[name_col] = df[name_col].astype(str).str.strip()
    # اختيار القسم
    departments = df[dept_col].unique() if dept_col in df.columns else []
    selected_dept = st.selectbox("Select Department", ["All"] + list(departments))
    # فلترة الموظفين حسب القسم
    if selected_dept != "All" and dept_col in df.columns:
        filtered_df = df[df[dept_col] == selected_dept]
    else:
        filtered_df = df
    emp_options = filtered_df[[code_col, name_col]].copy()
    emp_options["Display"] = emp_options[name_col] + " (Code: " + emp_options[code_col] + ")"
    selected_display = st.selectbox("Select Employee", emp_options["Display"].tolist())
    selected_row = emp_options[emp_options["Display"] == selected_display].iloc[0]
    selected_code = selected_row[code_col]
    selected_name = selected_row[name_col]
    st.success(f"✅ Selected: {selected_name} (Code: {selected_code})")
    request_text = st.text_area("Request Details", height=100)
    uploaded_file = st.file_uploader("Attach File (Optional)", type=["pdf", "docx", "xlsx", "jpg", "png"])
    if st.button("📤 Send Request"):
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
        
        # ✅ التحقق من نجاح الحفظ قبل الإرسال
        if save_hr_requests(requests_df):
            add_notification(selected_code, "", f"HR has sent you a new request (ID: {new_id}). Check 'HR Request' page.")
            st.session_state["ask_employees_success"] = f"✅ Request sent to {selected_name} (Code: {selected_code}) successfully."
            st.rerun()
        else:
            st.session_state["ask_employees_error"] = "❌ Failed to send request. Please check file permissions and try again."
            st.rerun()

# ============================
# 🆕 PAGE: HR Request (for ALL employees) - FIXED with success messages
# ============================
def page_request_hr(user):
    # ✅ NEW: Show success message from session state
    if st.session_state.get("request_hr_success"):
        st.success("✅ Response submitted successfully!")
        del st.session_state["request_hr_success"]
    if st.session_state.get("request_hr_error"):
        st.error(st.session_state["request_hr_error"])
        del st.session_state["request_hr_error"]
    st.subheader("📥 HR Requests")
    st.info("Here you can respond to requests sent by HR.")
    user_code = str(user.get("Employee Code", "N/A")).strip().replace(".0", "")
    requests_df = load_hr_requests()
    if requests_df.empty:
        st.info("📭 No requests from HR.")
        return
    user_requests = requests_df[requests_df["Employee Code"].astype(str) == user_code].copy()
    if user_requests.empty:
        st.info("📭 No requests from HR for you.")
        return
    user_requests = user_requests.sort_values("Date Sent", ascending=False).reset_index(drop=True)
    for idx, row in user_requests.iterrows():
        st.markdown(f"### 📄 Request ID: {row['ID']}")
        st.write(f"**From HR:** {row['Request']}")
        date_sent_val = row.get("Date Sent")
        if pd.notna(date_sent_val) and date_sent_val != pd.NaT:
            try:
                formatted_date = pd.to_datetime(date_sent_val).strftime('%d-%m-%Y %H:%M')
                st.write(f"**Date Sent:** {formatted_date}")
            except Exception:
                st.write("**Date Sent:** Not available")
        else:
            st.write("**Date Sent:** Not available")
        file_attached = row.get("File Attached", "")
        if pd.notna(file_attached) and isinstance(file_attached, str) and file_attached.strip() != "":
            filepath = os.path.join("hr_request_files", file_attached)
            if os.path.exists(filepath):
                with open(filepath, "rb") as f:
                    st.download_button("📥 Download Attached File", f, file_name=file_attached, key=f"dl_req_{idx}")
            else:
                st.warning("⚠️ The attached file does not exist on the server.")
        else:
            st.info("📎 No file was attached to this request.")
        if row["Status"] == "Completed":
            st.success("✅ This request has been responded to.")
            response_file = row.get("Response File", "")
            if pd.notna(response_file) and isinstance(response_file, str) and response_file.strip() != "":
                resp_path = os.path.join("hr_response_files", response_file)
                if os.path.exists(resp_path):
                    with open(resp_path, "rb") as f:
                        st.download_button("📥 Download Your Response", f, file_name=response_file, key=f"dl_resp_{idx}")
                else:
                    st.warning("⚠️ Your response file does not exist on the server.")
            continue
        st.markdown("---")
        response_text = st.text_area("Your Response", key=f"resp_text_{idx}")
        uploaded_resp_file = st.file_uploader("Attach Response File (Optional)", type=["pdf", "docx", "xlsx", "jpg", "png"], key=f"resp_file_{idx}")
        if st.button("📤 Submit Response", key=f"submit_resp_{idx}"):
            if not response_text.strip() and not uploaded_resp_file:
                st.warning("Please provide a response or attach a file.")
                continue
            requests_df.loc[requests_df["ID"] == row["ID"], "Response"] = response_text.strip()
            requests_df.loc[requests_df["ID"] == row["ID"], "Status"] = "Completed"
            requests_df.loc[requests_df["ID"] == row["ID"], "Date Responded"] = pd.Timestamp.now()
            response_file_name = ""
            if uploaded_resp_file:
                resp_filename = save_response_file(uploaded_resp_file, user_code, row["ID"])
                response_file_name = resp_filename
            if save_hr_requests(requests_df):  # ✅ Check save result
                st.session_state["request_hr_success"] = True
                # ✅ FIXED: Send notification to HR
                add_notification("", "HR", f"Employee {user_code} responded to request ID {row['ID']}.")
                st.rerun()
            else:
                st.session_state["request_hr_error"] = "❌ Failed to save response. Please try again."
                st.rerun()

# ============================
# 🆕 PAGE: Employee Photos (HR View) - NEW PAGE
# ============================
def page_employee_photos(user):
    st.subheader("📸 Employee Photos (HR View)")
    st.info("View and manage all employee profile photos.")
    if not os.path.exists("employee_photos"):
        st.info("📭 No employee photos uploaded yet.")
        return
    photo_files = os.listdir("employee_photos")
    if not photo_files:
        st.info("📭 No employee photos uploaded yet.")
        return
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.warning("⚠️ Employee data not loaded.")
        code_to_name = {}
    else:
        col_map = {c.lower().strip(): c for c in df.columns}
        emp_code_col = col_map.get("employee_code") or col_map.get("employee code")
        emp_name_col = col_map.get("employee_name") or col_map.get("employee name") or col_map.get("name")
        if emp_code_col and emp_name_col:
            df[emp_code_col] = df[emp_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
            code_to_name = dict(zip(df[emp_code_col], df[emp_name_col]))
        else:
            code_to_name = {}
    # Group photos by employee code
    employee_photos = {}
    for filename in photo_files:
        if '.' in filename:
            emp_code = filename.rsplit('.', 1)[0]
            if emp_code not in employee_photos:
                employee_photos[emp_code] = []
            employee_photos[emp_code].append(filename)
    # Display photos in a grid
    cols_per_row = 4
    all_employees = sorted(employee_photos.keys())
    for i in range(0, len(all_employees), cols_per_row):
        cols = st.columns(cols_per_row)
        for j in range(cols_per_row):
            if i + j < len(all_employees):
                emp_code = all_employees[i + j]
                emp_name = code_to_name.get(emp_code, "Unknown")
                with cols[j]:
                    st.markdown(f"**{emp_code}**")
                    st.markdown(f"*{emp_name}*")
                    for photo in employee_photos[emp_code]:
                        filepath = os.path.join("employee_photos", photo)
                        if os.path.exists(filepath):
                            st.image(filepath, use_column_width=True)
                            with open(filepath, "rb") as f:
                                st.download_button(
                                    f"📥 {photo}",
                                    f,
                                    file_name=photo,
                                    key=f"dl_photo_{emp_code}_{photo}",
                                    use_container_width=True
                                )
    st.markdown("---")
    # Download all photos as ZIP
    st.markdown("---")
    if st.button("📦 Download All Photos (ZIP)"):
        zip_path = "employee_photos_all.zip"
        with zipfile.ZipFile(zip_path, 'w') as zipf:
            for filename in photo_files:
                filepath = os.path.join("employee_photos", filename)
                if os.path.exists(filepath):
                    zipf.write(filepath, filename)
        with open(zip_path, "rb") as f:
            st.download_button(
                label="📥 Download All Photos ZIP",
                data=f,
                file_name="employee_photos_all.zip",
                mime="application/zip",
                use_container_width=True
            )
        st.success("✅ ZIP file created. Click the button above to download.")

# ============================
# Remaining Page Functions (modified for photo upload)
# ============================
def calculate_leave_balance(employee_code, leaves_df=None):
    if leaves_df is None:
        leaves_df = load_leaves_data()
    employee_code = str(employee_code).strip().replace(".0", "")
    leaves_df["Employee Code"] = leaves_df["Employee Code"].astype(str).str.strip()
    approved_leaves = leaves_df[
        (leaves_df["Employee Code"] == employee_code) &
        (leaves_df["Status"] == "Approved")
    ]
    used_days = 0
    for _, row in approved_leaves.iterrows():
        if pd.notna(row["Start Date"]) and pd.notna(row["End Date"]):
            used_days += (row["End Date"] - row["Start Date"]).days + 1
    remaining_days = DEFAULT_ANNUAL_LEAVE - used_days
    return DEFAULT_ANNUAL_LEAVE, used_days, remaining_days

def build_team_hierarchy_recursive(df, manager_code, manager_title, depth=0, max_depth=10):
    if depth > max_depth:
        return None
    df = df.copy()
    df["Employee Code"] = df["Employee Code"].astype(str).str.strip()
    df["Manager Code"] = df["Manager Code"].astype(str).str.strip()
    direct_reports = df[df["Manager Code"] == manager_code].copy()
    team = []
    for _, emp in direct_reports.iterrows():
        emp_code = emp["Employee Code"]
        emp_title = emp["Title"].strip().upper()
        sub_team = build_team_hierarchy_recursive(df, emp_code, emp_title, depth + 1, max_depth)
        team.append({
            "Employee Code": emp_code,
            "Employee Name": emp.get("Employee Name", emp_code),
            "Title": emp_title,
            "Manager Code": manager_code,
            "Team": sub_team if sub_team else []
        })
    return team

def page_leave_request(user):
    st.subheader("📅 Request Leave")
    employee_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    col1, col2 = st.columns(2)
    with col1:
        start_date = st.date_input("Start Date")
    with col2:
        end_date = st.date_input("End Date")
    leave_type = st.selectbox("Leave Type", ["Annual Leave", "Sick Leave", "Emergency Leave", "Other"])
    reason = st.text_area("Reason")
    if st.button("📤 Submit Request"):
        if end_date < start_date:
            st.error("End date cannot be before start date.")
        else:
            leaves_df = load_leaves_data()
            manager_code = ""
            df = st.session_state.get("df", pd.DataFrame())
            if not df.empty:
                df["Employee Code"] = df["Employee Code"].astype(str).str.strip()
                user_row = df[df["Employee Code"] == employee_code]
                if not user_row.empty:
                    manager_code = str(user_row.iloc[0].get("Manager Code", "")).strip()
            new_row = pd.DataFrame([{
                "Employee Code": employee_code,
                "Manager Code": manager_code,
                "Start Date": start_date,
                "End Date": end_date,
                "Leave Type": leave_type,
                "Reason": reason,
                "Status": "Pending",
                "Decision Date": None,
                "Comment": ""
            }])
            leaves_df = pd.concat([leaves_df, new_row], ignore_index=True)
            if save_leaves_data(leaves_df):
                add_notification(manager_code, "", f"New leave request from {employee_code}")
                st.success("✅ Leave request submitted.")
                st.rerun()
            else:
                st.error("❌ Failed to save leave request.")

def page_my_profile(user):
    st.subheader("👤 My Profile")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.error("Employee data not loaded.")
        return
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    df["Employee Code"] = df["Employee Code"].astype(str).str.strip()
    user_row = df[df["Employee Code"] == user_code]
    if user_row.empty:
        st.error("Your profile not found.")
        return
    user_row = user_row.iloc[0]
    st.markdown("### Personal Information")
    col1, col2 = st.columns(2)
    with col1:
        st.write(f"**Employee Code:** {user_row.get('Employee Code', 'N/A')}")
        st.write(f"**Name:** {user_row.get('Employee Name', 'N/A')}")
        st.write(f"**Title:** {user_row.get('Title', 'N/A')}")
    with col2:
        st.write(f"**Department:** {user_row.get('Department', 'N/A')}")
        st.write(f"**Manager Code:** {user_row.get('Manager Code', 'N/A')}")
    # ✅ عرض البريد الخاص (Private Email) فقط في صفحة الملف الشخصي
    if "Private Email" in user_row.index:
        private_email = user_row["Private Email"]
        st.write(f"**Private Email:** {private_email if pd.notna(private_email) else 'N/A'}")
    st.markdown("### Contact Information")
    if "E-Mail" in user_row.index:
        email = user_row["E-Mail"]
        st.write(f"**Email:** {email if pd.notna(email) else 'N/A'}")
    if "Phone" in user_row.index:
        st.write(f"**Phone:** {user_row.get('Phone', 'N/A')}")
    st.markdown("### Additional Information")
    for col in user_row.index:
        if col not in ["Employee Code", "Employee Name", "Title", "Department", "Manager Code", "E-Mail", "Phone", "Private Email", "Password"]:
            val = user_row[col]
            if pd.notna(val):
                st.write(f"**{col}:** {val}")
    st.markdown("---")
    st.markdown("### 📸 Profile Photo")
    photo_dir = "employee_photos"
    user_photo = None
    if os.path.exists(photo_dir):
        for ext in ["jpg", "jpeg", "png"]:
            candidate = os.path.join(photo_dir, f"{user_code}.{ext}")
            if os.path.exists(candidate):
                user_photo = candidate
                break
    if user_photo:
        st.image(user_photo, width=200)
        # ✅ NEW: Change Photo button
        if st.button("🔄 Change Photo"):
            st.session_state["show_photo_upload"] = True
    else:
        st.info("📭 No profile photo uploaded yet.")
    if st.button("➕ Upload Photo"):
        st.session_state["show_photo_upload"] = True
    # Show upload form if button clicked
    if st.session_state.get("show_photo_upload", False):
        uploaded_file = st.file_uploader(
            "Choose a new photo (JPG/PNG)",
            type=["jpg", "jpeg", "png"],
            key="photo_uploader_new"
        )
        col1, col2 = st.columns(2)
        with col1:
            if st.button("✅ Save Photo"):
                if uploaded_file:
                    try:
                        filename = save_employee_photo(user_code, uploaded_file)
                        add_notification("", "HR", f"Employee {user_code} updated their profile photo.")
                        st.success(f"✅ Photo updated successfully!")
                        st.session_state["show_photo_upload"] = False
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ Failed to save photo: {e}")
                else:
                    st.warning("⚠️ Please select a photo first.")
        with col2:
            if st.button("❌ Cancel"):
                st.session_state["show_photo_upload"] = False
                st.rerun()

def page_team_structure(user):
    st.subheader("👥 Team Structure")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.error("Employee data not loaded.")
        return
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    title_val = str(user.get("Title", "")).strip().upper()
    allowed_titles = {"AM", "DM", "HR", "BUM"}
    if title_val not in allowed_titles:
        st.warning("⚠️ Only AM, DM, HR, and BUM can view team structure.")
        return
    hierarchy = build_team_hierarchy_recursive(df, user_code, title_val)
    if not hierarchy:
        st.info("📭 No team members found under your supervision.")
        return
    # ✅ FIXED: Show BUM team structure cards (AM, DM, MR counts)
    if title_val == "BUM":
        st.markdown("### Team Structure Summary")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown(f"""
<div class="team-structure-card">
<div class="team-structure-title">AM Count</div>
<div class="team-structure-value am">{len([x for x in hierarchy if x.get('Title') == 'AM'])}</div>
</div>
""", unsafe_allow_html=True)
        with col2:
            st.markdown(f"""
<div class="team-structure-card">
<div class="team-structure-title">DM Count</div>
<div class="team-structure-value dm">{len([x for x in hierarchy if x.get('Title') == 'DM'])}</div>
</div>
""", unsafe_allow_html=True)
        with col3:
            st.markdown(f"""
<div class="team-structure-card">
<div class="team-structure-title">MR Count</div>
<div class="team-structure-value mr">{sum(len(x.get('Team', [])) for x in hierarchy if x.get('Title') == 'DM')}</div>
</div>
""", unsafe_allow_html=True)
    # ✅ FIXED: Show AM team structure cards (DM, MR counts)
    elif title_val == "AM":
        st.markdown("### Team Structure Summary")
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"""
<div class="team-structure-card">
<div class="team-structure-title">DM Count</div>
<div class="team-structure-value dm">{len([x for x in hierarchy if x.get('Title') == 'DM'])}</div>
</div>
""", unsafe_allow_html=True)
        with col2:
            st.markdown(f"""
<div class="team-structure-card">
<div class="team-structure-title">MR Count</div>
<div class="team-structure-value mr">{sum(len(x.get('Team', [])) for x in hierarchy if x.get('Title') == 'DM')}</div>
</div>
""", unsafe_allow_html=True)
    def display_hierarchy(node, level=0):
        indent = "  " * level
        emp_code = node.get("Employee Code", "N/A")
        emp_name = node.get("Employee Name", emp_code)
        emp_title = node.get("Title", "N/A")
        color_map = {"AM": "#05445E", "DM": "#0A5C73", "MR": "#dc2626"}
        color = color_map.get(emp_title, "#666666")
        st.markdown(f"{indent}• <span style='color:{color}; font-weight:bold;'>{emp_name}</span> ({emp_code}) - <span style='color:{color};'>{emp_title}</span>", unsafe_allow_html=True)
        for child in node.get("Team", []):
            display_hierarchy(child, level + 1)
    st.markdown("### Your Team")
    if hierarchy is not None:
        for member in hierarchy:
            display_hierarchy(member)
    else:
        st.info("📭 No team members found under your supervision.")

def page_hr_queries(user):
    st.subheader("💬 HR Queries")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.error("Employee data not loaded.")
        return
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    queries_df = load_json_file(HR_QUERIES_FILE_PATH, default_columns=["ID", "Employee Code", "Query", "Response", "Status", "Timestamp"])
    st.markdown("### Ask HR a Question")
    with st.form("new_query"):
        query_text = st.text_area("Your Question")
        submitted = st.form_submit_button("📤 Submit")
        if submitted:
            if not query_text.strip():
                st.warning("Please enter your question.")
            else:
                new_id = int(queries_df["ID"].max()) + 1 if not queries_df.empty else 1
                new_row = pd.DataFrame([{
                    "ID": new_id,
                    "Employee Code": user_code,
                    "Query": query_text.strip(),
                    "Response": "",
                    "Status": "Pending",
                    "Timestamp": pd.Timestamp.now()
                }])
                queries_df = pd.concat([queries_df, new_row], ignore_index=True)
                save_json_file(queries_df, HR_QUERIES_FILE_PATH)
                add_notification("", "HR", f"New query from employee {user_code}")
                st.success("✅ Query submitted to HR.")
                st.rerun()
    st.markdown("### My Queries")
    my_queries = queries_df[queries_df["Employee Code"] == user_code].sort_values("Timestamp", ascending=False)
    for _, row in my_queries.iterrows():
        status_color = "#059669" if row["Status"] == "Answered" else "#dc2626"
        st.markdown(f"""
<div style="background-color:#f8fafc; padding:12px; border-radius:8px; margin:10px 0; border-left:4px solid {status_color};">
<div style="color:{status_color}; font-weight:bold;">Status: {row['Status']}</div>
<div style="color:#666666; margin-top:4px;"><strong>Question:</strong> {row['Query']}</div>
""")
        if row["Response"]:
            st.markdown(f"<div style='color:#05445E; margin-top:8px;'><strong>HR Response:</strong> {row['Response']}</div>", unsafe_allow_html=True)
        st.markdown(f"<div style='color:#999999; font-size:0.9rem; margin-top:4px;'>{format_relative_time(row['Timestamp'])}</div>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

def page_hr_view_queries(user):
    st.subheader("💬 HR Queries (HR View)")
    queries_df = load_json_file(HR_QUERIES_FILE_PATH, default_columns=["ID", "Employee Code", "Query", "Response", "Status", "Timestamp"])
    pending_queries = queries_df[queries_df["Status"] == "Pending"].sort_values("Timestamp", ascending=True)
    st.markdown("### 🟡 Pending Queries")
    if not pending_queries.empty:
        for idx, row in pending_queries.iterrows():
            st.markdown(f"**Employee Code:** {row['Employee Code']} | **Asked:** {format_relative_time(row['Timestamp'])}")
            st.write(f"**Question:** {row['Query']}")
            response = st.text_area("Your Response", key=f"resp_{row['ID']}")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("✅ Answer", key=f"ans_{row['ID']}"):
                    queries_df.loc[queries_df["ID"] == row["ID"], "Response"] = response.strip()
                    queries_df.loc[queries_df["ID"] == row["ID"], "Status"] = "Answered"
                    save_json_file(queries_df, HR_QUERIES_FILE_PATH)
                    add_notification(row["Employee Code"], "", "HR has answered your query.")
                    st.success("✅ Response sent.")
                    st.rerun()
            with col2:
                if st.button("⏭️ Skip", key=f"skip_{row['ID']}"):
                    st.info("Skipped.")
            st.markdown("---")
    else:
        st.info("📭 No pending queries.")
    st.markdown("### 📋 All Queries History")
    all_queries = queries_df.sort_values("Timestamp", ascending=False)
    st.dataframe(all_queries, use_container_width=True)

def page_hr_requests(user):
    st.subheader("📋 HR Requests")
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    requests_df = load_json_file(HR_REQUESTS_FILE_PATH, default_columns=["ID", "Employee Code", "Request Type", "Description", "File Path", "Status", "HR Response", "Timestamp"])
    st.markdown("### Submit a Request to HR")
    request_type = st.selectbox("Request Type", ["Equipment", "Training", "Other"])
    description = st.text_area("Description")
    uploaded_file = st.file_uploader("Attach File (optional)", type=["pdf", "doc", "docx", "jpg", "png"])
    if st.button("📤 Submit Request"):
        if not description.strip():
            st.warning("Please provide a description.")
        else:
            new_id = int(requests_df["ID"].max()) + 1 if not requests_df.empty else 1
            file_path = ""
            if uploaded_file:
                os.makedirs("hr_request_files", exist_ok=True)
                ext = uploaded_file.name.split(".")[-1].lower()
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"req_{user_code}_{timestamp}.{ext}"
                filepath = os.path.join("hr_request_files", filename)
                with open(filepath, "wb") as f:
                    f.write(uploaded_file.getbuffer())
                file_path = filepath
            new_row = pd.DataFrame([{
                "ID": new_id,
                "Employee Code": user_code,
                "Request Type": request_type,
                "Description": description.strip(),
                "File Path": file_path,
                "Status": "Pending",
                "HR Response": "",
                "Timestamp": pd.Timestamp.now()
            }])
            requests_df = pd.concat([requests_df, new_row], ignore_index=True)
            save_json_file(requests_df, HR_REQUESTS_FILE_PATH)
            add_notification("", "HR", f"New request from employee {user_code}")
            st.success("✅ Request submitted to HR.")
            st.rerun()
    st.markdown("### My Requests")
    my_requests = requests_df[requests_df["Employee Code"] == user_code].sort_values("Timestamp", ascending=False)
    for _, row in my_requests.iterrows():
        status_color = "#059669" if row["Status"] == "Approved" else "#dc2626" if row["Status"] == "Rejected" else "#666666"
        st.markdown(f"""
<div style="background-color:#f8fafc; padding:12px; border-radius:8px; margin:10px 0; border-left:4px solid {status_color};">
<div style="color:{status_color}; font-weight:bold;">Status: {row['Status']}</div>
<div style="color:#666666; margin-top:4px;"><strong>Type:</strong> {row['Request Type']} | <strong>Description:</strong> {row['Description']}</div>
""")
        if row["HR Response"]:
            st.markdown(f"<div style='color:#05445E; margin-top:8px;'><strong>HR Response:</strong> {row['HR Response']}</div>", unsafe_allow_html=True)
        if row["File Path"] and os.path.exists(row["File Path"]):
            with open(row["File Path"], "rb") as f:
                st.download_button("📥 Download Attached File", f, key=f"dl_req_{row['ID']}")
        st.markdown(f"<div style='color:#999999; font-size:0.9rem; margin-top:4px;'>{format_relative_time(row['Timestamp'])}</div>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

def page_hr_view_requests(user):
    st.subheader("📋 HR Requests (HR View)")
    requests_df = load_json_file(HR_REQUESTS_FILE_PATH, default_columns=["ID", "Employee Code", "Request Type", "Description", "File Path", "Status", "HR Response", "Timestamp"])
    pending_requests = requests_df[requests_df["Status"] == "Pending"].sort_values("Timestamp", ascending=True)
    st.markdown("### 🟡 Pending Requests")
    if not pending_requests.empty:
        for idx, row in pending_requests.iterrows():
            st.markdown(f"**Employee Code:** {row['Employee Code']} | **Type:** {row['Request Type']} | **Submitted:** {format_relative_time(row['Timestamp'])}")
            st.write(f"**Description:** {row['Description']}")
            if row["File Path"] and os.path.exists(row["File Path"]):
                with open(row["File Path"], "rb") as f:
                    st.download_button("📥 Download Attached File", f, key=f"dl_view_{row['ID']}")
            response = st.text_area("HR Response", key=f"hr_resp_{row['ID']}")
            col1, col2, col3 = st.columns(3)
            with col1:
                if st.button("✅ Approve", key=f"app_req_{row['ID']}"):
                    requests_df.loc[requests_df["ID"] == row["ID"], "HR Response"] = response.strip()
                    requests_df.loc[requests_df["ID"] == row["ID"], "Status"] = "Approved"
                    save_json_file(requests_df, HR_REQUESTS_FILE_PATH)
                    add_notification(row["Employee Code"], "", "Your HR request has been approved.")
                    st.success("✅ Request approved.")
                    st.rerun()
            with col2:
                if st.button("❌ Reject", key=f"rej_req_{row['ID']}"):
                    requests_df.loc[requests_df["ID"] == row["ID"], "HR Response"] = response.strip()
                    requests_df.loc[requests_df["ID"] == row["ID"], "Status"] = "Rejected"
                    save_json_file(requests_df, HR_REQUESTS_FILE_PATH)
                    add_notification(row["Employee Code"], "", "Your HR request was rejected.")
                    st.success("✅ Request rejected.")
                    st.rerun()
            with col3:
                if st.button("⏭️ Skip", key=f"skip_req_{row['ID']}"):
                    st.info("Skipped.")
            st.markdown("---")
    else:
        st.info("📭 No pending requests.")
    st.markdown("### 📋 All Requests History")
    all_requests = requests_df.sort_values("Timestamp", ascending=False)
    st.dataframe(all_requests, use_container_width=True)

def page_recruitment(user):
    st.subheader("👥 Recruitment")
    st.info("Use the Google Form link below to submit candidate information.")
    st.markdown(f"[📝 Submit Candidate Form]({GOOGLE_FORM_RECRUITMENT_LINK})")
    st.markdown("### Upload CVs")
    uploaded_cv = st.file_uploader("Upload CV (PDF/DOC/DOCX)", type=["pdf", "doc", "docx"])
    candidate_name = st.text_input("Candidate Name")
    position = st.text_input("Position Applied For")
    if uploaded_cv and st.button("📤 Submit CV"):
        try:
            filename = save_recruitment_cv(uploaded_cv)
            recruitment_df = load_json_file(RECRUITMENT_DATA_FILE, default_columns=["ID", "Candidate Name", "Position", "CV File", "Submitted By", "Timestamp"])
            new_id = int(recruitment_df["ID"].max()) + 1 if not recruitment_df.empty else 1
            new_row = pd.DataFrame([{
                "ID": new_id,
                "Candidate Name": candidate_name,
                "Position": position,
                "CV File": filename,
                "Submitted By": user.get("Employee Name", user.get("Employee Code", "")),
                "Timestamp": pd.Timestamp.now()
            }])
            recruitment_df = pd.concat([recruitment_df, new_row], ignore_index=True)
            save_json_file(recruitment_df, RECRUITMENT_DATA_FILE)
            st.success("✅ CV submitted successfully!")
            st.rerun()
        except Exception as e:
            st.error(f"❌ Failed to submit CV: {e}")
    st.markdown("### Submitted CVs")
    recruitment_df = load_json_file(RECRUITMENT_DATA_FILE)
    if not recruitment_df.empty:
        st.dataframe(recruitment_df[["Candidate Name", "Position", "Submitted By", "Timestamp"]], use_container_width=True)
        for idx, row in recruitment_df.iterrows():
            filepath = os.path.join(RECRUITMENT_CV_DIR, row["CV File"])
            if os.path.exists(filepath):
                with open(filepath, "rb") as f:
                    st.download_button(f"📥 {row['CV File']}", f, key=f"dl_cv_{idx}")
    else:
        st.info("📭 No CVs submitted yet.")

def page_hr_recruitment_view(user):
    st.subheader("👥 Recruitment (HR View)")
    recruitment_df = load_json_file(RECRUITMENT_DATA_FILE)
    if not recruitment_df.empty:
        st.dataframe(recruitment_df, use_container_width=True)
        for idx, row in recruitment_df.iterrows():
            filepath = os.path.join(RECRUITMENT_CV_DIR, row["CV File"])
            if os.path.exists(filepath):
                with open(filepath, "rb") as f:
                    st.download_button(f"📥 Download {row['CV File']}", f, key=f"dl_hr_cv_{idx}")
    else:
        st.info("📭 No recruitment data available.")

# ============================
# Login Page
# ============================
def page_login():
    st.title("👥 HRAS — Averroes Admin")
    st.markdown("### Login")
    col1, col2 = st.columns([1, 1])
    with col1:
        code = st.text_input("Employee Code")
        password = st.text_input("Password", type="password")
        if st.button("🔐 Login"):
            df = st.session_state.get("df", pd.DataFrame())
            if df.empty:
                st.error("Employee data not loaded. Please contact admin.")
            else:
                user = login(df, code, password)
                if user:
                    st.session_state["logged_in"] = True
                    st.session_state["user"] = user
                    st.success(f"✅ Welcome, {user.get('Employee Name', code)}!")
                    st.rerun()
                else:
                    st.error("❌ Invalid credentials.")
    with col2:
        st.markdown("### 🔐 Forgot Password?")
        st.info("If your password was reset by HR, you can set a new one without logging in.")
        if st.button("Change Password (No Login Required)"):
            st.session_state["show_forgot_password"] = True
            st.rerun()
    if st.session_state.get("show_forgot_password"):
        st.markdown("---")
        page_forgot_password()

# ============================
# Main App - SIDEBAR (FIXED: Remove Team Leaves from DM/AM, Remove Leave Request from MR/DM/AM/BUM, Enhanced Notifications) + SIDEBAR BUTTONS + COMMUNICATION FIX
# ============================
def main():
    # Initialize session state
    if "logged_in" not in st.session_state:
        st.session_state["logged_in"] = False
    if "user" not in st.session_state:
        st.session_state["user"] = None
    if "show_photo_upload" not in st.session_state:
        st.session_state["show_photo_upload"] = False
    # ✅ Initialize success/error flags for messaging pages
    if "ask_hr_success" not in st.session_state:
        st.session_state["ask_hr_success"] = False
    if "ask_hr_error" not in st.session_state:
        st.session_state["ask_hr_error"] = False
    if "request_hr_success" not in st.session_state:
        st.session_state["request_hr_success"] = False
    if "request_hr_error" not in st.session_state:
        st.session_state["request_hr_error"] = False
    if "hr_inbox_success" not in st.session_state:
        st.session_state["hr_inbox_success"] = False
    if "hr_inbox_error" not in st.session_state:
        st.session_state["hr_inbox_error"] = False
    # ✅ NEW: Initialize success/error flags for Ask Employees page
    if "ask_employees_success" not in st.session_state:
        st.session_state["ask_employees_success"] = False
    if "ask_employees_error" not in st.session_state:
        st.session_state["ask_employees_error"] = False
    
    # Load employee data if not loaded
    ensure_session_df()
    
    # Login page if not logged in
    if not st.session_state["logged_in"]:
        page_login()
        return
    
    # Get user info
    user = st.session_state["user"]
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    user_name = user.get("Employee Name", user_code)
    user_title = str(user.get("Title", "")).strip().upper()
    
    # Sidebar with enhanced notifications
    with st.sidebar:
        st.markdown('<p class="sidebar-title">👥 HRAS</p>', unsafe_allow_html=True)
        st.markdown(f"**{user_name}**")
        st.markdown(f"*{user_title}*")
        st.markdown("---")
        # Compute unread notifications count FIRST
        unread_count = get_unread_count(user)
        # Define special titles
        SPECIAL_TITLES = {
            "OPERATION MANAGER", "SFE MANAGER", "SFE SPECIALIST",
            "ASSOCIATE COMPLIANCE", "FIELD COMPLIANCE SPECIALIST",
            "OPERATION SUPERVISOR", "OPERATION ADMIN", "DISTRIBUTION SPECIALIST",
            "STORE SPECIALIST", "DIRECT SALES", "OPERATION SPECIALIST",
            "OPERATION AND ANALYTICS SPECIALIST", "OFFICE BOY"
        }
        # Build navigation pages with DYNAMIC notification label
        pages = ["👤 My Profile"]
        # ✅ FIXED: Enhanced notification label with badge
        notif_label = "🔔 Notifications"
        if unread_count > 0:
            notif_label = f"🔔 Notifications ({unread_count})"
        pages.append(notif_label)
        # ✅ FIXED: Remove Team Leaves from AM/DM, Remove Leave Request from MR/DM/AM/BUM
        if user_title in {"AM", "DM"}:
            # ❌ NO Team Leaves for AM/DM
            # ❌ NO Request Leave for AM/DM
            pages.extend(["👥 Team Structure", "📋 Report Compliance",
                         "💬 Ask HR", "📥 HR Request", "💰 Salary Monthly"])
        elif user_title == "MR":
            # ❌ NO Request Leave for MR
            pages.extend(["🚀 IDB – Individual Development Blueprint",
                         "🌱 Self Development", "📨 Notify Compliance",
                         "💬 Ask HR", "📥 HR Request", "💰 Salary Monthly"])
        elif user_title in {"ASSOCIATE COMPLIANCE", "FIELD COMPLIANCE SPECIALIST", "COMPLIANCE MANAGER"}:
            pages.append("📋 Report Compliance")
            pages.append("💰 Salary Monthly")
        elif user_title == "BUM":
            # ❌ NO Request Leave for BUM (only Team Leaves)
            pages.extend(["📅 Team Leave Requests", "👥 Team Structure", "📋 Report Compliance",
                         "💰 Salary Monthly"])
        elif user_title in SPECIAL_TITLES:
            # ✅ ONLY special titles get "Request Leave"
            pages.extend(["📅 Request Leave", "💬 Ask HR", "📥 HR Request",
                         "💰 Salary Monthly"])
        elif user_title == "HR":
            pages.extend([
                "💬 HR Queries (HR View)",
                "📋 HR Requests (HR View)",
                "📬 HR Inbox",
                "📤 Ask Employees",
                "📸 Employee Photos",
                "👥 Recruitment (HR View)",
                "🎓 Employee Development (HR View)",
                "⚙️ HR Manager",
                "💰 Salary Monthly",
                "📤 Salary Report"
            ])
        pages.append("🚪 Logout")
        
        # Display navigation with ENHANCED BUTTONS (Sky Blue with White Text)
        selected_page = None
        for page in pages:
            if st.button(page, key=f"nav_{page}", use_container_width=True):
                st.session_state["selected_page"] = page
                st.rerun()
        
        # Get selected page from session state
        selected_page = st.session_state.get("selected_page", pages[0])
    
    # Page routing with ENHANCED notification handling
    if selected_page.startswith("👤 My Profile"):
        page_my_profile(user)
    elif selected_page.startswith("🔔 Notifications"):
        page_notifications(user)
    elif selected_page.startswith("📅 Request Leave"):
        page_leave_request(user)
    elif selected_page.startswith("📅 Team Leave Requests"):
        page_manager_leaves(user)
    elif selected_page.startswith("👥 Team Structure"):
        page_team_structure(user)
    elif selected_page.startswith("💬 HR Queries"):
        if "(HR View)" in selected_page:
            page_hr_view_queries(user)
        else:
            page_hr_queries(user)
    elif selected_page.startswith("📋 HR Requests"):
        if "(HR View)" in selected_page:
            page_hr_view_requests(user)
        else:
            page_hr_requests(user)
    elif selected_page.startswith("🚀 IDB"):
        page_idb_mr(user)
    elif selected_page.startswith("🌱 Self Development"):
        page_self_development(user)
    elif selected_page.startswith("🎓 Employee Development"):
        page_hr_development(user)
    elif selected_page.startswith("📨 Notify Compliance"):
        page_notify_compliance(user)
    elif selected_page.startswith("📋 Report Compliance"):
        page_report_compliance(user)
    elif selected_page.startswith("💰 Salary Monthly"):
        page_salary_monthly(user)
    elif selected_page.startswith("📤 Salary Report"):
        if user_title == "HR":
            page_salary_report(user)
        else:
            st.error("❌ Access denied. HR only.")
    elif selected_page.startswith("👥 Recruitment"):
        if "(HR View)" in selected_page:
            page_hr_recruitment_view(user)
        else:
            page_recruitment(user)
    elif selected_page.startswith("⚙️ HR Manager"):
        if user_title == "HR":
            page_hr_manager(user)
        else:
            st.error("❌ Access denied. HR only.")
    elif selected_page.startswith("💬 Ask HR"):
        page_ask_hr(user)
    elif selected_page.startswith("📬 HR Inbox"):
        if user_title == "HR":
            page_hr_inbox(user)
        else:
            st.error("❌ Access denied. HR only.")
    elif selected_page.startswith("📤 Ask Employees"):
        if user_title == "HR":
            page_ask_employees(user)
        else:
            st.error("❌ Access denied. HR only.")
    elif selected_page.startswith("📥 HR Request"):
        page_request_hr(user)
    elif selected_page.startswith("📸 Employee Photos"):
        if user_title == "HR":
            page_employee_photos(user)
        else:
            st.error("❌ Access denied. HR only.")
    elif selected_page.startswith("🚪 Logout"):
        st.session_state["logged_in"] = False
        st.session_state["user"] = None
        st.session_state["show_photo_upload"] = False
        st.session_state["ask_hr_success"] = False
        st.session_state["ask_hr_error"] = False
        st.session_state["request_hr_success"] = False
        st.session_state["request_hr_error"] = False
        st.session_state["hr_inbox_success"] = False
        st.session_state["hr_inbox_error"] = False
        st.session_state["ask_employees_success"] = False
        st.session_state["ask_employees_error"] = False
        st.session_state["selected_page"] = None
        st.success("✅ You have been logged out.")
        st.rerun()
    else:
        st.info("📭 Page not found.")

# ============================
# Run the app
# ============================
if __name__ == "__main__":
    main()
