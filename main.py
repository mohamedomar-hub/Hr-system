# hr_system_with_mysql.py — FULLY CONVERTED TO JSON + MYSQL INTEGRATION (NO LINE DELETED) + PAGE-SPECIFIC NOTIFICATIONS
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
# ✅ إضافة مكتبة الاتصال بـ MySQL (السطر 14)
import mysql.connector
from mysql.connector import Error
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
def decrypt_salary_value(encrypted_str) -> float:  # ✅ FIXED: Improved to handle edge cases
    try:
        # Handle NaN/None/empty first
        if pd.isna(encrypted_str) or encrypted_str is None or encrypted_str == "":
            return 0.0
        # If already a number (not encrypted), return directly
        if isinstance(encrypted_str, (int, float)) and not isinstance(encrypted_str, bool):
            return float(encrypted_str)
        # Convert to string and strip
        encrypted_str = str(encrypted_str).strip()
        if not encrypted_str:
            return 0.0
        # Try to decode as base64 (encrypted format)
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_str.encode())
            decrypted = fernet_salary.decrypt(encrypted_bytes)
            return float(decrypted.decode())
        except Exception:
            # If decoding fails, assume it's plain text number
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
# 🆕 FUNCTION: Sanitize employee data (APPLY YOUR 3 RULES)
# ============================
def sanitize_employee_data(df: pd.DataFrame) -> pd.DataFrame:
    """
    Applies the following rules:
    1. Drop 'annual_leave_balance' column if exists.
    2. Drop 'monthly_salary' column if exists.
    3. Hide 'E-Mail' for anyone NOT in ['BUM', 'AM', 'DM'].
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
# ✅ MySQL Connection Function with Fallback (السطر 250)
# ============================
def get_db_connection():
    try:
        # ❌ لا تستخدم قيم افتراضية للـ password والـ user
        host = st.secrets["MYSQL_HOST"]
        user = st.secrets["MYSQL_USER"]
        password = st.secrets["MYSQL_PASSWORD"]
        database = st.secrets["MYSQL_DATABASE"]
        port = st.secrets.get("MYSQL_PORT", 3306)
        connection = mysql.connector.connect(
            host=host,
            user=user,
            password=password,
            database=database,
            port=port,  # ✅ أضف هذا السطر
            charset='utf8mb4',
            collation='utf8mb4_unicode_ci',
            connect_timeout=3
        )
        if connection.is_connected():
            return connection
        else:
            st.warning("⚠️ MySQL connection established but not active. Falling back to JSON files.")
            return None
    except KeyError as e:
        st.error(f"❌ Missing required secret: {str(e)}. Please configure Streamlit Secrets.")
        st.stop()
    except Exception as e:
        st.warning(f"MySQL Connection Failed: {str(e)[:80]}. Using JSON files instead.")
        return None
# ============================
# ✅ Load Employees from MySQL (السطر 280)
# ============================
def load_employees_from_mysql():
    """Load employees from MySQL database with fallback to empty DataFrame"""
    conn = get_db_connection()
    if not conn:
        return pd.DataFrame()
    try:
        query = """
        SELECT employee_code AS `Employee Code`,
        employee_name AS `Employee Name`,
        title AS `Title`,
        manager_code AS `Manager Code`,
        department AS `Department`,
        mobile AS `Mobile`,
        email AS `E-Mail`,
        address AS `Address as 702 bricks`,
        hire_date AS `Hiring Date`
        FROM employees
        ORDER BY employee_name
        """
        df = pd.read_sql(query, conn)
        conn.close()
        # Apply sanitization (same as current logic)
        return sanitize_employee_data(df)
    except Exception as e:
        st.warning(f"MySQL query failed: {e}. Falling back to JSON files.")
        if conn:
            conn.close()
        return pd.DataFrame()
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
        # Save encrypted version to disk
        data = df_copy.where(pd.notnull(df_copy), None).to_dict(orient='records')
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False
# ============================
# Styling - Modern Light Mode CSS (Updated per your request)
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
# ✅ تم دمج Colors.txt بالكامل + تعديل Hover إلى الأحمر + الحفاظ على الأنماط الإضافية
updated_css = """
<style>
/* ========== COLORS SYSTEM ========== */
:root {
--primary: #05445E;
--secondary: #0A5C73;
--text-main: #2E2E2E;
--text-muted: #6B7280;
--card-bg: #FFFFFF;
--soft-bg: #F2F6F8;
--border-soft: #E5E7EB;
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
/* ========== إضافات ضرورية للوظائف ========== */
.sidebar-title {
font-size: 1.4rem;
font-weight: bold;
color: var(--primary);
text-align: center;
margin-bottom: 10px;
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
.notification-badge {
background-color: #ef4444 !important;
color: white !important;
border-radius: 50%;
width: 22px;
height: 22px;
display: flex;
align-items: center;
justify-content: center;
font-weight: bold;
font-size: 0.85rem;
margin-left: 8px;
}
/* الأزرار */
.stButton > button {
background-color: var(--primary) !important;
color: white !important;
border: none !important;
font-weight: 600;
padding: 0.5rem 1rem;
border-radius: 6px;
}
.stButton > button:hover {
background-color: #dc2626 !important; /* 🔴 RED on hover */
color: white !important;
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
                add_notification("", "HR", f"Employee {emp_code_clean} set a new password after reset.", target_page="HR Inbox")
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
# ✅ MODIFIED: ensure_session_df with MySQL Fallback (السطر 680)
# ============================
def ensure_session_df():
    """
    Priority order for loading employee data:
    1. MySQL Database (if available and connected)
    2. GitHub (if configured)
    3. Local JSON file (employees.json)
    4. Demo data (if all else fails)
    """
    if "df" not in st.session_state:
        # ✅ المرحلة 1: جرب من قاعدة البيانات أولاً
        df_loaded = load_employees_from_mysql()
        if not df_loaded.empty:
            st.session_state["df"] = df_loaded
            st.success("✅ Employee data loaded from MySQL database.")
            return
        # ✅ المرحلة 2: لو فشل الـ MySQL، جرب من جيتهاب
        df_loaded = load_employee_data_from_github()
        if not df_loaded.empty:
            st.session_state["df"] = df_loaded
            st.info("⚠️ Using employee data from GitHub (MySQL unavailable).")
            return
        # ✅ المرحلة 3: لو فشل كله، استخدم الملف المحلي
        st.session_state["df"] = load_json_file(FILE_PATH)
        if st.session_state["df"].empty:
            # ✅ المرحلة 4: بيانات تجريبية احتياطية
            st.warning("⚠️ No employee data found. Using demo data for testing.")
            st.session_state["df"] = pd.DataFrame([{
                "Employee Code": "1001",
                "Employee Name": "محمد عمر",
                "Title": "HR",
                "Manager Code": "",
                "Department": "HR",
                "Mobile": "01000000000",
                "E-Mail": "mohamed@example.com",
                "Password": "1234"
            }])
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
# 🆕 PAGE-SPECIFIC NOTIFICATIONS SYSTEM (REPLACES OLD NOTIFICATIONS)
# ============================
def load_notifications():
    return load_json_file(NOTIFICATIONS_FILE_PATH, default_columns=[
        "Recipient Code", "Recipient Title", "Message", "Timestamp", "Is Read", "Target Page"
    ])
def save_notifications(df):
    df = df.copy()
    if "Timestamp" in df.columns:
        df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce").astype(str)
    return save_json_file(df, NOTIFICATIONS_FILE_PATH)
def add_notification(recipient_code, recipient_title, message, target_page=None):
    """
    Add notification with optional target page for badge display
    target_page examples: "HR Inbox", "Request HR", "Team Leaves", "📋 Report Compliance", "🎓 Employee Development (HR View)"
    """
    notifications = load_notifications()
    new_row = pd.DataFrame([{
        "Recipient Code": str(recipient_code),
        "Recipient Title": str(recipient_title),
        "Message": message,
        "Timestamp": pd.Timestamp.now().isoformat(),
        "Is Read": False,
        "Target Page": str(target_page) if target_page else ""
    }])
    notifications = pd.concat([notifications, new_row], ignore_index=True)
    save_notifications(notifications)
def get_unread_count_for_page(user, page_name):
    """
    Get unread notification count for a specific page
    """
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
    
    # Filter notifications for this specific page
    mask = notifications["Target Page"].astype(str) == page_name
    
    # For HR Inbox: show all Ask HR messages
    if page_name == "HR Inbox":
        mask = notifications["Recipient Title"].astype(str).str.upper() == "HR"
        mask &= notifications["Message"].str.contains("Ask HR", case=False, na=False)
    
    # For Request HR: show messages targeted to employee's Request HR page
    elif page_name == "Request HR":
        mask = notifications["Recipient Code"].astype(str) == user_code
        mask &= notifications["Target Page"].astype(str) == "Request HR"
    
    # For Team Leaves: show leave requests for managers
    elif page_name == "Team Leaves":
        mask = notifications["Recipient Code"].astype(str) == user_code
        mask &= notifications["Message"].str.contains("leave request", case=False, na=False)
    
    # For Report Compliance: show compliance messages for compliance team
    elif page_name == "📋 Report Compliance":
        compliance_titles = {"ASSOCIATE COMPLIANCE", "FIELD COMPLIANCE SPECIALIST", "COMPLIANCE MANAGER"}
        mask = notifications["Recipient Title"].astype(str).str.upper().isin(compliance_titles)
        mask &= notifications["Target Page"].astype(str) == "📋 Report Compliance"
    
    # For Employee Development (HR View): show IDB/certification updates
    elif page_name == "🎓 Employee Development (HR View)":
        mask = notifications["Recipient Title"].astype(str).str.upper() == "HR"
        mask &= notifications["Target Page"].astype(str) == "🎓 Employee Development (HR View)"
    
    # For Ask Employees: show HR's sent requests
    elif page_name == "Ask Employees":
        mask = notifications["Recipient Title"].astype(str).str.upper() == "HR"
        mask &= notifications["Target Page"].astype(str) == "Ask Employees"
    
    unread = notifications[mask & (~notifications["Is Read"])]
    return len(unread)
def mark_page_as_read(user, page_name):
    """
    Mark all notifications for a specific page as read
    """
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
    
    if not user_code and not user_title:
        return
    
    # Filter notifications for this specific page (same logic as get_unread_count_for_page)
    mask = notifications["Target Page"].astype(str) == page_name
    
    if page_name == "HR Inbox":
        mask = notifications["Recipient Title"].astype(str).str.upper() == "HR"
        mask &= notifications["Message"].str.contains("Ask HR", case=False, na=False)
    
    elif page_name == "Request HR":
        mask = notifications["Recipient Code"].astype(str) == user_code
        mask &= notifications["Target Page"].astype(str) == "Request HR"
    
    elif page_name == "Team Leaves":
        mask = notifications["Recipient Code"].astype(str) == user_code
        mask &= notifications["Message"].str.contains("leave request", case=False, na=False)
    
    elif page_name == "📋 Report Compliance":
        compliance_titles = {"ASSOCIATE COMPLIANCE", "FIELD COMPLIANCE SPECIALIST", "COMPLIANCE MANAGER"}
        mask = notifications["Recipient Title"].astype(str).str.upper().isin(compliance_titles)
        mask &= notifications["Target Page"].astype(str) == "📋 Report Compliance"
    
    elif page_name == "🎓 Employee Development (HR View)":
        mask = notifications["Recipient Title"].astype(str).str.upper() == "HR"
        mask &= notifications["Target Page"].astype(str) == "🎓 Employee Development (HR View)"
    
    elif page_name == "Ask Employees":
        mask = notifications["Recipient Title"].astype(str).str.upper() == "HR"
        mask &= notifications["Target Page"].astype(str) == "Ask Employees"
    
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
                    add_notification(row['Employee Code'], "", "Your leave request has been approved!", target_page="Request HR")
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
                    add_notification(row['Employee Code'], "", msg, target_page="Request HR")
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
# Salary Monthly Page — **REPLACED WITH IMPROVED VERSION FROM edit.txt**
# ============================
def page_salary_monthly(user):
    st.subheader("Monthly Salaries")
    # 🔹 Normalize logged-in employee code
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    try:
        # 🔹 Load salaries JSON
        if not os.path.exists(SALARIES_FILE_PATH):
            st.error(f"❌ File '{SALARIES_FILE_PATH}' not found.")
            return
        salary_df = load_json_file(SALARIES_FILE_PATH)
        if salary_df.empty:
            st.info("No salary data available.")
            return
        # 🔹 Ensure required columns
        required_columns = ["Employee Code", "Month", "Basic Salary", "KPI Bonus", "Deductions"]
        missing_cols = [c for c in required_columns if c not in salary_df.columns]
        if missing_cols:
            st.error(f"❌ Missing columns: {missing_cols}")
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
            st.info(f"🚫 No salary records found for you (Code: {user_code}).")
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
            if st.button(f"Show Details for {month}", key=btn_key):
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
                if st.button(f"Hide Details for {month}", key=f"hide_{month}"):
                    del st.session_state[details_key]
                    st.rerun()
    except Exception as e:
        st.error(f"❌ Error loading salary data: {e}")
# ============================
# Salary Report Page — Encrypt on Upload
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
            st.error(f"Could not load salary data from {SALARIES_FILE_PATH}. Upload a file first.")
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
# HR Manager — UPDATED with Password Reset Feature
# ============================
def page_hr_manager(user):
    st.subheader("HR Manager")
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
                    add_notification(emp_code_clean, "", "Your password was reset by HR. Please set a new password using the 'Change Password (No Login)' link on the login page.", target_page="Request HR")
                else:
                    # Even if not in hashes, if in employees.json, we treat it as reset
                    col_map = {c.lower().strip(): c for c in df.columns}
                    code_col = col_map.get("employee_code") or col_map.get("employee code")
                    if code_col:
                        df[code_col] = df[code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
                        if emp_code_clean in df[code_col].values:
                            st.success(f"✅ Employee {emp_code_clean} marked for password reset. They can now set a new password.")
                            add_notification(emp_code_clean, "", "Your account is ready for a new password. Use the 'Change Password (No Login)' link.", target_page="Request HR")
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
                if st.button("Replace In-Memory Dataset with Uploaded File"):
                    st.session_state["df"] = new_df.copy()
                    # ✅ NEW: Re-initialize passwords from new data
                    initialize_passwords_from_data(new_df.to_dict(orient='records'))
                    st.success("In-memory dataset replaced and password hashes updated.")
            with col2:
                if st.button("Preview only (do not replace)"):
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
    # ============================
    # Save / Push Dataset
    # ============================
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
    # ============================
    # Clear All Test Data
    # ============================
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
                # ✅ إشعار لكل عناوين الـ Compliance مع تحديد الصفحة المستهدفة
                for title in compliance_titles:
                    add_notification("", title, f"New message from MR {user_code}", target_page="📋 Report Compliance")
                # ✅ إشعار للمدير (إذا كان موجودًا)
                if manager_code != "N/A" and manager_code != user_code:
                    add_notification(manager_code, "", f"New compliance message from your team member {user_code}", target_page="Team Leaves")
                # ✅ رسالة تأكيد فورية (بدون rerun)
                st.success("✅ Your message has been sent to Compliance and your manager.")
            else:
                st.error("❌ Failed to send message.")
# ============================
# 🆕 PAGE: Report Compliance (for Compliance team + Managers)
# ============================
def page_report_compliance(user):
    st.subheader("📋 Report Compliance")
    st.info("Messages sent by MRs regarding delays, absences, or compliance issues.")
    messages_df = load_compliance_messages()
    if messages_df.empty:
        st.info("No compliance messages yet.")
        return
    # جلب بيانات الموظفين
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.error("Employee data not loaded.")
        return
    # تحديد صلاحيات المستخدم
    title_val = str(user.get("Title", "")).strip().upper()
    is_compliance = title_val in {"ASSOCIATE COMPLIANCE", "FIELD COMPLIANCE SPECIALIST", "COMPLIANCE MANAGER"}
    is_manager = title_val in {"AM", "DM"}
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
# 🚀 صفحة IDB – Individual Development Blueprint (NEW)
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
                    # ✅ FIXED: Send notification to HR + ALL managers (DM, AM, BUM) with target page
                    add_notification("", "HR", f"MR {user_name} ({user_code}) updated their IDB report.", target_page="🎓 Employee Development (HR View)")
                    add_notification("", "DM", f"MR {user_name} ({user_code}) updated their IDB report.", target_page="🎓 Employee Development (HR View)")
                    add_notification("", "AM", f"MR {user_name} ({user_code}) updated their IDB report.", target_page="🎓 Employee Development (HR View)")
                    add_notification("", "BUM", f"MR {user_name} ({user_code}) updated their IDB report.", target_page="🎓 Employee Development (HR View)")
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
# 🌱 صفحة Self Development (NEW)
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
        add_notification("", "HR", f"MR {user_code} uploaded a new certification.", target_page="🎓 Employee Development (HR View)")
        st.success("✅ Certification submitted to HR!")
        st.rerun()
# ============================
# 🎓 صفحة عرض التطوير (HR Development View) (NEW)
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
# Remaining Page Functions (unchanged)
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
                        add_notification("", "HR", f"Employee {emp_code_clean} uploaded a new photo.", target_page="🎓 Employee Development (HR View)")
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
                    add_notification("", "HR", f"Employee {user_code_clean} changed their password.", target_page="HR Inbox")
                else:
                    st.error("❌ Current password is incorrect.")
def calculate_leave_balance(user_code, leaves_df):
    annual_balance = DEFAULT_ANNUAL_LEAVE
    user_approved_leaves = leaves_df[
        (leaves_df["Employee Code"].astype(str) == str(user_code)) &
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
                    add_notification(manager_code, "", f"New leave request from {user_code}", target_page="Team Leaves")
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
        subordinate_types = ["MR"]
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
    }
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
            add_notification("", "HR", f"Full leaves report generated: {out_path}", target_page="HR Inbox")
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
    ROLE_ICONS = {
        "BUM": "🏢",
        "AM": "👨‍💼",
        "DM": "👩‍💼",
        "MR": "🧑‍⚕️"
    }
    ROLE_COLORS = {
        "BUM": "#05445E",
        "AM": "#05445E",
        "DM": "#0A5C73",
        "MR": "#dc2626"
    }
    st.markdown("""
    <style>
    .team-node {
    background-color: #FFFFFF;
    border-left: 4px solid #05445E;
    padding: 12px;
    margin: 8px 0;
    border-radius: 6px;
    box-shadow: 0 2px 6px rgba(0,0,0,0.05);
    }
    .team-node-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-weight: 600;
    color: #05445E;
    margin-bottom: 8px;
    }
    .team-node-summary {
    font-size: 0.9rem;
    color: #666666;
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
    background-color: #f8fafc;
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
    user_title = role.upper()
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
    def render_tree(node, level=0, is_last_child=False):
        if not node:
            return
        am_count = node["Summary"]["AM"]
        dm_count = node["Summary"]["DM"]
        mr_count = node["Summary"]["MR"]
        total_count = node["Summary"]["Total"]
        summary_parts = []
        if am_count > 0:
            summary_parts.append(f"🟢 {am_count} AM")
        if dm_count > 0:
            summary_parts.append(f"🔵 {dm_count} DM")
        if mr_count > 0:
            summary_parts.append(f"🟣 {mr_count} MR")
        if total_count > 0:
            summary_parts.append(f"🔢 {total_count} Total")
        summary_str = " | ".join(summary_parts) if summary_parts else "No direct reports"
        manager_info = node.get("Manager", "Unknown")
        manager_code = node.get("Manager Code", "N/A")
        role = "MR"
        if "(" in manager_info and ")" in manager_info:
            role_part = manager_info.split("(")[-1].split(")")[0].strip()
            if role_part in ROLE_ICONS:
                role = role_part
        icon = ROLE_ICONS.get(role, "👤")
        color = ROLE_COLORS.get(role, "#2E2E2E")
        prefix = ""
        if level > 0:
            for i in range(level - 1):
                prefix += "│   "
            if is_last_child:
                prefix += "└── "
            else:
                prefix += "├── "
        st.markdown(f"""
        <div class="team-node">
        <div class="team-node-header">
        <span style="color: {color};">{prefix}{icon} <strong>{manager_info}</strong> (Code: {manager_code})</span>
        <span class="team-node-summary">{summary_str}</span>
        </div>
        """, unsafe_allow_html=True)
        if node.get("Team"):
            st.markdown('<div class="team-node-children">', unsafe_allow_html=True)
            team_count = len(node.get("Team", []))
            for i, team_member in enumerate(node.get("Team", [])):
                is_last = (i == team_count - 1)
                render_tree(team_member, level + 1, is_last)
            st.markdown('</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
    render_tree(hierarchy, 0, True)
    if not hierarchy.get("Team"):
        root_manager_info = hierarchy.get("Manager", "Unknown")
        root_manager_code = hierarchy.get("Manager Code", "N/A")
        role = "MR"
        if "(" in root_manager_info and ")" in root_manager_info:
            role_part = root_manager_info.split("(")[-1].split(")")[0].strip()
            if role_part in ROLE_ICONS:
                role = role_part
        icon = ROLE_ICONS.get(role, "👤")
        color = ROLE_COLORS.get(role, "#2E2E2E")
        st.markdown(f'<span style="color: {color};">{icon} <strong>{root_manager_info}</strong> (Code: {root_manager_code})</span>', unsafe_allow_html=True)
        st.info("No direct subordinates found under your supervision.")
def page_directory(user):
    st.subheader("Company Structure")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.info("Employee data not loaded.")
        return
    st.info("Search and filter employees below.")
    COLUMNS_TO_SHOW = [
        "Employee Code",
        "Employee Name",
        "Manager Name",
        "Title",
        "Mobile",
        "Department",
        "E-Mail",
        "Address as 702 bricks"
    ]
    col_map = {c.lower().strip(): c for c in df.columns}
    final_columns = []
    for col_name in COLUMNS_TO_SHOW:
        variations = [
            col_name.lower().replace(' ', '_'),
            col_name.lower().replace(' ', ''),
            col_name.lower(),
            col_name
        ]
        found_col = None
        for var in variations:
            if var in col_map:
                found_col = col_map[var]
                break
        if found_col:
            final_columns.append(found_col)
        else:
            st.warning(f"Column '{col_name}' not found in data.")
    col1, col2 = st.columns(2)
    with col1:
        search_name = st.text_input("Search by Employee Name")
    with col2:
        search_code = st.text_input("Search by Employee Code")
    filtered_df = df.copy()
    if search_name:
        emp_name_col = None
        for col in df.columns:
            if col.lower().replace(" ", "_").replace("-", "_") in ["employee_name", "name", "employee name", "full name", "first name"]:
                emp_name_col = col
                break
        if emp_name_col:
            filtered_df = filtered_df[filtered_df[emp_name_col].astype(str).str.contains(search_name, case=False, na=False)]
        else:
            st.warning("Employee Name column not found for search.")
    if search_code:
        emp_code_col = None
        for col in df.columns:
            if col.lower().replace(" ", "_").replace("-", "_") in ["employee_code", "code", "employee code", "emp_code"]:
                emp_code_col = col
                break
        if emp_code_col:
            filtered_df = filtered_df[filtered_df[emp_code_col].astype(str).str.contains(search_code, case=False, na=False)]
        else:
            st.warning("Employee Code column not found for search.")
    if final_columns:
        display_df = filtered_df[final_columns].copy()
        st.dataframe(display_df, use_container_width=True)
        st.info(f"Showing {len(display_df)} of {len(df)} employees.")
    else:
        st.error("No columns could be mapped for display. Please check your Excel sheet headers.")
def load_hr_queries():
    return load_json_file(HR_QUERIES_FILE_PATH, default_columns=[
        "ID", "Employee Code", "Employee Name", "Subject", "Message",
        "Reply", "Status", "Date Sent", "Date Replied"
    ])
def save_hr_queries(df):
    df = df.copy()
    if "Date Sent" in df.columns:
        df["Date Sent"] = pd.to_datetime(df["Date Sent"], errors="coerce").astype(str)
    if "Date Replied" in df.columns:
        df["Date Replied"] = pd.to_datetime(df["Date Replied"], errors="coerce").astype(str)
    if "ID" in df.columns:
        df = df.copy()
        df["ID"] = pd.to_numeric(df["ID"], errors="coerce")
        if df["ID"].isna().any():
            existing_max = int(df["ID"].max(skipna=True)) if not df["ID"].isna().all() else 0
            for idx in df[df["ID"].isna()].index:
                existing_max += 1
                df.at[idx, "ID"] = existing_max
            df["ID"] = df["ID"].astype(int)
    return save_json_file(df, HR_QUERIES_FILE_PATH)
def load_hr_requests():
    return load_json_file(HR_REQUESTS_FILE_PATH, default_columns=[
        "ID", "HR Code", "Employee Code", "Employee Name", "Request", "File Attached", "Status", "Response", "Response File", "Date Sent", "Date Responded"
    ])
def save_hr_requests(df):
    df = df.copy()
    for col in ["Date Sent", "Date Responded"]:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors="coerce").astype(str)
    if "ID" in df.columns:
        df = df.copy()
        df["ID"] = pd.to_numeric(df["ID"], errors="coerce")
        if df["ID"].isna().any():
            existing_max = int(df["ID"].max(skipna=True)) if not df["ID"].isna().all() else 0
            for idx in df[df["ID"].isna()].index:
                existing_max += 1
                df.at[idx, "ID"] = existing_max
            df["ID"] = df["ID"].astype(int)
    return save_json_file(df, HR_REQUESTS_FILE_PATH)
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
# ✅ FIXED: page_ask_employees with proper filtered_options initialization
def page_ask_employees(user):
    st.subheader("📤 Ask Employees")
    st.info("🔍 Type employee name or code to search. HR can send requests with file attachments.")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.error("Employee data not loaded.")
        return
    col_map = {c.lower().strip(): c for c in df.columns}
    code_col_options = ["employee_code", "employee code", "emp code", "code", "employeeid", "emp_id"]
    code_col = None
    for opt in code_col_options:
        if opt in col_map:
            code_col = col_map[opt]
            break
    if not code_col:
        st.error("Could not find any column for Employee Code. Please check your Excel sheet headers.")
        return
    name_col_options = ["employee_name", "employee name", "name", "emp name", "full name", "first name"]
    name_col = None
    for opt in name_col_options:
        if opt in col_map:
            name_col = col_map[opt]
            break
    if not name_col:
        st.error("Could not find any column for Employee Name. Please check your Excel sheet headers.")
        return
    df[code_col] = df[code_col].astype(str).str.strip()
    df[name_col] = df[name_col].astype(str).str.strip()
    emp_options = df[[code_col, name_col]].copy()
    emp_options["Display"] = emp_options[name_col] + " (Code: " + emp_options[code_col] + ")"
    st.markdown("### 🔍 Search Employee by Name or Code")
    search_term = st.text_input("Type employee name or code to search...")
    # ✅ FIXED: Initialize filtered_options BEFORE conditional logic to avoid UnboundLocalError
    filtered_options = emp_options.copy()  # Default to all employees
    if search_term:
        try:
            mask = (
                emp_options[name_col].str.contains(search_term, case=False, na=False) |
                emp_options[code_col].str.contains(search_term, case=False, na=False)
            )
            filtered_options = emp_options[mask].copy()
            if filtered_options.empty:
                st.warning("No employee found matching your search.")
                return
        except Exception as e:
            st.warning(f"Search error: {e}. Showing all employees.")
            filtered_options = emp_options.copy()
    # Now filtered_options is ALWAYS defined
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
        add_notification(selected_code, "", f"HR has sent you a new request (ID: {new_id}). Check 'Request HR' page.", target_page="Request HR")
        st.success(f"Request sent to {selected_name} (Code: {selected_code}) successfully.")
        st.rerun()
# ============================
# ✅ تم إصلاح صفحة Request HR هنا
# ============================
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
        # ✅ تم إصلاح الخطأ هنا باستخدام التحقق الآمن
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
                st.warning("The attached file does not exist on the server.")
        else:
            st.info("No file was attached to this request.")
        if row["Status"] == "Completed":
            st.success("✅ This request has been responded to.")
            response_file = row.get("Response File", "")
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
                resp_filename = save_response_file(uploaded_resp_file, user_code, row["ID"])
                response_file_name = resp_filename
            save_hr_requests(requests_df)
            add_notification("", "HR", f"Employee {user_code} responded to request ID {row['ID']}.", target_page="Ask Employees")
            st.success("Response submitted successfully.")
            st.rerun()
def page_recruitment(user):
    st.subheader("👥 Recruitment Management")
    if user.get("Title", "").upper() != "HR":
        st.error("Access denied. HR only.")
        return
    st.markdown(f"""
    <div style="background-color:white; padding:12px; border-radius:8px; border:1px solid #05445E; margin-bottom:20px;">
    <h4>📝 Candidate Application Form</h4>
    <p>Share this link with job applicants:</p>
    <a href="{GOOGLE_FORM_RECRUITMENT_LINK}" target="_blank" style="color:#05445E; text-decoration:underline;">
    👉 Apply via Google Form
    </a>
    <p style="font-size:0.9rem; color:#666666; margin-top:8px;">
    After applicants submit, download the Excel responses from Google Sheets and upload them below.
    </p>
    </div>
    """, unsafe_allow_html=True)
    tab_cv, tab_db = st.tabs(["📄 CV Candidates", "📊 Recruitment Database"])
    with tab_cv:
        st.markdown("### Upload New Candidate CV")
        uploaded_cv = st.file_uploader("Upload CV (PDF or Word)", type=["pdf", "doc", "docx"])
        candidate_name = st.text_input("Candidate Name (for reference)")
        if uploaded_cv and st.button("✅ Save CV"):
            try:
                filename = save_recruitment_cv(uploaded_cv)
                st.success(f"CV saved as: `{filename}`")
                if candidate_name:
                    add_notification("", "HR", f"New CV uploaded for: {candidate_name}", target_page="HR Inbox")
                st.rerun()
            except Exception as e:
                st.error(f"Failed to save CV: {e}")
        st.markdown("---")
        st.markdown("### All Uploaded CVs")
        cv_files = []
        if os.path.exists(RECRUITMENT_CV_DIR):
            cv_files = sorted(os.listdir(RECRUITMENT_CV_DIR), reverse=True)
        if not cv_files:
            st.info("No CVs uploaded yet.")
        else:
            for cv in cv_files:
                col1, col2 = st.columns([4, 1])
                with col1:
                    st.markdown(f"📄 `{cv}`")
                with col2:
                    with open(os.path.join(RECRUITMENT_CV_DIR, cv), "rb") as f:
                        st.download_button("📥", f, file_name=cv, key=f"dl_cv_{cv}")
        if st.button("📦 Download All CVs (ZIP)"):
            zip_path = "all_cvs.zip"
            with zipfile.ZipFile(zip_path, 'w') as zipf:
                for cv in cv_files:
                    zipf.write(os.path.join(RECRUITMENT_CV_DIR, cv), cv)
            with open(zip_path, "rb") as f:
                st.download_button("Download ZIP", f, file_name="Recruitment_CVs.zip", mime="application/zip")
    with tab_db:
        st.markdown("### Upload Recruitment Data from Google Forms")
        uploaded_db = st.file_uploader("Upload Excel from Google Forms", type=["xlsx"])
        if uploaded_db:
            try:
                new_db_df = pd.read_excel(uploaded_db)
                st.session_state["recruitment_preview"] = new_db_df.copy()
                st.success("File loaded successfully.")
                st.dataframe(new_db_df.head(10), use_container_width=True)
                if st.button("✅ Replace Recruitment Database"):
                    save_json_file(new_db_df, RECRUITMENT_DATA_FILE)
                    st.success("Recruitment database updated!")
                    st.rerun()
            except Exception as e:
                st.error(f"Error reading file: {e}")
        st.markdown("---")
        st.markdown("### Current Recruitment Database")
        db_df = load_json_file(RECRUITMENT_DATA_FILE)
        if not db_df.empty:
            st.dataframe(db_df, use_container_width=True)
            buf = BytesIO()
            with pd.ExcelWriter(buf, engine="openpyxl") as writer:
                db_df.to_excel(writer, index=False)
            buf.seek(0)
            st.download_button(
                "📥 Download Recruitment Database",
                data=buf,
                file_name="Recruitment_Data.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )
        else:
            st.info("No recruitment data uploaded yet.")
# ... (الجزء الأول من الكود كما هو)
def page_settings(user):
    st.subheader("⚙️ System Settings")
    if user.get("Title", "").upper() != "HR":
        st.error("You do not have permission to access System Settings.")
        return
    st.markdown("Manage system configuration, templates, design and backup options.")
    # ❌ Removed General Settings and Theme Settings tabs
    tab3, tab4 = st.tabs([
        "🧾 Templates",
        "💾 Backup"
    ])
    with tab3:
        st.markdown("### Upload Templates")
        st.markdown("**Upload Salary Template (.xlsx)**")
        uploaded_template = st.file_uploader("Upload Salary Template", type=["xlsx"])
        if uploaded_template:
            with open("salary_template.xlsx", "wb") as f:
                f.write(uploaded_template.getbuffer())
            st.success("Salary template uploaded successfully.")
        st.markdown("### Upload System Logo")
        uploaded_logo = st.file_uploader("Upload Logo (PNG / JPG)", type=["png", "jpg", "jpeg"])
        if uploaded_logo:
            with open("logo.jpg", "wb") as f:
                f.write(uploaded_logo.getbuffer())
            st.success("Logo updated successfully.")
    with tab4:
        st.markdown("### Full System Backup")
        if st.button("Create Backup Zip"):
            backup_name = f"backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
            with zipfile.ZipFile(backup_name, "w") as zipf:
                for file in [
                    DEFAULT_FILE_PATH, LEAVES_FILE_PATH, NOTIFICATIONS_FILE_PATH,
                    HR_QUERIES_FILE_PATH, HR_REQUESTS_FILE_PATH, SALARIES_FILE_PATH
                ]:
                    if os.path.exists(file):
                        zipf.write(file)
                if os.path.exists("employee_photos"):
                    for photo in os.listdir("employee_photos"):
                        zipf.write(os.path.join("employee_photos", photo))
            with open(backup_name, "rb") as f:
                st.download_button(
                    label="📥 Download Backup ZIP",
                    data=f,
                    file_name=backup_name,
                    mime="application/zip"
                )
            st.success("Backup created successfully.")
# ... (باقي الكود كما هو)
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
        # ✅ FIXED: إغلاق الـ div داخل نفس الكتلة
        card_html = f"""
        <div class="hr-message-card">
        <div class="hr-message-title">📌 {subj if subj else 'No Subject'}</div>
        <div class="hr-message-meta">👤 {emp_name} — {emp_code} &nbsp;|&nbsp; 🕒 {sent_time} &nbsp;|&nbsp; 🏷️ {status}</div>
        <div class="hr-message-body">{msg if msg else ''}</div>
        </div>
        """
        st.markdown(card_html, unsafe_allow_html=True)
        if reply_existing:
            st.markdown("**🟢 Existing reply:**")
            st.markdown(reply_existing)
        reply_text = st.text_area("✍️ Write reply here:", value="", key=f"reply_{idx}", height=120)
        col1, col2, col3 = st.columns([2, 2, 1])
        with col1:
            if st.button("✅ Send Reply", key=f"send_reply_{idx}"):
                try:
                    hr_df.at[idx, "Reply"] = reply_text
                    hr_df.at[idx, "Status"] = "Replied"
                    hr_df.at[idx, "Date Replied"] = pd.Timestamp.now()
                    save_hr_queries(hr_df)
                    add_notification(emp_code, "", f"HR replied to your message: {subj}", target_page="Ask HR")
                    st.success("✅ Reply sent and employee notified.")
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ Failed to send reply: {e}")
        with col2:
            if st.button("🗂️ Mark as Closed", key=f"close_bottom_{idx}"):
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
                    add_notification("", "HR", f"New Ask HR from {user_name} ({user_code})", target_page="HR Inbox")
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
        # ✅ FIXED: إغلاق الـ div داخل نفس الكتلة
        message_html = f"""
        <div class='hr-message-card'>
        <div class='hr-message-title'>{subj}</div>
        <div class='hr-message-meta'>Sent: {sent_time} — Status: {status}</div>
        <div class='hr-message-body'>{msg}</div>
        </div>
        """
        st.markdown(message_html, unsafe_allow_html=True)
        if pd.notna(reply) and str(reply).strip() != "":
            st.markdown("**🟢 HR Reply:**")
            st.markdown(reply)
        else:
            st.markdown("**🕒 HR Reply:** Pending")
        st.markdown("---")
# ============================
# Main App Flow
# ============================
ensure_session_df()
if not os.path.exists(SECURE_PASSWORDS_FILE):
    df_init = st.session_state.get("df", pd.DataFrame())
    if not df_init.empty:
        initialize_passwords_from_data(df_init.to_dict(orient='records'))
# render_logo_and_title()  # ← تم حذف هذا السطر
if "logged_in_user" not in st.session_state:
    st.session_state["logged_in_user"] = None
if "current_page" not in st.session_state:
    st.session_state["current_page"] = "My Profile"
if "external_password_page" not in st.session_state:
    st.session_state["external_password_page"] = False
with st.sidebar:
    # تم حذف كل الكود الخاص باللوجو من هنا
    st.markdown('<div class="sidebar-title">HRAS — Averroes Admin</div>', unsafe_allow_html=True)
    st.markdown("<hr style='border: 1px solid #05445E; margin: 10px 0;'>", unsafe_allow_html=True)
    if not st.session_state["logged_in_user"] and not st.session_state["external_password_page"]:
        with st.container():
            st.markdown("<div style='background-color:white; padding: 10px; border-radius: 8px; border: 1px solid #cbd5e1;'>", unsafe_allow_html=True)
            st.markdown("### 🔐 Login Required")
            with st.form("login_form"):
                uid = st.text_input("Employee Code")
                pwd = st.text_input("Password", type="password")
                submitted = st.form_submit_button("Sign in")
                if submitted:
                    df = st.session_state.get("df", pd.DataFrame())
                    if df.empty:
                        st.error("Employee data not loaded. Please check your file.")
                    else:
                        user = login(df, uid, pwd)
                        if user is None:
                            st.error("Invalid credentials or required columns missing.")
                        else:
                            if "Title" not in user:
                                user["Title"] = "Unknown"
                            st.session_state["logged_in_user"] = user
                            st.session_state["current_page"] = "My Profile"
                            st.success("Login successful!")
                            st.rerun()
            st.markdown("</div>", unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("🔐 Change Password (No Login)", use_container_width=True):
            st.session_state["external_password_page"] = True
            st.rerun()
    else:
        if st.session_state["external_password_page"]:
            if st.button("← Back to Login", use_container_width=True):
                st.session_state["external_password_page"] = False
                st.rerun()
        else:
            user = st.session_state["logged_in_user"]
            title_val = str(user.get("Title") or user.get("title") or "").strip().upper()
            is_hr = "HR" in title_val
            is_bum = title_val == "BUM"
            is_am = title_val == "AM"
            is_dm = title_val == "DM"
            is_mr = title_val == "MR"
            # ✅ Define special titles that CAN access Leave Request & Team Leaves
            SPECIAL_TITLES = {
                "KEY ACCOUNT SPECIALIST",
                "SFE SPECIALIST",
                "TRAINING SPECIALIST",
                "SENIOR TALENT ACQUISITION",
                "HR SPECIALIST",
                "ASSOCIATE COMPLIANCE",
                "FIELD COMPLIANCE SPECIALIST",
                "OPERATION SUPERVISOR",
                "OPERATION ADMIN",
                "STORE SPECIALIST",
                "DIRECT SALES",
                "OPERATION SPECIALIST",
                "OPERATION AND ANALYTICS SPECIALIST",
                "OFFICE BOY"
            }
            is_special = title_val in SPECIAL_TITLES
            st.write(f"👋 **Welcome, {user.get('Employee Name') or 'User'}**")
            st.markdown("---")
            # ✅ حذف صفحة Notifications من جميع القوائم
            if is_hr:
                pages = ["Dashboard", "Reports", "HR Manager", "HR Inbox", "Employee Photos", "Ask Employees", "Recruitment", "🎓 Employee Development (HR View)", "Structure", "Salary Monthly", "Salary Report", "Settings"]
            elif is_bum:
                # ✅ BUM gets Team Leaves ONLY (Team Structure removed)
                pages = ["My Profile", "Team Leaves", "Ask HR", "Request HR", "Structure", "Salary Monthly"]
            elif is_am or is_dm:
                # ✅ AM/DM gets NO Team Structure or Team Leaves
                pages = ["My Profile", "Ask HR", "Request HR", "Structure", "Salary Monthly"]
            elif is_mr:
                # ✅ MR gets Notify Compliance + IDB + Self Development
                pages = ["My Profile", "🚀 IDB – Individual Development Blueprint", "🌱 Self Development", "Notify Compliance", "Ask HR", "Request HR", "Structure", "Salary Monthly"]
            elif is_special:
                # ✅ Special titles get Leave Request + Team Leaves access
                pages = ["My Profile", "Request Leave", "Team Leaves", "Ask HR", "Request HR", "Structure", "Salary Monthly"]
            else:
                pages = ["My Profile", "Request Leave", "Ask HR", "Request HR", "Structure", "Salary Monthly"]
                # ✅ FIXED: استبدال st.selectbox بأزرار فردية مع شارات الإشعارات الحمراء
            for page in pages:
                # التحقق من وجود إشعارات غير مقروءة لهذه الصفحة
                unread_count = 0
                notification_pages = [
                    "Ask HR", "Request HR", "HR Inbox", "Ask Employees", 
                    "Team Leaves", "📋 Report Compliance", "🎓 Employee Development (HR View)"
                ]
                
                if page in notification_pages:
                    unread_count = get_unread_count_for_page(user, page)
                
                # إنشاء تسمية الزر مع الشارة إذا لزم الأمر
                button_label = page
                if unread_count > 0:
                    button_label = f"{page} 🔴{unread_count}"
                
                if st.button(button_label, use_container_width=True, key=f"nav_{page}"):
                    st.session_state["current_page"] = page
                    
                    # وضع علامة مقروء تلقائياً عند فتح الصفحة
                    if page in notification_pages and unread_count > 0:
                        mark_page_as_read(user, page)
                    
                    st.rerun()
            st.markdown("---")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🚪 Logout", use_container_width=True):
                    st.session_state["logged_in_user"] = None
                    st.session_state["current_page"] = "My Profile"
                    st.rerun()
            with col2:
                if st.button("🔄 Refresh", use_container_width=True):
                    st.rerun()
            st.markdown("<br>", unsafe_allow_html=True)
            # ❌ تم حذف مؤشر الإشعارات القديم (الجرس الأحمر في الزاوية)
# ============================
# توجيه الصفحات الرئيسية
# ============================
if st.session_state["external_password_page"]:
    page_forgot_password()
elif st.session_state["logged_in_user"]:
    user = st.session_state["logged_in_user"]
    current_page = st.session_state["current_page"]
    # توجيه إلى دالة الصفحة المناسبة
    if current_page == "My Profile":
        page_my_profile(user)
    elif current_page == "Request Leave":
        page_leave_request(user)
    elif current_page == "Team Leaves":
        page_manager_leaves(user)
    elif current_page == "My Team":
        title_val = str(user.get("Title", "")).strip().upper()
        page_my_team(user, role=title_val)
    elif current_page == "Structure":
        page_directory(user)
    elif current_page == "Ask HR":
        page_ask_hr(user)
    elif current_page == "HR Inbox":
        page_hr_inbox(user)
    elif current_page == "Ask Employees":
        page_ask_employees(user)  # ✅ FIXED: filtered_options always defined now
    elif current_page == "Request HR":
        page_request_hr(user)
    elif current_page == "Dashboard":
        page_dashboard(user)
    elif current_page == "Reports":
        page_reports(user)
    elif current_page == "HR Manager":
        page_hr_manager(user)
    elif current_page == "Employee Photos":
        page_employee_photos(user)
    elif current_page == "Recruitment":
        page_recruitment(user)
    elif current_page == "Settings":
        page_settings(user)
    elif current_page == "Salary Monthly":
        page_salary_monthly(user)  # ✅ FIXED: Salary decryption handles edge cases properly
    elif current_page == "Salary Report":
        page_salary_report(user)
    elif current_page == "Notify Compliance":
        page_notify_compliance(user)
    elif current_page == "📋 Report Compliance":
        page_report_compliance(user)
    elif current_page == "🚀 IDB – Individual Development Blueprint":
        page_idb_mr(user)
    elif current_page == "🌱 Self Development":
        page_self_development(user)
    elif current_page == "🎓 Employee Development (HR View)":
        page_hr_development(user)
    # ❌ تم حذف: elif current_page == "Notifications": page_notifications(user)
    else:
        st.error(f"Page '{current_page}' not implemented yet.")
else:
    st.markdown("""
    <div style="text-align: center; padding: 40px; background-color: white; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.08);">
    <h2 style="color: #05445E; margin-bottom: 20px;">👥 HRAS — Averroes Admin System</h2>
    <p style="color: #666666; font-size: 1.1rem; max-width: 600px; margin: 0 auto;">
    Welcome to the HR Administration System. Please log in using your Employee Code and Password to access your personalized dashboard.
    </p>
    <div style="margin-top: 30px; padding: 15px; background-color: #f0fdf4; border-radius: 8px; border-left: 4px solid #059669;">
    <p style="color: #05445E; font-weight: 500; margin: 0;">
    🔐 Forgot your password? Click "Change Password (No Login)" on the sidebar to reset it.
    </p>
    </div>
    </div>
    """, unsafe_allow_html=True)
# ============================
# Footer
# ============================
st.markdown("""
<div style="text-align: center; padding: 20px; color: #666666; font-size: 0.9rem; margin-top: 30px; border-top: 1px solid #e5e7eb;">
<p>HRAS — Averroes Admin System &copy; 2026 | Secure • Encrypted • Role-Based Access</p>
</div>
""", unsafe_allow_html=True)
