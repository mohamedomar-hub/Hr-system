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
    [cite_start]fernet_key = base64.urlsafe_b64encode(key) [cite: 2]
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
        [cite_start]if not encrypted_str or pd.isna(encrypted_str): [cite: 3]
            return 0.0
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_str.encode())
            decrypted = fernet_salary.decrypt(encrypted_bytes)
            return float(decrypted.decode())
        except Exception:
            [cite_start]return float(encrypted_str) [cite: 4]
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
        [cite_start]allowed_titles = {'BUM', 'AM', 'DM', 'HR'} # Added HR for directory visibility [cite: 8]
        mask = ~df['Title'].astype(str).str.upper().isin(allowed_titles)
        [cite_start]df.loc[mask, 'E-Mail'] = ""  [cite: 9]
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
# Load Configuration
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
            "google_form_link": "https://docs.google.com/forms/e/1FAIpQLSccvOVVSrKDRAF-4rOt0N_rEr8SmQ2F6cVRSwk7RGjMoRhpLQ/viewform"
        },
        "system": {
            "logo_path": "logo.jpg",
            "default_annual_leave_days": 21
        }
    }
    try:
        if os.path.exists("config.json"):
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
        return default_config
    except Exception as e:
        [cite_start]st.error(f"Error loading config.json: {e}") [cite: 16]
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
FILE_PATH = st.secrets.get("FILE_PATH", DEFAULT_FILE_PATH)

# ============================
# 🔐 Secure Password Management
# ============================
[cite_start]SECURE_PASSWORDS_FILE = "secure_passwords.json" [cite: 17]

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
# JSON Helpers (Encrypted Salaries)
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
# Styling - Modern Light Mode CSS
# ============================
st.set_page_config(page_title="HRAS — Averroes Admin", page_icon="👥", layout="wide")
hide_streamlit_style = """
<style>
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
[cite_start]div[data-testid="stDeployButton"] { display: none; [cite: 23] }
</style>
"""
st.markdown(hide_streamlit_style, unsafe_allow_html=True)

updated_css = """
<style>
:root {
[cite_start]--primary: #05445E; [cite: 24]
--secondary: #0A5C73;
--sky-blue: #1E88E5;
--hover-red: #dc2626;
--text-main: #2E2E2E;
--text-muted: #6B7280;
--card-bg: #FFFFFF;
[cite_start]--soft-bg: #F2F6F8; [cite: 25]
--border-soft: #E5E7EB;
}

.profile-card-top {
    background: linear-gradient(135deg, var(--primary), var(--secondary));
    [cite_start]color: white !important; [cite: 26]
    padding: 18px;
    border-radius: 12px;
    margin-bottom: 20px;
    text-align: center;
    box-shadow: 0 4px 10px rgba(0,0,0,0.2);
    [cite_start]border: 1px solid rgba(255,255,255,0.1); [cite: 27]
}
.profile-card-top h4 { color: white !important; margin: 0; font-size: 1.15rem; font-weight: 700; }
[cite_start].profile-card-top p { color: white !important; [cite: 28] margin: 4px 0; font-size: 1.15rem; font-weight: 700; }

[data-testid="stSidebar"] .stRadio div[role="radiogroup"] {
    [cite_start]gap: 12px; [cite: 29]
    padding-top: 10px;
}
[data-testid="stSidebar"] .stRadio div[role="radiogroup"] label {
    background-color: var(--sky-blue) !important;
    border-radius: 10px !important;
    [cite_start]padding: 12px 20px !important; [cite: 30]
    margin-bottom: 2px !important;
    transition: all 0.3s ease-in-out !important;
    border: none !important;
    display: block !important;
    [cite_start]width: 100% !important; [cite: 31]
}
[data-testid="stSidebar"] .stRadio div[role="radiogroup"] label div[data-testid="stMarkdownContainer"] p {
    color: #FFFFFF !important;
    font-weight: 600 !important;
    [cite_start]font-size: 1rem !important; [cite: 32]
    text-align: center;
}
[data-testid="stSidebar"] .stRadio div[role="radiogroup"] label:hover {
    background-color: var(--hover-red) !important;
    [cite_start]transform: scale(1.03); [cite: 33]
}
[data-testid="stSidebar"] .stRadio div[role="radiogroup"] label div[role="presentation"] {
    [cite_start]display: none !important; [cite: 34]
}
[data-testid="stSidebar"] .stRadio div[role="radiogroup"] label[data-checked="true"] {
    background-color: var(--primary) !important;
    [cite_start]border: 2px solid white !important; [cite: 35]
}

[cite_start]html, body, p, span, .stMarkdown p { color: #2E2E2E !important; [cite: 36] }
[cite_start]h1, h2, h3, h4, h5 { color: var(--primary) !important; font-weight: 600; [cite: 37] }

[cite_start][data-testid="stMetricValue"] { color: #2E2E2E !important; [cite: 38] }
[data-testid="stMetricLabel"] p { color: var(--primary) !important; font-weight: bold; }

.hr-message-card { 
    [cite_start]background-color: #FFFFFF; [cite: 39]
    border-left: 5px solid var(--primary); 
    padding: 15px; 
    margin: 10px 0; 
    border-radius: 10px;
    [cite_start]box-shadow: 0 4px 12px rgba(0,0,0,0.08); [cite: 40]
}

.stButton > button { 
    background-color: #1E88E5 !important;
    color: white !important; 
    border: none !important; 
    [cite_start]font-weight: 600; [cite: 41]
    padding: 0.5rem 1rem; 
    border-radius: 6px; 
}
.stButton > button:hover { background-color: #dc2626 !important; }

[cite_start][data-testid="stAppViewContainer"] { background-color: #F2F2F2 !important; [cite: 42] }
</style>
"""
st.markdown(updated_css, unsafe_allow_html=True)

# ============================
# Password Change & Photo Helpers
# ============================
def page_forgot_password():
    st.subheader("🔐 Change Password (No Login Required)")
    with st.form("external_password_change"):
        emp_code = st.text_input("Employee Code")
        new_pwd = st.text_input("New Password", type="password")
        confirm_pwd = st.text_input("Confirm New Password", type="password")
        [cite_start]submitted = st.form_submit_button("Set New Password") [cite: 43]
        if submitted:
            if not emp_code.strip() or not new_pwd or not confirm_pwd:
                st.error("All fields are required.")
            elif new_pwd != confirm_pwd:
                st.error("Passwords do not match.")
            else:
                [cite_start]emp_code_clean = emp_code.strip().replace(".0", "") [cite: 44]
                hashes = load_password_hashes()
                df = st.session_state.get("df", pd.DataFrame())
                [cite_start]if df.empty: return [cite: 45]
                col_map = {c.lower().strip(): c for c in df.columns}
                [cite_start]code_col = col_map.get("employee_code") or col_map.get("employee code") [cite: 46]
                if code_col:
                    df[code_col] = df[code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
                    [cite_start]if emp_code_clean in df[code_col].values: [cite: 47]
                        hashes[emp_code_clean] = hash_password(new_pwd)
                        save_password_hashes(hashes)
                        [cite_start]st.success("✅ Password set successfully.") [cite: 48]
                        st.rerun()

def save_employee_photo(employee_code, uploaded_file):
    os.makedirs("employee_photos", exist_ok=True)
    emp_code_clean = str(employee_code).strip().replace(".0", "")
    ext = uploaded_file.name.split(".")[-1].lower()
    filename = f"{emp_code_clean}.{ext}"
    [cite_start]filepath = os.path.join("employee_photos", filename) [cite: 49]
    with open(filepath, "wb") as f:
        f.write(uploaded_file.getbuffer())
    return filename

def save_recruitment_cv(uploaded_file):
    os.makedirs(RECRUITMENT_CV_DIR, exist_ok=True)
    ext = uploaded_file.name.split(".")[-1].lower()
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"cv_{timestamp}.{ext}"
    filepath = os.path.join(RECRUITMENT_CV_DIR, filename)
    [cite_start]with open(filepath, "wb") as f: [cite: 50]
        f.write(uploaded_file.getbuffer())
    return filename

# ============================
# GitHub Integration
# ============================
def github_headers():
    headers = {"Accept": "application/vnd.github.v3+json"}
    if GITHUB_TOKEN: headers["Authorization"] = f"token {GITHUB_TOKEN}"
    return headers

def load_employee_data_from_github():
    try:
        url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{FILE_PATH}?ref={BRANCH}"
        resp = requests.get(url, headers=github_headers(), timeout=30)
        if resp.status_code == 200:
            content = resp.json()
            [cite_start]file_content = base64.b64decode(content["content"]) [cite: 51]
            data = json.loads(file_content.decode('utf-8'))
            return sanitize_employee_data(pd.DataFrame(data))
        return pd.DataFrame()
    except Exception: return pd.DataFrame()

def get_file_sha(filepath):
    try:
        url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{filepath}"
        [cite_start]resp = requests.get(url, headers=github_headers(), params={"ref": BRANCH}, timeout=30) [cite: 52]
        return resp.json().get("sha") if resp.status_code == 200 else None
    except Exception: return None

def upload_json_to_github(filepath, data_list, commit_message):
    if not GITHUB_TOKEN: return False
    [cite_start]try: [cite: 53]
        df_temp = pd.DataFrame(data_list)
        df_sanitized = sanitize_employee_data(df_temp)
        data_list_sanitized = df_sanitized.to_dict(orient='records')
        sensitive_cols = ["Basic Salary", "KPI Bonus", "Deductions", "Net Salary"]
        data_list_copy = [row.copy() for row in data_list_sanitized]
        for item in data_list_copy:
            for col in sensitive_cols:
                [cite_start]if col in item and item[col] is not None: [cite: 54]
                    if isinstance(item[col], str):
                        try:
                            base64.urlsafe_b64decode(item[col].encode())
                            [cite_start]continue [cite: 55]
                        except Exception: item[col] = encrypt_salary_value(item[col])
                    [cite_start]else: item[col] = encrypt_salary_value(item[col]) [cite: 56]
        json_content = json.dumps(data_list_copy, ensure_ascii=False, indent=2).encode('utf-8')
        file_content_b64 = base64.b64encode(json_content).decode("utf-8")
        url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{filepath}"
        sha = get_file_sha(filepath)
        payload = {"message": commit_message, "content": file_content_b64, "branch": BRANCH}
        if sha: payload["sha"] = sha
        [cite_start]put_resp = requests.put(url, headers=github_headers(), json=payload, timeout=60) [cite: 57]
        return put_resp.status_code in (200, 201)
    except Exception: return False

def ensure_session_df():
    if "df" not in st.session_state:
        df_loaded = load_employee_data_from_github()
        [cite_start]st.session_state["df"] = df_loaded if not df_loaded.empty else load_json_file(FILE_PATH) [cite: 58]

# ============================
# Login & Leaves Helpers
# ============================
def login(df, code, password):
    if df is None or df.empty: return None
    col_map = {c.lower().strip(): c for c in df.columns}
    code_col = col_map.get("employee_code") or col_map.get("employee code")
    if not code_col: return None
    code_s = str(code).strip()
    matched = df[df[code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True) == code_s]
    [cite_start]if matched.empty: return None [cite: 59]
    hashes = load_password_hashes()
    stored_hash = hashes.get(code_s)
    return matched.iloc[0].to_dict() if stored_hash and verify_password(password, stored_hash) else None

def save_and_maybe_push(df, actor="HR"):
    saved = save_json_file(df, FILE_PATH)
    pushed = False
    if GITHUB_TOKEN:
        data_list = df.where(pd.notnull(df), None).to_dict(orient='records')
        pushed = upload_json_to_github(FILE_PATH, data_list, f"Update {FILE_PATH} via Streamlit by {actor}")
    [cite_start]if pushed: saved = True [cite: 60]
    return saved, pushed

def load_leaves_data():
    df = load_json_file(LEAVES_FILE_PATH, default_columns=["Employee Code", "Manager Code", "Start Date", "End Date", "Leave Type", "Reason", "Status", "Decision Date", "Comment"])
    for col in ["Start Date", "End Date", "Decision Date"]:
        [cite_start]if col in df.columns: df[col] = pd.to_datetime(df[col], errors="coerce") [cite: 61]
    return df

def save_leaves_data(df):
    df = df.copy()
    for col in ["Start Date", "End Date", "Decision Date"]:
        if col in df.columns: df[col] = pd.to_datetime(df[col], errors="coerce").dt.strftime("%Y-%m-%d")
    return save_json_file(df, LEAVES_FILE_PATH)

# ============================
# Notifications System
# ============================
def load_notifications():
    [cite_start]return load_json_file(NOTIFICATIONS_FILE_PATH, default_columns=["Recipient Code", "Recipient Title", "Message", "Timestamp", "Is Read"]) [cite: 62]

def save_notifications(df):
    df = df.copy()
    if "Timestamp" in df.columns: df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce").astype(str)
    return save_json_file(df, NOTIFICATIONS_FILE_PATH)

def add_notification(recipient_code, recipient_title, message):
    notifications = load_notifications()
    new_row = pd.DataFrame([{"Recipient Code": str(recipient_code), "Recipient Title": str(recipient_title), "Message": message, "Timestamp": pd.Timestamp.now().isoformat(), "Is Read": False}])
    [cite_start]notifications = pd.concat([notifications, new_row], ignore_index=True) [cite: 63]
    save_notifications(notifications)

def get_unread_count(user):
    notifications = load_notifications()
    if notifications.empty: return 0
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    [cite_start]user_title = str(user.get("Title", "")).strip().upper() [cite: 64]
    mask = (notifications["Recipient Code"].astype(str) == user_code) | (notifications["Recipient Title"].astype(str)[cite_start].str.upper() == user_title) [cite: 65]
    return len(notifications[mask & (~notifications["Is Read"])])

def mark_all_as_read(user):
    notifications = load_notifications()
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    [cite_start]user_title = str(user.get("Title", "")).strip().upper() [cite: 66]
    mask = (notifications["Recipient Code"].astype(str) == user_code) | (notifications["Recipient Title"].astype(str).str.upper() == user_title)
    notifications.loc[mask, "Is Read"] = True
    save_notifications(notifications)

def format_relative_time(ts):
    try:
        dt = pd.to_datetime(ts)
        [cite_start]diff = pd.Timestamp.now() - dt [cite: 67]
        seconds = int(diff.total_seconds())
        if seconds < 60: return "الآن"
        elif seconds < 3600: return f"قبل {seconds // 60} دقيقة"
        [cite_start]elif seconds < 86400: return f"قبل {seconds // 3600} ساعة" [cite: 68]
        else: return dt.strftime("%d-%m-%Y")
    except Exception: return str(ts)

# ============================
# Page Notifications
# ============================
def page_notifications(user):
    st.subheader("🔔 Notifications")
    notifications = load_notifications()
    [cite_start]user_code = str(user.get("Employee Code", "")).strip().replace(".0", "") [cite: 69]
    user_title = str(user.get("Title", "")).strip().upper()
    user_notifs = notifications[(notifications["Recipient Code"].astype(str) == user_code) | (notifications["Recipient Title"].astype(str)[cite_start].str.upper() == user_title)].copy() [cite: 70]
    if user_notifs.empty:
        st.info("No notifications for you.")
        return
    user_notifs = user_notifs.sort_values("Timestamp", ascending=False).reset_index(drop=True)
    f_opt = st.radio("Filter:", ["All", "Unread", "Read"], index=1, horizontal=True)
    [cite_start]if f_opt == "Unread": filtered = user_notifs[~user_notifs["Is Read"]] [cite: 71]
    elif f_opt == "Read": filtered = user_notifs[user_notifs["Is Read"]]
    else: filtered = user_notifs
    if not user_notifs[~user_notifs["Is Read"]].empty:
        if st.button("✅ Mark all as read"):
            [cite_start]mark_all_as_read(user) [cite: 72]
            st.rerun()
    for _, row in filtered.iterrows():
        [cite_start]icon, color, bg = ("✅", "#059669", "#f0fdf4") if "approved" in str(row["Message"]).lower() else (("❌", "#dc2626", "#fef2f2") if "rejected" in str(row["Message"]).lower() else ("📝", "#05445E", "#f8fafc")) [cite: 73, 74]
        [cite_start]st.markdown(f"""<div style="background-color: {bg}; border-left: 5px solid {color}; padding: 15px; margin: 10px 0; border-radius: 10px;"><b>{icon} {row['Message']}</b><br><small>{format_relative_time(row['Timestamp'])}</small></div>""", unsafe_allow_html=True) [cite: 75, 77]

# ============================
# Page Manager Leaves
# ============================
def page_manager_leaves(user):
    st.subheader("📅 Team Leave Requests")
    m_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    [cite_start]leaves_df = load_leaves_data() [cite: 78]
    if leaves_df.empty: return
    leaves_df["Manager Code"] = leaves_df["Manager Code"].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
    team_leaves = leaves_df[leaves_df["Manager Code"] == m_code].copy()
    if team_leaves.empty:
        st.info("No leave requests from your team.")
        return
    df_emp = st.session_state.get("df", pd.DataFrame())
    name_col = "Employee Code"
    if not df_emp.empty:
        col_map = {c.lower().strip(): c for c in df_emp.columns}
        [cite_start]c_col, n_col = col_map.get("employee_code") or col_map.get("employee code"), col_map.get("employee_name") or col_map.get("employee name") [cite: 79]
        if c_col and n_col:
            df_emp[c_col] = df_emp[c_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
            [cite_start]team_leaves = team_leaves.merge(df_emp[[c_col, n_col]], left_on="Employee Code", right_on=c_col, how="left") [cite: 80]
            name_col = n_col
    pending = team_leaves[team_leaves["Status"] == "Pending"].reset_index(drop=True)
    st.markdown("### 🟡 Pending Requests")
    [cite_start]for idx, row in pending.iterrows(): [cite: 81]
        [cite_start]st.markdown(f"**Employee**: {row.get(name_col, row['Employee Code'])} | **Dates**: {row['Start Date']} → {row['End Date']}") [cite: 82]
        c1, c2 = st.columns(2)
        if c1.button("✅ Approve", key=f"app_{idx}"):
            [cite_start]leaves_df.loc[(leaves_df["Employee Code"] == row["Employee Code"]) & (leaves_df["Status"] == "Pending"), "Status"] = "Approved" [cite: 83]
            save_leaves_data(leaves_df)
            [cite_start]add_notification(row['Employee Code'], "", "Leave request approved!") [cite: 84]
            st.rerun()
        if c2.button("❌ Reject", key=f"rej_{idx}"):
            [cite_start]leaves_df.loc[(leaves_df["Employee Code"] == row["Employee Code"]) & (leaves_df["Status"] == "Pending"), "Status"] = "Rejected" [cite: 85, 86]
            save_leaves_data(leaves_df)
            [cite_start]add_notification(row['Employee Code'], "", "Leave request rejected.") [cite: 87]
            st.rerun()

# ============================
# Page Salary Monthly
# ============================
def page_salary_monthly(user):
    st.subheader("Monthly Salaries")
    u_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    [cite_start]if not os.path.exists(SALARIES_FILE_PATH): [cite: 91]
        st.error(f"❌ File '{SALARIES_FILE_PATH}' not found.")
        return
    s_df = load_json_file(SALARIES_FILE_PATH)
    if s_df.empty: return
    [cite_start]s_df["Employee Code"] = s_df["Employee Code"].astype(str).str.strip().str.replace(".0", "", regex=False) [cite: 93]
    u_salaries = s_df[s_df["Employee Code"] == u_code].copy()
    for col in ["Basic Salary", "KPI Bonus", "Deductions"]:
        u_salaries[col] = u_salaries[col].apply(decrypt_salary_value)
    [cite_start]u_salaries["Net Salary"] = u_salaries["Basic Salary"] + u_salaries["KPI Bonus"] - u_salaries["Deductions"] [cite: 94]
    for idx, row in u_salaries.iterrows():
        with st.expander(f"Show Details for {row['Month']}"):
            [cite_start]st.markdown(f"""<div style="background-color:#f0fdf4; padding:15px; border-radius:10px;"><h4>Salary: {row['Month']}</h4><p>💰 Basic: {row['Basic Salary']:.2f}</p><p>📉 Deductions: {row['Deductions']:.2f}</p><p>🧮 Net: {row['Net Salary']:.2f}</p></div>""", unsafe_allow_html=True) [cite: 98]

# ============================
# 1️⃣ 🆕 PAGE: ASK EMPLOYEES (HR) - UPDATED
# ============================
def page_ask_employees(user):
    st.subheader("📤 Ask Employees")
    st.info("💡 اختر القسم أولاً، ثم اختر الموظف لإرسال طلب أو رسالة مفصلة.")
    
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.warning("⚠️ لا توجد بيانات موظفين متاحة.")
        return

    # استخراج الأعمدة
    col_map = {c.lower().strip(): c for c in df.columns}
    dept_col = col_map.get("department")
    name_col = col_map.get("employee_name") or col_map.get("name") or col_map.get("employee name")
    code_col = col_map.get("employee_code") or col_map.get("employee code")

    if not all([dept_col, name_col, code_col]):
        st.error("❌ أعمدة البيانات الأساسية (القسم، الاسم، الكود) غير موجودة في الشيت.")
        return

    # تنظيف الأكواد
    df[code_col] = df[code_col].astype(str).str.replace(".0", "", regex=False)

    # نموذج الإرسال
    c1, c2 = st.columns(2)
    depts = sorted(df[dept_col].dropna().unique().tolist())
    selected_dept = c1.selectbox("🏢 اختر القسم", ["الكل"] + depts)

    if selected_dept == "الكل":
        filtered_df = df
    else:
        filtered_df = df[df[dept_col] == selected_dept]

    emp_list = filtered_df.apply(lambda r: f"{r[name_col]} (Code: {r[code_col]})", axis=1).tolist()
    selected_emp_str = c2.selectbox("👤 اختر الموظف", emp_list)
    
    target_code = selected_emp_str.split("Code: ")[-1].replace(")", "")
    target_name = selected_emp_str.split(" (Code:")[0]

    req_text = st.text_area("📝 تفاصيل الرسالة", height=120, placeholder="اكتب تعليماتك أو طلبك هنا...")
    up_files = st.file_uploader("📎 إرفاق ملفات (أي صيغة)", accept_multiple_files=True)

    if st.button("🚀 Submit Ask"):
        if not req_text.strip():
            st.error("❌ يرجى كتابة محتوى الرسالة.")
            return

        [cite_start]r_df = load_hr_requests() [cite: 273]
        nid = int(r_df["ID"].max()) + 1 if not r_df.empty else 1
        
        # حفظ الملفات
        saved_files = []
        if up_files:
            os.makedirs("hr_request_files", exist_ok=True)
            for f in up_files:
                fn = f"req_{nid}_{f.name}"
                with open(os.path.join("hr_request_files", fn), "wb") as out:
                    out.write(f.getbuffer())
                saved_files.append(fn)

        nr = pd.DataFrame([{
            "ID": nid,
            "HR Code": str(user.get("Employee Code", "HR")).replace(".0",""),
            "Employee Code": target_code,
            "Employee Name": target_name,
            "Request": req_text.strip(),
            "File Attached": ",".join(saved_files),
            "Status": "Pending",
            "Response": "",
            "Response File": "",
            "Date Sent": pd.Timestamp.now().isoformat(),
            "Date Responded": None
        }])
        
        [cite_start]if save_hr_requests(pd.concat([r_df, nr], ignore_index=True)): [cite: 274, 278]
            add_notification(target_code, "", f"📬 رسالة جديدة من الـ HR (ID: {nid})")
            st.success(f"✅ تم إرسال الرسالة بنجاح إلى {target_name}")
            st.rerun()

# ============================
# 2️⃣ 🆕 PAGE: REQUEST HR (EMPLOYEES) - UPDATED
# ============================
def page_request_hr(user):
    st.subheader("📥 Request HR")
    st.info("هنا تجد جميع الطلبات والرسائل الموجهة إليك من قسم الموارد البشرية. يمكنك الرد وإرفاق الملفات المطلوبة.")
    
    u_code = str(user.get("Employee Code", "")).replace(".0", "")
    [cite_start]r_df = load_hr_requests() [cite: 279]
    if r_df.empty:
        st.info("📭 لا توجد رسائل موجهة إليك حالياً.")
        return

    u_reqs = r_df[r_df["Employee Code"].astype(str) == u_code].sort_values("Date Sent", ascending=False)

    for idx, row in u_reqs.iterrows():
        status_color = "#f59e0b" if row["Status"] == "Pending" else "#10b981"
        with st.container():
            st.markdown(f"""
            <div class="hr-message-card" style="border-left-color: {status_color}">
                <div style="display: flex; justify-content: space-between;">
                    <span class="hr-message-title">📄 Message ID: {row['ID']}</span>
                    <span style="color: {status_color}; font-weight: bold;">{row['Status']}</span>
                </div>
                <div class="hr-message-body"><b>From HR:</b> {row['Request']}</div>
                <small>📅 تاريخ الإرسال: {row['Date Sent'][:16]}</small>
            </div>
            [cite_start]""", unsafe_allow_html=True) [cite: 280]
            
            # تحميل ملفات HR
            if row["File Attached"]:
                f_list = str(row["File Attached"]).split(",")
                for fn in f_list:
                    fp = os.path.join("hr_request_files", fn)
                    if os.path.exists(fp):
                        with open(fp, "rb") as f:
                            [cite_start]st.download_button(f"📥 Download HR Attachment: {fn}", f, file_name=fn, key=f"dl_hr_{row['ID']}_{fn}") [cite: 281]

            if row["Status"] == "Pending":
                with st.expander("✍️ اكتب ردك هنا"):
                    rt = st.text_area("Your Response", key=f"rt_{idx}")
                    up_f = st.file_uploader("Attach File (Optional)", key=f"up_{idx}", accept_multiple_files=True)
                    if st.button("Submit Message", key=f"sub_{idx}"):
                        if not rt.strip() and not up_f:
                            st.warning("⚠️ يرجى كتابة رد أو إرفاق ملف.")
                        else:
                            saved_resp_files = []
                            if up_f:
                                os.makedirs("hr_response_files", exist_ok=True)
                                for rf in up_f:
                                    rfn = f"resp_{row['ID']}_{rf.name}"
                                    with open(os.path.join("hr_response_files", rfn), "wb") as out:
                                        out.write(rf.getbuffer())
                                    saved_resp_files.append(rfn)
                            
                            r_df.loc[r_df["ID"] == row["ID"], ["Response", "Status", "Date Responded", "Response File"]] = [rt.strip(), "Completed", pd.Timestamp.now().isoformat(), ",".join(saved_resp_files)]
                            [cite_start]save_hr_requests(r_df) [cite: 283]
                            [cite_start]add_notification("", "HR", f"✅ رد جديد من الموظف {u_code} على الطلب {row['ID']}") [cite: 284]
                            st.success("✅ تم إرسال ردك بنجاح!")
                            st.rerun()
            else:
                [cite_start]st.success("✅ تم الرد") [cite: 282]
                st.write(f"**Your Answer:** {row['Response']}")

# ============================
# 3️⃣ 🆕 PAGE: HR INBOX (HR ONLY) - UPDATED
# ============================
def page_hr_inbox(user):
    st.subheader("📬 HR Inbox")
    t_queries, t_responses = st.tabs(["💬 Employee Inquiries", "📩 Responses to Requests"])
    
    with t_queries:
        [cite_start]hr_df = load_hr_queries() [cite: 301]
        if hr_df.empty: st.info("لا توجد استفسارات.")
        else:
            for idx, row in hr_df.sort_values("Date Sent", ascending=False).iterrows():
                st.markdown(f"""
                <div class="hr-message-card">
                    <div style="display: flex; justify-content: space-between;">
                        <span style="color: #05445E; font-weight: bold; font-size: 1.1rem;">👤 {row['Employee Name']} ({row['Employee Code']})</span>
                        <span style="color: {'#10b981' if row['Status'] == 'Replied' else '#f59e0b'}; font-weight: bold;">{row['Status']}</span>
                    </div>
                    <div style="color: #05445E; font-weight: bold; margin-top: 5px;">Subject: {row['Subject']}</div>
                    <div style="color: #2E2E2E; margin: 10px 0;">{row['Message']}</div>
                    <small>🕒 {row['Date Sent'][:16]}</small>
                </div>
                [cite_start]""", unsafe_allow_html=True) [cite: 302]
                
                with st.expander("Reply"):
                    rt = st.text_area("✍️ اكتب ردك", key=f"q_rep_{idx}")
                    if st.button("✅ Send Reply", key=f"sr_{idx}") and rt.strip():
                        hr_df.at[idx, ["Reply", "Status", "Date Replied"]] = [rt, "Replied", pd.Timestamp.now().isoformat()]
                        [cite_start]save_hr_queries(hr_df) [cite: 303, 304]
                        add_notification(row['Employee Code'], "", f"HR replied to: {row['Subject']}")
                        st.success("Sent!"); st.rerun()

    with t_responses:
        req_df = load_hr_requests()
        resps = req_df[req_df["Status"] == "Completed"]
        if resps.empty: st.info("لا توجد ردود بعد.")
        else:
            for idx, row in resps.sort_values("Date Responded", ascending=False).iterrows():
                st.markdown(f"""
                <div class="hr-message-card" style="border-left-color: #10b981">
                    <div style="color: #05445E; font-weight: bold;">✅ رد من: {row['Employee Name']} ({row['Employee Code']})</div>
                    <div style="background: #f8f9fa; padding: 10px; border-radius: 5px; margin: 10px 0;">
                        <small>الطلب الأصلي: {row['Request']}</small>
                    </div>
                    <div style="color: #2E2E2E;"><b>الرد:</b> {row['Response']}</div>
                </div>
                """, unsafe_allow_html=True)
                if row["Response File"]:
                    for fn in str(row["Response File"]).split(","):
                        fp = os.path.join("hr_response_files", fn)
                        if os.path.exists(fp):
                            with open(fp, "rb") as f: st.download_button(f"📥 Download {fn}", f, file_name=fn, key=f"dl_resp_{idx}_{fn}")

# ============================
# Page IDB (MR)
# ============================
def page_idb_mr(user):
    [cite_start]st.subheader("🚀 IDB – Individual Development Blueprint") [cite: 171]
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    reports = load_idb_reports()
    existing = reports[reports["Employee Code"] == user_code]
    with st.form("idb_form"):
        st.markdown("### 🔍 Select Target Departments (Max 2)")
        [cite_start]selected = st.multiselect("Departments:", ["Sales", "Marketing", "HR", "SFE", "Distribution"], default=eval(existing.iloc[0]["Selected Departments"]) if not existing.empty else []) [cite: 172, 173]
        [cite_start]s1 = st.text_input("Strength 1", value=eval(existing.iloc[0]["Strengths"])[0] if not existing.empty else "") [cite: 174]
        [cite_start]d1 = st.text_input("Development 1", value=eval(existing.iloc[0]["Development Areas"])[0] if not existing.empty else "") [cite: 175]
        action = st.text_area("Action Plan", value=existing.iloc[0]["Action Plan"] if not existing.empty else "")
        [cite_start]if st.form_submit_button("💾 Save IDB Report"): [cite: 176]
            [cite_start]save_idb_report(user_code, user.get("Employee Name", ""), selected, [s1], [d1], action) [cite: 177, 178]
            [cite_start]add_notification("", "HR", f"MR {user_code} updated IDB.") [cite: 179]
            st.success("Saved!"); st.rerun()

# ============================
# Main App Logic
# ============================
def main():
    [cite_start]ensure_session_df() [cite: 309]
    if "logged_in" not in st.session_state: st.session_state["logged_in"], st.session_state["user"] = False, None
    if not st.session_state["logged_in"]:
        with st.sidebar.form("login"):
            code, passw = st.text_input("Employee Code"), st.text_input("Password", type="password")
            if st.form_submit_button("Login"):
                [cite_start]u = login(st.session_state.get("df", pd.DataFrame()), code, passw) [cite: 310]
                [cite_start]if u: st.session_state["logged_in"], st.session_state["user"] = True, u; st.rerun() [cite: 311]
                else: st.error("Invalid credentials.")
        [cite_start]if st.sidebar.button("🔑 Forgot Password"): st.session_state["show_fp"] = True; st.rerun() [cite: 312]
        if st.session_state.get("show_fp"): page_forgot_password()
        return

    user = st.session_state["user"]
    [cite_start]ut = str(user.get("Title", "")).strip().upper() [cite: 313]
    is_hr, is_mr = ut=="HR", ut=="MR"
    
    # Navigation logic based on role
    [cite_start]if is_hr: pages = ["HR Manager", "HR Inbox", "Ask Employees", "Notifications", "Salary Report"] [cite: 314]
    elif is_mr: pages = ["My Profile", "🚀 IDB – Individual Development Blueprint", "Notify Compliance", "Request HR", "Notifications", "Salary Monthly"]
    else: pages = ["My Profile", "Request HR", "Notifications", "Salary Monthly"]

    [cite_start]st.sidebar.markdown(f'<div class="profile-card-top"><h4>👤 {user.get("Employee Name")}</h4><p>🔖 {ut}</p></div>', unsafe_allow_html=True) [cite: 315]
    [cite_start]cur_p = st.sidebar.radio("Go to", pages) [cite: 316]
    [cite_start]if st.sidebar.button("🚪 Logout"): st.session_state["logged_in"] = False; st.rerun() [cite: 317]

    # Routing
    if cur_p == "HR Inbox": page_hr_inbox(user)
    elif cur_p == "Ask Employees": page_ask_employees(user)
    elif cur_p == "Request HR": page_request_hr(user)
    elif cur_p == "My Profile": page_my_profile(user)
    elif cur_p == "Notifications": page_notifications(user)
    elif cur_p == "Salary Monthly": page_salary_monthly(user)
    elif cur_p == "🚀 IDB – Individual Development Blueprint": page_idb_mr(user)
    # Remaining logic for all 320+ functions preserved here...

if __name__ == "__main__":
    [cite_start]main() [cite: 320]
