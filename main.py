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
# 🆕 NEW FILES FOR IDB & CERTIFICATIONS
# ============================
IDB_REPORTS_FILE = "idb_reports.json"
CERTIFICATIONS_LOG_FILE = "certifications_log.json"
CERTIFICATIONS_DIR = "certifications"

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
# 🆕 IDB HELPERS
# ============================
def load_idb_reports():
    return load_json_file(IDB_REPORTS_FILE, default_columns=[
        "Employee Code", "Selected Departments", "Strengths", "Development Areas", "Action Plan", "Updated At"
    ])

def save_idb_report(employee_code, selected_deps, strengths, development, action):
    reports = load_idb_reports()
    now = pd.Timestamp.now().isoformat()
    new_row = {
        "Employee Code": employee_code,
        "Selected Departments": selected_deps,
        "Strengths": strengths,
        "Development Areas": development,
        "Action Plan": action,
        "Updated At": now
    }
    reports = reports[reports["Employee Code"] != employee_code]
    reports = pd.concat([reports, pd.DataFrame([new_row])], ignore_index=True)
    return save_json_file(reports, IDB_REPORTS_FILE)

# ============================
# 🆕 CERTIFICATION HELPERS
# ============================
def save_certification_file(uploaded_file, employee_code):
    os.makedirs(CERTIFICATIONS_DIR, exist_ok=True)
    ext = uploaded_file.name.split(".")[-1].lower()
    if ext not in ["pdf", "jpg", "jpeg", "png"]:
        raise ValueError("Only PDF, JPG, PNG allowed.")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"cert_{employee_code}_{timestamp}.{ext}"
    filepath = os.path.join(CERTIFICATIONS_DIR, filename)
    with open(filepath, "wb") as f:
        f.write(uploaded_file.getbuffer())
    return filename

def load_certifications_log():
    return load_json_file(CERTIFICATIONS_LOG_FILE, default_columns=[
        "Employee Code", "File", "Description", "Uploaded At"
    ])

def save_certification_log(employee_code, filename, description):
    log_df = load_certifications_log()
    new_row = pd.DataFrame([{
        "Employee Code": employee_code,
        "File": filename,
        "Description": description,
        "Uploaded At": pd.Timestamp.now().isoformat()
    }])
    log_df = pd.concat([log_df, new_row], ignore_index=True)
    return save_json_file(log_df, CERTIFICATIONS_LOG_FILE)

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
        # Save encrypted version to disk
        data = df_copy.where(pd.notnull(df_copy), None).to_dict(orient='records')
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False

# ============================
# Existing helper functions (unchanged)
# ============================

def apply_custom_css():
    st.markdown("""
    <style>
        /* General background and text */
        .stApp {
            background-color: #ffffff;
            color: #05445E;
        }
        /* Sidebar */
        [data-testid="stSidebar"] {
            background-color: #f8f9fa;
        }
        /* Buttons */
        .stButton > button {
            background-color: #05445E;
            color: white;
            border: none;
            border-radius: 6px;
            padding: 8px 16px;
            font-weight: bold;
        }
        .stButton > button:hover {
            background-color: red !important;
            color: white !important;
        }
        /* Tables */
        .dataframe {
            font-size: 14px;
        }
        th {
            background-color: #05445E !important;
            color: white !important;
        }
        /* Inputs */
        input, textarea, select {
            border: 1px solid #05445E;
            border-radius: 4px;
        }
        /* Success/Error messages */
        .stSuccess, .stError, .stWarning {
            font-weight: bold;
        }
    </style>
    """, unsafe_allow_html=True)

def add_notification(sender, recipient, message):
    notifications = load_json_file(NOTIFICATIONS_FILE_PATH, default_columns=["Sender", "Recipient", "Message", "Timestamp", "Read"])
    new_notification = pd.DataFrame([{
        "Sender": sender,
        "Recipient": recipient,
        "Message": message,
        "Timestamp": pd.Timestamp.now().isoformat(),
        "Read": False
    }])
    notifications = pd.concat([notifications, new_notification], ignore_index=True)
    save_json_file(notifications, NOTIFICATIONS_FILE_PATH)

def load_leaves_data():
    return load_json_file(LEAVES_FILE_PATH, default_columns=[
        "Employee Code", "Employee Name", "Start Date", "End Date", "Days", "Type", "Status", "Notes", "Request Date"
    ])

def save_and_maybe_push(df, actor="System"):
    saved = save_json_file(df, FILE_PATH)
    pushed = False
    if saved and GITHUB_TOKEN:
        try:
            with open(FILE_PATH, "rb") as f:
                content = base64.b64encode(f.read()).decode()
            url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{FILE_PATH}"
            headers = {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"}
            response = requests.get(url, headers=headers, params={"ref": BRANCH})
            sha = response.json().get("sha", "") if response.status_code == 200 else ""
            payload = {
                "message": f"Update by {actor} at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}",
                "content": content,
                "branch": BRANCH
            }
            if sha:
                payload["sha"] = sha
            requests.put(url, headers=headers, json=payload)
            pushed = True
        except Exception:
            pushed = False
    return saved, pushed

def login_page():
    st.title("🔐 HR System Login")
    st.markdown("Please enter your credentials to continue.")
    df = st.session_state.get("df", pd.DataFrame())
    col_map = {c.lower().strip(): c for c in df.columns}
    code_col = col_map.get("employee_code") or col_map.get("employee code")
    name_col = col_map.get("employee name") or col_map.get("name")
    title_col = col_map.get("title")
    if not all([code_col, name_col, title_col]):
        st.error("Required columns missing in employee data.")
        return
    df[code_col] = df[code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
    employee_codes = df[code_col].tolist()
    selected_code = st.selectbox("Employee Code", [""] + employee_codes)
    if selected_code:
        user_row = df[df[code_col] == selected_code]
        if not user_row.empty:
            user_name = user_row.iloc[0][name_col]
            st.write(f"Welcome, **{user_name}**")
            stored_hashes = load_password_hashes()
            if selected_code in stored_hashes:
                password = st.text_input("Password", type="password")
                if st.button("Login"):
                    if verify_password(password, stored_hashes[selected_code]):
                        st.session_state["authenticated"] = True
                        st.session_state["user"] = {
                            "Employee Code": selected_code,
                            "Employee Name": user_name,
                            "Title": user_row.iloc[0][title_col]
                        }
                        st.rerun()
                    else:
                        st.error("Incorrect password.")
            else:
                st.error("No password set for this employee. Contact HR.")

# ============================
# Page: My Profile (with Private Email)
# ============================
def page_my_profile(user):
    st.subheader("👤 My Profile")
    user_code_clean = str(user.get("Employee Code", "")).strip().replace(".0", "")
    df = st.session_state.get("df", pd.DataFrame())
    col_map = {c.lower().strip(): c for c in df.columns}
    code_col = col_map.get("employee_code") or col_map.get("employee code")
    if not code_col:
        st.error("Employee code column not found.")
        return
    df[code_col] = df[code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
    user_row = df[df[code_col] == user_code_clean]
    if user_row.empty:
        st.error("Your record not found.")
        return
    user_data = user_row.iloc[0].to_dict()
    # Display profile info (non-sensitive)
    st.markdown("### 📋 Personal Information")
    for key, value in user_data.items():
        if key not in ["Password", "annual_leave_balance", "monthly_salary"]:
            st.write(f"**{key}:** {value}")
    # 🔐 Change Password
    st.markdown("---")
    st.markdown("### 🔑 Change Your Password")
    with st.form("change_password_form"):
        current_pwd = st.text_input("Current Password", type="password")
        new_pwd = st.text_input("New Password", type="password")
        confirm_pwd = st.text_input("Confirm New Password", type="password")
        pwd_submitted = st.form_submit_button("🔄 Update Password")
        if pwd_submitted:
            if not current_pwd or not new_pwd or not confirm_pwd:
                st.error("All fields are required.")
            elif new_pwd != confirm_pwd:
                st.error("New passwords do not match.")
            else:
                emp_code = user_code_clean
                stored_hashes = load_password_hashes()
                if emp_code not in stored_hashes:
                    st.error("Password record not found. Contact HR.")
                elif not verify_password(current_pwd, stored_hashes[emp_code]):
                    st.error("Incorrect current password.")
                else:
                    stored_hashes[emp_code] = hash_password(new_pwd)
                    save_password_hashes(stored_hashes)
                    st.success("✅ Password updated successfully!")
                    st.rerun()
    # 📧 Private Email Section (NEW)
    st.markdown("---")
    st.markdown("### 📧 Private Email (Visible only to you and HR)")
    current_private_email = user_data.get("Private Email", "") or ""
    with st.form("private_email_form"):
        new_private_email = st.text_input("Your Personal Email", value=str(current_private_email))
        email_submitted = st.form_submit_button("💾 Save Private Email")
        if email_submitted:
            df.loc[df[code_col] == user_code_clean, "Private Email"] = new_private_email
            st.session_state["df"] = df
            saved, pushed = save_and_maybe_push(df, actor=user.get("Employee Name","HR"))
            if saved:
                st.success("✅ Private email saved.")
                if pushed:
                    st.success("Pushed to GitHub.")
                st.rerun()
            else:
                st.error("❌ Failed to save.")

# ============================
# Page: Notify Compliance
# ============================
def page_notify_compliance(user):
    st.subheader("🚨 Notify Compliance")
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    user_name = user.get("Employee Name", "")
    compliance_recipients = ["DM", "AM", "BUM", "HR"]
    recipient_title = st.selectbox("Select Compliance Authority", compliance_recipients)
    message = st.text_area("Your Message", height=150)
    if st.button("📤 Send Notification"):
        if not message.strip():
            st.error("Message cannot be empty.")
        else:
            add_notification(user_name, recipient_title, f"[Compliance Alert from MR {user_code}] {message}")
            st.success("✅ Message sent successfully to Compliance Authority!")

# ============================
# 🆕 Page: IDB for MR
# ============================
def page_idb_mr(user):
    st.subheader("🚀 IDB – Individual Development Blueprint")
    st.markdown("""
    <div style="background-color:#f0fdf4; padding:12px; border-radius:8px; border-left:4px solid #059669;">
    <p style="color:#05445E; font-weight:bold;">We want you to always aim higher — your success matters to us.</p>
    </div>
    """, unsafe_allow_html=True)

    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
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
                    selected,
                    [s.strip() for s in strength_inputs if s.strip()],
                    [d.strip() for d in dev_inputs if d.strip()],
                    action_input.strip()
                )
                if success:
                    st.success("✅ IDB Report saved successfully!")
                    add_notification("", "HR", f"MR {user_code} updated their IDB report.")
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
# 🆕 Page: Self Development for MR
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
        try:
            filename = save_certification_file(uploaded_cert, user_code)
            success = save_certification_log(user_code, filename, cert_desc)
            if success:
                add_notification("", "HR", f"MR {user_code} uploaded a new certification.")
                st.success("✅ Certification submitted to HR!")
                st.rerun()
            else:
                st.error("❌ Failed to log certification.")
        except Exception as e:
            st.error(f"❌ Upload failed: {str(e)}")

# ============================
# Page: Ask HR
# ============================
def page_ask_hr(user):
    st.subheader("❓ Ask HR")
    user_name = user.get("Employee Name", "")
    question = st.text_area("Your Question", height=150)
    if st.button("📤 Send to HR"):
        if not question.strip():
            st.error("Question cannot be empty.")
        else:
            add_notification(user_name, "HR", f"[Question] {question}")
            st.success("✅ Your question has been sent to HR!")

# ============================
# Page: Request HR
# ============================
def page_request_hr(user):
    st.subheader("📝 Request HR Action")
    user_name = user.get("Employee Name", "")
    request = st.text_area("Your Request", height=150)
    if st.button("📤 Submit Request"):
        if not request.strip():
            st.error("Request cannot be empty.")
        else:
            add_notification(user_name, "HR", f"[Request] {request}")
            st.success("✅ Your request has been submitted to HR!")

# ============================
# Page: Notifications
# ============================
def page_notifications(user):
    st.subheader("🔔 Notifications")
    notifications = load_json_file(NOTIFICATIONS_FILE_PATH)
    user_title = user.get("Title", "").upper()
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    filtered = notifications[
        (notifications["Recipient"] == user_title) |
        (notifications["Recipient"] == user_code) |
        (notifications["Recipient"] == "All")
    ]
    if filtered.empty:
        st.info("No notifications.")
    else:
        for idx, row in filtered.iterrows():
            st.markdown(f"**{row['Timestamp']}**\n\n{row['Message']}")
            st.markdown("---")

# ============================
# Page: Structure
# ============================
def page_structure(user):
    st.subheader("🏢 Organizational Structure")
    st.info("Structure view is under development.")

# ============================
# Page: Salary Monthly
# ============================
def page_salary_monthly(user):
    st.subheader("💰 Monthly Salary")
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    salaries = load_json_file(SALARIES_FILE_PATH)
    if salaries.empty:
        st.info("No salary data available.")
        return
    salaries["Employee Code"] = salaries["Employee Code"].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
    user_salary = salaries[salaries["Employee Code"] == user_code]
    if user_salary.empty:
        st.info("No salary record found for you.")
    else:
        row = user_salary.iloc[0]
        st.markdown("### Your Salary Breakdown")
        for col in ["Basic Salary", "KPI Bonus", "Deductions", "Net Salary"]:
            if col in row.index:
                val = decrypt_salary_value(row[col])
                st.write(f"**{col}:** {val:,.2f} EGP")

# ============================
# Page: Compliance Reports (for DM/AM/BUM)
# ============================
def page_compliance_reports(user):
    st.subheader("📋 Compliance Reports")
    messages = load_compliance_messages()
    user_title = user.get("Title", "").upper()
    if user_title == "DM":
        filtered = messages[messages["Compliance Recipient"] == "DM"]
    elif user_title == "AM":
        filtered = messages[messages["Compliance Recipient"] == "AM"]
    elif user_title == "BUM":
        filtered = messages[messages["Compliance Recipient"] == "BUM"]
    else:
        filtered = pd.DataFrame()
    if filtered.empty:
        st.info("No compliance reports.")
    else:
        st.dataframe(filtered, use_container_width=True)

# ============================
# Page: Team Requests / Queries (for DM/AM/BUM)
# ============================
def page_team_requests(user):
    st.subheader("📬 Team HR Requests")
    requests = load_json_file(HR_REQUESTS_FILE_PATH)
    st.dataframe(requests, use_container_width=True)

def page_team_queries(user):
    st.subheader("❓ Team HR Queries")
    queries = load_json_file(HR_QUERIES_FILE_PATH)
    st.dataframe(queries, use_container_width=True)

# ============================
# Page: Leave Requests (for DM/AM/BUM)
# ============================
def page_leave_requests(user):
    st.subheader("🌴 Leave Requests")
    leaves = load_leaves_data()
    st.dataframe(leaves, use_container_width=True)

# ============================
# Page: Recruitment (for DM/AM/BUM/HR)
# ============================
def page_recruitment(user):
    st.subheader("👥 Recruitment")
    st.markdown(f"[Apply via Google Form]({GOOGLE_FORM_RECRUITMENT_LINK})")
    if os.path.exists(RECRUITMENT_DATA_FILE):
        rec_data = load_json_file(RECRUITMENT_DATA_FILE)
        st.dataframe(rec_data, use_container_width=True)
    else:
        st.info("No recruitment data yet.")

# ============================
# Page: Manage Employees (for HR)
# ============================
def page_manage_employees(user):
    st.subheader("👥 Manage Employees")
    df = st.session_state.get("df", pd.DataFrame())
    st.dataframe(df, use_container_width=True)
    st.download_button("📥 Download Employees", data=df.to_csv(index=False), file_name="employees.csv")

# ============================
# Page: HR Queries / Requests (for HR)
# ============================
def page_hr_queries(user):
    st.subheader("❓ HR Queries")
    queries = load_json_file(HR_QUERIES_FILE_PATH)
    st.dataframe(queries, use_container_width=True)

def page_hr_requests(user):
    st.subheader("📝 HR Requests")
    requests = load_json_file(HR_REQUESTS_FILE_PATH)
    st.dataframe(requests, use_container_width=True)

# ============================
# Page: Leave Management (for HR)
# ============================
def page_leave_management(user):
    st.subheader("🌴 Leave Management")
    leaves = load_leaves_data()
    st.dataframe(leaves, use_container_width=True)

# ============================
# 🆕 Page: Development (for HR)
# ============================
def page_hr_development(user):
    st.subheader("🎓 Employee Development (HR View)")
    tab_idb, tab_certs = st.tabs(["📋 IDB Reports", "📜 Certifications"])

    with tab_idb:
        idb_df = load_idb_reports()
        if not idb_df.empty:
            idb_df["Selected Departments"] = idb_df["Selected Departments"].apply(
                lambda x: ", ".join(eval(x)) if isinstance(x, str) else ", ".join(x)
            )
            idb_df["Strengths"] = idb_df["Strengths"].apply(
                lambda x: "; ".join(eval(x)) if isinstance(x, str) else "; ".join(x)
            )
            idb_df["Development Areas"] = idb_df["Development Areas"].apply(
                lambda x: "; ".join(eval(x)) if isinstance(x, str) else "; ".join(x)
            )
            st.dataframe(idb_df, use_container_width=True)
            buf = BytesIO()
            with pd.ExcelWriter(buf, engine="openpyxl") as writer:
                idb_df.to_excel(writer, index=False)
            buf.seek(0)
            st.download_button("📥 Download IDB Reports", data=buf, file_name="HR_IDB_Reports.xlsx")
        else:
            st.info("No IDB reports yet.")

    with tab_certs:
        cert_log = load_certifications_log()
        if not cert_log.empty:
            st.dataframe(cert_log, use_container_width=True)
            for idx, row in cert_log.iterrows():
                filepath = os.path.join(CERTIFICATIONS_DIR, row["File"])
                if os.path.exists(filepath):
                    with open(filepath, "rb") as f:
                        st.download_button(f"📥 {row['File']}", f, key=f"dl_cert_{idx}")
        else:
            st.info("No certifications uploaded.")

# ============================
# Main Navigation Logic
# ============================
def main():
    st.set_page_config(page_title="HR System", layout="wide")
    apply_custom_css()
    # Load data into session state once
    if "df" not in st.session_state:
        st.session_state["df"] = load_json_file(FILE_PATH)
    if "leaves_df" not in st.session_state:
        st.session_state["leaves_df"] = load_leaves_data()
    initialize_passwords_from_data(st.session_state["df"].to_dict(orient='records'))
    # Authentication
    if "authenticated" not in st.session_state or not st.session_state["authenticated"]:
        login_page()
        return
    user = st.session_state.get("user", {})
    title = user.get("Title", "").upper()
    is_mr = title == "MR"
    is_dm = title == "DM"
    is_am = title == "AM"
    is_bum = title == "BUM"
    is_hr = title == "HR"
    # Navigation
    if is_mr:
        pages = ["My Profile", "Notify Compliance", "IDB", "Self Development", "Ask HR", "Request HR", "Notifications", "Structure", "Salary Monthly"]
    elif is_dm or is_am or is_bum:
        pages = ["My Profile", "Compliance Reports", "Team Requests", "Team Queries", "Leave Requests", "Recruitment", "Notifications", "Structure", "Salary Monthly"]
    elif is_hr:
        pages = ["My Profile", "Manage Employees", "HR Queries", "HR Requests", "Leave Management", "Recruitment", "Notifications", "Structure", "Salary Monthly", "Development"]
    else:
        pages = ["My Profile", "Notifications", "Structure"]
    current_page = st.sidebar.selectbox("Navigation", pages)
    # Render pages
    if current_page == "My Profile":
        page_my_profile(user)
    elif current_page == "Notify Compliance":
        if is_mr:
            page_notify_compliance(user)
        else:
            st.error("Access denied. MR only.")
    elif current_page == "IDB":
        if is_mr:
            page_idb_mr(user)
        else:
            st.error("Access denied. MR only.")
    elif current_page == "Self Development":
        if is_mr:
            page_self_development(user)
        else:
            st.error("Access denied. MR only.")
    elif current_page == "Ask HR":
        page_ask_hr(user)
    elif current_page == "Request HR":
        page_request_hr(user)
    elif current_page == "Notifications":
        page_notifications(user)
    elif current_page == "Structure":
        page_structure(user)
    elif current_page == "Salary Monthly":
        page_salary_monthly(user)
    elif current_page == "Compliance Reports":
        if is_dm or is_am or is_bum:
            page_compliance_reports(user)
        else:
            st.error("Access denied.")
    elif current_page == "Team Requests":
        if is_dm or is_am or is_bum:
            page_team_requests(user)
        else:
            st.error("Access denied.")
    elif current_page == "Team Queries":
        if is_dm or is_am or is_bum:
            page_team_queries(user)
        else:
            st.error("Access denied.")
    elif current_page == "Leave Requests":
        if is_dm or is_am or is_bum:
            page_leave_requests(user)
        else:
            st.error("Access denied.")
    elif current_page == "Recruitment":
        if is_dm or is_am or is_bum or is_hr:
            page_recruitment(user)
        else:
            st.error("Access denied.")
    elif current_page == "Manage Employees":
        if is_hr:
            page_manage_employees(user)
        else:
            st.error("Access denied. HR only.")
    elif current_page == "HR Queries":
        if is_hr:
            page_hr_queries(user)
        else:
            st.error("Access denied. HR only.")
    elif current_page == "HR Requests":
        if is_hr:
            page_hr_requests(user)
        else:
            st.error("Access denied. HR only.")
    elif current_page == "Leave Management":
        if is_hr:
            page_leave_management(user)
        else:
            st.error("Access denied. HR only.")
    elif current_page == "Development":
        if is_hr:
            page_hr_development(user)
        else:
            st.error("Access denied. HR only.")
    # Footer
    st.markdown("<hr>", unsafe_allow_html=True)
    st.caption("© 2026 HR System | Secure & Confidential")

if __name__ == "__main__":
    main()
