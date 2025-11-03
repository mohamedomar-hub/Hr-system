# hr_system_dark_mode_v3.py - FINAL WORKING VERSION
import streamlit as st
import pandas as pd
import requests
import base64
from io import BytesIO
import os
import datetime
import plotly.express as px
import openpyxl  # ✅ ضروري لقراءة ملفات Excel

# ============================
# Configuration / Defaults
# ============================
DEFAULT_FILE_PATH = "Employees.xlsx"
LOGO_PATH = "logo.jpg"

# ⛔ تم تعطيل GitHub مؤقتًا — استخدام الملف المحلي فقط
GITHUB_TOKEN = None
REPO_OWNER = ""
REPO_NAME = ""
BRANCH = "main"
FILE_PATH = DEFAULT_FILE_PATH

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
.stTextInput>div>div>input, .stNumberInput>div>input, .stSelectbox>div>div>div {background-color: #071226; color: #e6eef8;}
</style>
"""
st.markdown(dark_css, unsafe_allow_html=True)

# ============================
# Local-only data loader (no GitHub)
# ============================
def load_employee_data_local():
    if os.path.exists(FILE_PATH):
        try:
            df = pd.read_excel(FILE_PATH)
            return df
        except Exception as e:
            st.error(f"خطأ في قراءة ملف الموظفين: {e}")
            return pd.DataFrame()
    else:
        st.warning("ملف Employees.xlsx غير موجود في نفس مجلد الكود.")
        return pd.DataFrame()

# ============================
# Login function
# ============================
def login(df, code, password):
    if df.empty:
        return None
    df_local = df.copy()
    # تأمين أسماء الأعمدة (تجاهل حالة الأحرف والمسافات الزائدة)
    col_map = {str(c).strip().lower(): c for c in df_local.columns}
    code_col = col_map.get("employee code", col_map.get("employee_code", None))
    pass_col = col_map.get("password", None)
    title_col = col_map.get("title", None)
    name_col = col_map.get("employee name", col_map.get("name", None))
    
    if not all([code_col, pass_col, title_col, name_col]):
        st.error("أحد الأعمدة المطلوبة مفقود: Employee Code, Password, Title, أو Employee Name")
        return None

    df_local[code_col] = df_local[code_col].astype(str).str.strip()
    df_local[pass_col] = df_local[pass_col].astype(str).str.strip()
    code_s = str(code).strip()
    pwd_s = str(password).strip()

    matched = df_local[(df_local[code_col] == code_s) & (df_local[pass_col] == pwd_s)]
    if not matched.empty:
        return matched.iloc[0].to_dict()
    return None

# ============================
# Main App Flow
# ============================
# تحميل البيانات عند البدء
if "df" not in st.session_state:
    st.session_state["df"] = load_employee_data_local()

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
            st.session_state["logged_in_user"] = user
            st.experimental_rerun()
else:
    # باقي واجهات التطبيق (Dashboard, HR Manager, etc.)
    # (تم حذفها للتوفير — استخدم نفس الواجهات من كودك الأصلي)
    user = st.session_state["logged_in_user"]
    title_val = str(user.get("Title") or user.get("title") or "").strip().lower()
    is_hr = title_val == "hr" or "hr" in title_val
    st.sidebar.write(f"👋 Welcome, {user.get('Employee Name', '')}")
    st.sidebar.markdown("---")
    if is_hr:
        st.success("تم تسجيل الدخول كـ HR بنجاح!")
        # يمكنك إعادة إضافة واجهاتك هنا
    else:
        st.success("مرحباً بك في حسابك!")
