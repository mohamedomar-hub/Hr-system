import streamlit as st
import pandas as pd
import os
from io import BytesIO

# ============================
# إعدادات الصفحة
# ============================
st.set_page_config(page_title="HR System", page_icon="👨‍💼", layout="wide")

# ============================
# دالة تسجيل الدخول
# ============================
def login():
    st.title("🔐 Login Page")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        try:
            df = pd.read_excel("Employees.xlsx")

            user_data = df[(df["employee_code"].astype(str) == username) &
                           (df["password"].astype(str) == password)]

            if not user_data.empty:
                st.session_state["logged_in"] = True
                st.session_state["user_role"] = user_data.iloc[0]["Title"]
                st.session_state["user_name"] = user_data.iloc[0]["Employee Name"]
                st.success("✅ Login successful!")
                st.rerun()
            else:
                st.error("❌ Invalid code or password. Please try again.")
        except FileNotFoundError:
            st.error("⚠️ Employees.xlsx file not found in the project directory.")
        except Exception as e:
            st.error(f"Unexpected error: {e}")

# ============================
# دالة رفع ملف جديد للـ HR
# ============================
def upload_employee_data():
    st.subheader("📤 Upload New Employee Data")

    uploaded_file = st.file_uploader("Upload a new Employees.xlsx file", type=["xlsx"])

    if uploaded_file is not None:
        try:
            # حفظ الملف الجديد بنفس الاسم القديم
            with open("Employees.xlsx", "wb") as f:
                f.write(uploaded_file.getbuffer())

            st.success("✅ Employees.xlsx has been successfully replaced with the new file.")
        except Exception as e:
            st.error(f"❌ Error while saving file: {e}")

# ============================
# الصفحة الرئيسية بعد تسجيل الدخول
# ============================
def main_dashboard():
    st.sidebar.title(f"Welcome, {st.session_state['user_name']} 👋")

    # لو المستخدم HR فقط يظهر له الزر
    if st.session_state["user_role"].strip().lower() == "hr":
        with st.sidebar.expander("HR Actions", expanded=True):
            if st.button("Upload New Employee Data"):
                st.session_state["upload_mode"] = True
                st.rerun()

    # لو اختار رفع ملف
    if st.session_state.get("upload_mode", False):
        upload_employee_data()
        return

    # باقي الصفحة الرئيسية أو الـ Dashboard
    st.title("📊 HR Dashboard")
    st.write("Welcome to the HR system dashboard!")
    st.write("Here you can view analytics, reports, and employee data.")

    try:
        df = pd.read_excel("Employees.xlsx")
        st.dataframe(df.head())
    except FileNotFoundError:
        st.warning("⚠️ Employees.xlsx not found. Please upload a new one.")
    except Exception as e:
        st.error(f"Error loading data: {e}")

# ============================
# منطق التحكم بين الصفحات
# ============================
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False
    st.session_state["upload_mode"] = False

if not st.session_state["logged_in"]:
    login()
else:
    main_dashboard()
