import streamlit as st
import pandas as pd
from io import BytesIO
import os
import datetime

# ============================
# Configuration
# ============================
DEFAULT_FILE_PATH = "Employees.xlsx"

# Page config
st.set_page_config(page_title="HR System", page_icon="👥", layout="wide")

# Dark mode CSS
st.markdown("""
<style>
[data-testid="stAppViewContainer"] {background-color: #0f1724; color: #e6eef8;}
[data-testid="stHeader"], [data-testid="stToolbar"] {background-color: #0b1220;}
.stButton>button {background-color: #0b72b9; color: white; border-radius: 8px;}
[data-testid="stSidebar"] {background-color: #071226;}
.stTextInput>div>div>input, .stNumberInput>div>input, .stSelectbox>div>div>div {
    background-color: #071226; color: #e6eef8;
}
</style>
""", unsafe_allow_html=True)

# ============================
# Helpers
# ============================
def clean_col(name):
    return str(name).replace("\n", " ").replace("\r", " ").strip().lower()

def ensure_df():
    if "df" not in st.session_state:
        if os.path.exists(DEFAULT_FILE_PATH):
            try:
                df = pd.read_excel(DEFAULT_FILE_PATH)
            except:
                df = pd.DataFrame()
        else:
            df = pd.DataFrame()
        st.session_state["df"] = df if not df.empty else pd.DataFrame()

def login(df, code, password):
    if df.empty:
        return None
    col_map = {clean_col(c): c for c in df.columns}
    code_col = col_map.get("employee_code") or col_map.get("employee_code")
    pass_col = col_map.get("password")
    if not code_col or not pass_col:
        return None
    df[code_col] = df[code_col].astype(str).str.strip()
    df[pass_col] = df[pass_col].astype(str).str.strip()
    matched = df[(df[code_col] == str(code).strip()) & (df[pass_col] == str(password).strip())]
    if not matched.empty:
        user = matched.iloc[0].to_dict()
        if "Title" not in user and "title" not in user:
            user["Title"] = "Employee"
        return user
    return None

def save_local(df):
    try:
        with pd.ExcelWriter(DEFAULT_FILE_PATH, engine="openpyxl") as w:
            df.to_excel(w, index=False)
        return True
    except:
        return False

# ============================
# Pages
# ============================
def page_my_profile(user):
    st.subheader("My Profile")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.info("No data available.")
        return
    col_map = {clean_col(c): c for c in df.columns}
    code_col = col_map.get("employee_code") or col_map.get("employee_code")
    if not code_col:
        st.error("Employee code column missing.")
        return
    user_code = str(user.get(code_col) or user.get("employee_code") or "").strip()
    row = df[df[code_col].astype(str) == user_code]
    if row.empty:
        st.error("Your record not found.")
        return
    st.dataframe(row.reset_index(drop=True), use_container_width=True)

def page_dashboard(user):
    st.subheader("HR Dashboard")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.info("No employee data.")
        return

    col_map = {clean_col(c): c for c in df.columns}
    dept_col = col_map.get("department")
    hire_col = None
    for key in ["hiring date", "hire date", "hiring_date", "hire_date"]:
        if key in col_map:
            hire_col = col_map[key]
            break

    total = len(df)
    depts = df[dept_col].nunique() if dept_col else 0
    new_hires = 0
    if hire_col:
        try:
            df[hire_col] = pd.to_datetime(df[hire_col], errors="coerce")
            new_hires = df[df[hire_col] >= (pd.Timestamp.now() - pd.Timedelta(days=30))].shape[0]
        except:
            new_hires = 0

    c1, c2, c3 = st.columns(3)
    c1.metric("Total Employees", total)
    c2.metric("Departments", depts)
    c3.metric("New Hires (30 days)", new_hires)

    st.markdown("---")
    if dept_col:
        counts = df[dept_col].fillna("Unknown").value_counts().reset_index()
        counts.columns = ["Department", "Count"]
        st.table(counts.sort_values("Count", ascending=False).reset_index(drop=True))
    else:
        st.info("Department column not found.")

def page_hr_manager(user):
    st.subheader("HR Manager")

    # ===== Upload New Data Button =====
    with st.expander("📤 Upload New Employee Data", expanded=False):
        uploaded_file = st.file_uploader("Upload new Employees.xlsx file", type=["xlsx"])
        if uploaded_file:
            try:
                new_df = pd.read_excel(uploaded_file)
                st.success("✅ File loaded successfully!")
                st.dataframe(new_df.head(30), use_container_width=True)
                if st.button("Replace Current Data"):
                    st.session_state["df"] = new_df
                    save_local(new_df)
                    st.success("✅ Data replaced successfully and saved locally.")
                    st.rerun()
            except Exception as e:
                st.error(f"❌ Error reading file: {e}")

    # ===== Existing Data =====
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.info("No employee data available.")
        return

    st.markdown("---")
    st.write("Current Employees (first 100 rows):")
    st.dataframe(df.head(100), use_container_width=True)

    # ===== Edit/Delete =====
    col_map = {clean_col(c): c for c in df.columns}
    code_col = col_map.get("employee code") or df.columns[0]
    emp_code = st.text_input("Enter Employee Code to Edit/Delete")

    if emp_code:
        row_match = df[df[code_col].astype(str) == emp_code]
        if row_match.empty:
            st.warning("Employee not found.")
        else:
            row = row_match.iloc[0]
            st.markdown("#### Edit Employee")
            with st.form("edit_form"):
                updates = {}
                for col in df.columns:
                    val = row[col]
                    if pd.isna(val):
                        val = ""
                    if isinstance(val, (int, float)) and not isinstance(val, bool):
                        updates[col] = st.number_input(str(col), value=float(val) if pd.notna(val) else 0.0, key=f"e_{col}")
                    elif "date" in str(col).lower():
                        try:
                            d = pd.to_datetime(val, errors="coerce")
                            updates[col] = st.date_input(str(col), value=d.date() if pd.notna(d) else datetime.date.today(), key=f"d_{col}")
                        except:
                            updates[col] = st.text_input(str(col), value=str(val), key=f"t_{col}")
                    else:
                        updates[col] = st.text_input(str(col), value=str(val), key=f"x_{col}")
                if st.form_submit_button("Save Changes"):
                    for k, v in updates.items():
                        if isinstance(v, datetime.date):
                            v = pd.Timestamp(v)
                        df.loc[df[code_col].astype(str) == emp_code, k] = v
                    st.session_state["df"] = df
                    save_local(df)
                    st.success("✅ Employee updated successfully!")
                    st.rerun()

            st.markdown("#### Delete Employee")
            if st.button("Delete This Employee"):
                st.session_state["df"] = df[df[code_col].astype(str) != emp_code].reset_index(drop=True)
                save_local(st.session_state["df"])
                st.success("🗑️ Employee deleted successfully.")
                st.rerun()

# ============================
# Main App
# ============================
ensure_df()

st.markdown("<h1 style='color:#e6eef8;text-align:center;'>HR System</h1>", unsafe_allow_html=True)

if "logged_in_user" not in st.session_state:
    st.session_state["logged_in_user"] = None

if not st.session_state["logged_in_user"]:
    st.sidebar.subheader("Login")
    with st.sidebar.form("login"):
        code = st.text_input("Employee Code")
        pwd = st.text_input("password (Numbers Only)", type="password")
        if st.form_submit_button("Login"):
            user = login(st.session_state["df"], code, pwd)
            if user:
                st.session_state["logged_in_user"] = user
                st.rerun()
            else:
                st.sidebar.error("Invalid code or password.")
else:
    user = st.session_state["logged_in_user"]
    title = str(user.get("Title", "")).strip().lower()
    is_hr = "hr" in title

    st.sidebar.write(f"👋 Welcome, {user.get('Employee Name', 'User')}")
    st.sidebar.markdown("---")

    if is_hr:
        page = st.sidebar.radio("Navigation", ["Dashboard", "HR Manager", "Logout"])
        if page == "Dashboard":
            page_dashboard(user)
        elif page == "HR Manager":
            page_hr_manager(user)
        elif page == "Logout":
            st.session_state["logged_in_user"] = None
            st.rerun()
    else:
        page = st.sidebar.radio("Navigation", ["My Profile", "Logout"])
        if page == "My Profile":
            page_my_profile(user)
        elif page == "Logout":
            st.session_state["logged_in_user"] = None
            st.rerun()
