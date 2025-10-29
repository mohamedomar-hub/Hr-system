# hr_system_dark_mode.py
import streamlit as st
import pandas as pd
import requests
import base64
from io import BytesIO
import os
import datetime
import plotly.express as px

# ============================
# Configuration / Defaults
# ============================
DEFAULT_FILE_PATH = "Employees.xlsx"
LOGO_PATH = "logo.jpg"  # the logo file (included)
GITHUB_TOKEN = st.secrets.get("GITHUB_TOKEN", None)
REPO_OWNER = st.secrets.get("REPO_OWNER", "mohamedomar-hub")
REPO_NAME = st.secrets.get("REPO_NAME", "hr-system")
BRANCH = st.secrets.get("BRANCH", "main")
FILE_PATH = st.secrets.get("FILE_PATH", DEFAULT_FILE_PATH) if st.secrets.get("FILE_PATH") else DEFAULT_FILE_PATH

# ============================
# Styling - Dark mode CSS
# ============================
st.set_page_config(page_title="HR System (Dark)", page_icon="👥", layout="wide")

dark_css = """
<style>
/* Background and text */
[data-testid="stAppViewContainer"] {
    background-color: #0f1724;
    color: #e6eef8;
}
[data-testid="stHeader"] {background-color: #0b1220;}
[data-testid="stToolbar"] {background-color: #0b1220;}
/* Cards */
.element-container{
    background-color: transparent !important;
}
/* Buttons */
.stButton>button {
    background-color: #0b72b9;
    color: white;
    border-radius: 8px;
    padding: 6px 12px;
}
/* Download button style fix */
.css-1emrehy.egzxvld3 {background-color: #0b72b9 !important;}
/* Sidebar */
[data-testid="stSidebar"] {background-color: #071226;}
</style>
"""
st.markdown(dark_css, unsafe_allow_html=True)

# ============================
# GitHub helpers
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
        file_content_b64 = base64.b64encode(output.read()).decode("utf-8")
        url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{FILE_PATH}"
        sha = get_file_sha()
        payload = {"message": commit_message, "content": file_content_b64, "branch": BRANCH}
        if sha:
            payload["sha"] = sha
        put_resp = requests.put(url, headers=github_headers(), json=payload, timeout=60)
        return put_resp.status_code in (200,201)
    except Exception:
        return False

# ============================
# App helpers and core logic
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

def normalize_mobile_column(new_df):
    if "Mobile" in new_df.columns:
        try:
            new_df["Mobile"] = pd.to_numeric(new_df["Mobile"], errors="coerce").fillna(0).astype(int)
            new_df["Mobile"] = new_df["Mobile"].apply(lambda x: f"{int(x):011d}" if x > 0 else "")
        except Exception:
            pass
    return new_df

def login(df, code, password):
    code_col = "employee_code"
    pass_col = "password"
    title_col = "Title"
    name_col = "Employee Name"

    missing_cols = [col for col in [code_col, pass_col, title_col, name_col] if col not in df.columns]
    if missing_cols:
        return {"error": f"Missing columns: {missing_cols}"}

    code_s = str(code).strip()
    pwd_s = str(password).strip()

    df_local = df.copy()
    df_local[code_col] = df_local[code_col].astype(str).str.strip()
    df_local[pass_col] = df_local[pass_col].astype(str).str.strip()

    matched = df_local[(df_local[code_col] == code_s) & (df_local[pass_col] == pwd_s)]
    if not matched.empty:
        user_info = matched.iloc[0].to_dict()
        user_info["employee name"] = user_info.get(name_col, "")
        return user_info
    else:
        return None

def save_df_to_local(df):
    try:
        with pd.ExcelWriter(FILE_PATH, engine="openpyxl") as writer:
            df.to_excel(writer, index=False)
        return True
    except Exception:
        return False

def save_and_maybe_push(df, actor="HR"):
    # Save locally first
    saved = save_df_to_local(df)
    pushed = False
    if saved and GITHUB_TOKEN:
        pushed = upload_to_github(df, commit_message=f"Update {FILE_PATH} via Streamlit by {actor}")
    return saved, pushed

# ============================
# UI Components: small helpers
# ============================
def render_logo_and_title():
    cols = st.columns([1,6,1])
    with cols[1]:
        if os.path.exists(LOGO_PATH):
            st.image(LOGO_PATH, width=220)
        st.markdown("<h1 style='color:#e6eef8'>HR System — Dark Mode</h1>", unsafe_allow_html=True)

def stats_cards(df):
    total = len(df)
    departments = df["Department"].nunique() if "Department" in df.columns else 0
    # new hires in last 30 days if Hire Date exists
    new_hires = 0
    if "Hire Date" in df.columns:
        try:
            df_dates = df.copy()
            df_dates["Hire Date"] = pd.to_datetime(df_dates["Hire Date"], errors="coerce")
            cutoff = pd.Timestamp.now() - pd.Timedelta(days=30)
            new_hires = df_dates[df_dates["Hire Date"] >= cutoff].shape[0]
        except Exception:
            new_hires = 0
    c1, c2, c3 = st.columns(3)
    c1.metric("👥 إجمالي الموظفين", total)
    c2.metric("🏷️ عدد الأقسام", departments)
    c3.metric("✨ موظفين جدد (30 يوم)", new_hires)

def render_department_charts(df):
    if "Department" not in df.columns or df.empty:
        st.info("لا توجد بيانات كافية للرسوم البيانية بعد.")
        return
    dept_counts = df["Department"].fillna("Unknown").value_counts().reset_index()
    dept_counts.columns = ["Department","Count"]
    fig_pie = px.pie(dept_counts, values="Count", names="Department", title="توزيع الموظفين حسب القسم")
    fig_bar = px.bar(dept_counts, x="Department", y="Count", title="عدد الموظفين في كل قسم")
    st.plotly_chart(fig_pie, use_container_width=True)
    st.plotly_chart(fig_bar, use_container_width=True)

# ============================
# Pages: Dashboard, Edit, Reports, HR uploader preserved
# ============================
def page_dashboard(user):
    st.subheader("لوحة القيادة - Dashboard")
    df = st.session_state.get("df", pd.DataFrame())
    stats_cards(df)
    st.markdown("---")
    st.write("### توزيع الموظفين")
    render_department_charts(df)
    st.markdown("---")
    st.write("### بحث سريع عن موظف")
    if not df.empty:
        names = df["Employee Name"].astype(str).tolist() if "Employee Name" in df.columns else []
        selected = st.selectbox("اختر اسم الموظف للعرض السريع:", options=[""]+names)
        if selected:
            row = df[df["Employee Name"] == selected].iloc[0].to_dict()
            st.json(row)
    else:
        st.info("لا توجد بيانات حالياً.")

def page_edit_employee(user):
    st.subheader("تعديل بيانات موظف")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.info("لا توجد بيانات لتحريرها.")
        return
    # Ensure key columns exist
    key_col = "employee_code"
    if key_col not in df.columns:
        st.error(f"العمود الأساسي {key_col} غير موجود في الشيت.")
        return
    # select employee
    options = df[key_col].astype(str).tolist()
    sel = st.selectbox("اختر الكود الوظيفي للموظف:", options=options)
    if sel:
        emp_row = df[df[key_col].astype(str) == sel].iloc[0].to_dict()
        # editable fields - we'll allow edits for common columns if present
        cols_to_edit = ["Employee Name","Department","Title","Mobile","Hire Date","password"]
        edits = {}
        for col in cols_to_edit:
            if col in df.columns:
                val = emp_row.get(col,"")
                if col == "Hire Date":
                    try:
                        val_dt = pd.to_datetime(val, errors="coerce")
                        new_val = st.date_input(f"{col}", value=val_dt.date() if not pd.isna(val_dt) else None)
                        edits[col] = new_val
                    except Exception:
                        edits[col] = st.text_input(f"{col}", value=str(val))
                else:
                    edits[col] = st.text_input(f"{col}", value=str(val))
        if st.button("💾 حفظ التغييرات"):
            # apply edits to df
            idx = df[df[key_col].astype(str)==sel].index[0]
            for k,v in edits.items():
                if k == "Hire Date":
                    try:
                        df.at[idx,k] = pd.to_datetime(v).date() if v is not None else ""
                    except Exception:
                        df.at[idx,k] = v
                else:
                    df.at[idx,k] = v
            st.session_state["df"] = df
            saved, pushed = save_and_maybe_push(df, actor=user.get("employee name","HR"))
            if saved:
                st.success("✅ تم حفظ التعديلات محلياً.")
            else:
                st.error("❌ فشل حفظ التعديلات محلياً.")
            if pushed:
                st.success("🔁 تم رفع التغييرات إلى GitHub.")
            else:
                if GITHUB_TOKEN:
                    st.warning("⚠️ لم يتم رفع التعديلات إلى GitHub.")
            st.experimental_rerun()

def page_reports(user):
    st.subheader("تصدير التقارير")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.info("لا توجد بيانات لتوليد تقارير.")
        return
    st.write("📄 اختر نوع التقرير الذي تريد توليده:")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("⬇️ تصدير Excel - تقرير الموظفين"):
            out = BytesIO()
            with pd.ExcelWriter(out, engine="openpyxl") as writer:
                df.to_excel(writer, index=False, sheet_name="Employees")
            st.download_button("⬇️ تحميل Excel", out.getvalue(), "employees_report.xlsx")
    with col2:
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.pdfgen import canvas
            if st.button("⬇️ توليد PDF - تقرير الموظفين"):
                pdf_buffer = BytesIO()
                c = canvas.Canvas(pdf_buffer, pagesize=A4)
                width, height = A4
                # add logo if exists
                if os.path.exists(LOGO_PATH):
                    try:
                        from reportlab.lib.utils import ImageReader
                        img = ImageReader(LOGO_PATH)
                        c.drawImage(img, 40, height-120, width=120, preserveAspectRatio=True)
                    except Exception:
                        pass
                c.setFont("Helvetica-Bold", 14)
                c.drawString(40, height-140, "Employees Report")
                c.setFont("Helvetica", 10)
                y = height-170
                for i, row in df.iterrows():
                    if y < 60:
                        c.showPage()
                        y = height-60
                    line = f"{row.get('employee_code','')} - {row.get('Employee Name','')} - {row.get('Department','')} - {row.get('Title','')}"
                    c.drawString(40, y, line[:120])
                    y -= 14
                c.save()
                pdf_buffer.seek(0)
                st.download_button("⬇️ تحميل PDF", pdf_buffer.getvalue(), "employees_report.pdf")
        except Exception:
            st.info("توليد PDF يتطلب تثبيت مكتبة reportlab على البيئة. يمكنك تحميل Excel بدلاً من ذلك.")

# Preserve original HR uploader functionality but cleaner (no repeated notes)
def page_hr_manager(user):
    st.subheader("HR - إدارة الملف")
    df = st.session_state.get("df", pd.DataFrame())
    st.write("### رفع ملف Excel جديد (Employees.xlsx)")
    uploaded_file = st.file_uploader("اختر ملف (.xlsx) لرفع وتحديث بيانات الموظفين", type=["xlsx"], key="hr_uploader2")
    if uploaded_file is not None:
        try:
            new_df = pd.read_excel(uploaded_file)
            new_df = normalize_mobile_column(new_df)
            st.write("🔍 معاينة سريعة للملف الجديد:")
            st.dataframe(new_df.head(20), use_container_width=True)
            if st.button("✅ تأكيد ورفع الملف وتحديث النظام"):
                st.session_state["df"] = new_df.copy()
                saved, pushed = save_and_maybe_push(new_df, actor=user.get("employee name","HR"))
                if saved:
                    st.success("✅ تم حفظ الملف محلياً وتحديث النظام.")
                else:
                    st.error("❌ فشل حفظ الملف محلياً.")
                if pushed:
                    st.success("🔁 تم رفع الملف على GitHub بنجاح.")
                else:
                    if GITHUB_TOKEN:
                        st.warning("⚠️ فشل رفع الملف إلى GitHub.")
                    else:
                        st.info("ℹ️ التحديث تم محلياً لأن GitHub token غير مُعد.")
                st.experimental_rerun()
            out = BytesIO()
            with pd.ExcelWriter(out, engine="openpyxl") as writer:
                new_df.to_excel(writer, index=False)
            st.download_button("⬇️ تنزيل نسخة من الملف الذي رفعته", out.getvalue(), f"{FILE_PATH}")
        except Exception as e:
            st.exception(f"❌ حدث خطأ أثناء قراءة الملف المرفوع: {e}")

    st.write("---")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🔄 إعادة تحميل البيانات من GitHub الآن"):
            df_loaded = load_employee_data_from_github()
            if not df_loaded.empty:
                st.session_state["df"] = df_loaded
                st.success("✅ تم إعادة تحميل البيانات من GitHub وتحديث النظام.")
                st.experimental_rerun()
            else:
                st.warning("⚠️ لم يتم تحميل بيانات من GitHub. تأكد أن الملف موجود وst.secrets مكوّن بشكل صحيح.")
    with col2:
        df_curr = st.session_state.get("df", pd.DataFrame())
        if not df_curr.empty:
            out2 = BytesIO()
            with pd.ExcelWriter(out2, engine="openpyxl") as writer:
                df_curr.to_excel(writer, index=False)
            st.download_button("⬇️ تنزيل employees_current.xlsx", out2.getvalue(), "employees_current.xlsx")
        else:
            st.info("لا توجد بيانات حالياً للحفظ أو التنزيل.")

# ============================
# Main App Flow
# ============================
ensure_session_df()
render_logo_and_title()

# Sidebar navigation & login/session handling
st.sidebar.title("القائمة")
if "logged_in_user" not in st.session_state:
    st.session_state["logged_in_user"] = None
    st.session_state["is_hr_user"] = False

# If not logged in, show login form
if not st.session_state["logged_in_user"]:
    st.sidebar.subheader("تسجيل الدخول")
    with st.sidebar.form("login_form"):
        uid = st.text_input("الكود الوظيفي", key="sid_uid")
        pwd = st.text_input("كلمة السر", type="password", key="sid_pwd")
        submitted = st.form_submit_button("دخول")
    if submitted:
        df = st.session_state.get("df", pd.DataFrame())
        if df.empty:
            st.error("لا توجد بيانات موظفين حالياً. تواصل مع مسؤول الـHR.")
        else:
            user = login(df, uid, pwd)
            if user is None:
                st.error("خطأ في بيانات الدخول.")
            else:
                st.session_state["logged_in_user"] = user
                st.session_state["is_hr_user"] = str(user.get("Title","")).strip().lower() == "hr"
                st.experimental_rerun()
    st.sidebar.markdown("---")
    st.sidebar.write("لا تملك حساب؟ تواصل مع مسؤول الـHR.")
else:
    user = st.session_state["logged_in_user"]
    st.sidebar.write(f"👋 مرحبًا، {user.get('employee name','')}")
    st.sidebar.markdown("---")
    # navigation
    page = st.sidebar.radio("الصفحات", ("Dashboard","Edit Employee","Reports","HR Manager","Logout"))
    if page == "Dashboard":
        page_dashboard(user)
    elif page == "Edit Employee":
        page_edit_employee(user)
    elif page == "Reports":
        page_reports(user)
    elif page == "HR Manager":
        # only HR role allowed
        if st.session_state.get("is_hr_user", False):
            page_hr_manager(user)
        else:
            st.error("هذه الصفحة متاحة فقط لمسؤولي الـHR.")
    elif page == "Logout":
        # clear session
        st.session_state["logged_in_user"] = None
        st.session_state["is_hr_user"] = False
        st.experimental_rerun()

# Footer notes removed (user requested)
