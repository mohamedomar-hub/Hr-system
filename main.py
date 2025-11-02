# main.py
import streamlit as st
import pandas as pd
import requests
import base64
from io import BytesIO
import os

# ============================
# إعدادات وأسامي افتراضية
# ============================
# اسم ملف الموظفين المطلوب (حسب طلبك)
DEFAULT_FILE_PATH = "Employees.xlsx"

# نحاول قراءة إعدادات الريبو من st.secrets أولًا، وإلا نستخدم القيم الافتراضية
GITHUB_TOKEN = st.secrets.get("GITHUB_TOKEN", None)
REPO_OWNER = st.secrets.get("REPO_OWNER", "mohamedomar-hub")
REPO_NAME = st.secrets.get("REPO_NAME", "hr-system")
BRANCH = st.secrets.get("BRANCH", "main")
FILE_PATH = st.secrets.get("FILE_PATH", DEFAULT_FILE_PATH) if st.secrets.get("FILE_PATH") else DEFAULT_FILE_PATH

# ============================
# دوال مساعدة لـ GitHub
# ============================
def github_headers():
    headers = {"Accept": "application/vnd.github.v3+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"
    return headers

def load_employee_data_from_github():
    """
    يجلب ملف Employees.xlsx من الريبو ويعيد DataFrame.
    """
    try:
        url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{FILE_PATH}?ref={BRANCH}"
        resp = requests.get(url, headers=github_headers(), timeout=30)
        if resp.status_code == 200:
            content = resp.json()
            file_content = base64.b64decode(content['content'])
            df = pd.read_excel(BytesIO(file_content))
            return df
        else:
            # لو الملف مش موجود أو خطأ، نرجع df فارغ
            return pd.DataFrame()
    except Exception:
        return pd.DataFrame()

def get_file_sha():
    """
    يرجع SHA للملف الموجود على GitHub (مطلوب للتحديث).
    """
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
    """
    يرفع DataFrame كملف Excel إلى GitHub (ينشئ أو يحدث الملف).
    يعيد True لو نجح، False لو فشل أو لم يتوفر توكن.
    """
    if not GITHUB_TOKEN:
        # ليس خطأ جسيم؛ لكن نعلم الـHR أنه لم يتم الرفع لأن التوكن غير مُعد.
        return False

    try:
        # تحويل df إلى Excel في الذاكرة
        output = BytesIO()
        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            df.to_excel(writer, index=False)
        output.seek(0)
        file_content_b64 = base64.b64encode(output.read()).decode("utf-8")

        url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{FILE_PATH}"
        sha = get_file_sha()

        payload = {
            "message": commit_message,
            "content": file_content_b64,
            "branch": BRANCH
        }
        if sha:
            payload["sha"] = sha

        put_resp = requests.put(url, headers=github_headers(), json=payload, timeout=60)

        return put_resp.status_code in (200, 201)
    except Exception:
        return False

# ============================
# دوال التطبيق
# ============================
def ensure_session_df():
    """
    يضمن وجود DataFrame في session_state عند أول تشغيل.
    نحاول حمله من GitHub أولاً، وإذا فشل نستخدم ملف محلي مؤقت إذا وجد.
    """
    if "df" not in st.session_state:
        df_loaded = load_employee_data_from_github()
        if not df_loaded.empty:
            st.session_state["df"] = df_loaded
        else:
            # لو ما فيش على GitHub حاول نقرأ ملف محلي بنفس الاسم (لو موجود)
            if os.path.exists(FILE_PATH):
                try:
                    st.session_state["df"] = pd.read_excel(FILE_PATH)
                except Exception:
                    st.session_state["df"] = pd.DataFrame()
            else:
                st.session_state["df"] = pd.DataFrame()

def normalize_mobile_column(new_df):
    """
    تحويل Mobile إلى 11 رقم إن وجد (محاولة آمنة).
    """
    if 'Mobile' in new_df.columns:
        try:
            new_df['Mobile'] = pd.to_numeric(new_df['Mobile'], errors='coerce').fillna(0).astype(int)
            new_df['Mobile'] = new_df['Mobile'].apply(lambda x: f"{int(x):011d}" if x > 0 else "")
        except Exception:
            pass
    return new_df

def login(df, code, password):
    """
    دالة تسجيل دخول: مقارنة كسلاسل بعد التنظيف.
    تتوقع أعمدة: 'employee_code', 'password', 'Title', 'Employee Name'
    """
    code_col = 'employee_code'
    pass_col = 'password'
    title_col = 'Title'
    name_col = 'Employee Name'

    missing_cols = [col for col in [code_col, pass_col, title_col, name_col] if col not in df.columns]
    if missing_cols:
        st.error(f"أعمدة مطلوبة مفقودة في شيت الموظفين: {missing_cols}")
        return None

    code_s = str(code).strip()
    pwd_s = str(password).strip()

    df_local = df.copy()
    df_local[code_col] = df_local[code_col].astype(str).str.strip()
    df_local[pass_col] = df_local[pass_col].astype(str).str.strip()

    matched = df_local[(df_local[code_col] == code_s) & (df_local[pass_col] == pwd_s)]
    if not matched.empty:
        user_info = matched.iloc[0].to_dict()
        user_info['employee name'] = user_info.get(name_col, "")
        return user_info
    else:
        return None

def show_employee_dashboard(user):
    st.title(f"مرحبا {user.get('employee name', 'غير محدد')} 👋")
    st.write("### بياناتك:")
    user_display = {k: v for k, v in user.items() if k not in ['password']}
    st.dataframe(pd.DataFrame([user_display]), use_container_width=True)

def show_hr_dashboard(user):
    """
    لوحة HR: تحتوي على رفع ملف جديد، تأكيد التحديث، ومحاولات الرفع إلى GitHub.
    هذه الدالة لا تُستدعى داخل الفورم لتجنّب مشاكل Streamlit.
    """
    st.title(f"مرحبا {user.get('employee name', 'HR')} 👋")
    st.subheader("لوحة مسؤول الموارد البشرية")

    df = st.session_state.get("df", pd.DataFrame())

    # عرض موظفي HR إن وجدوا
    if 'Title' in df.columns:
        hr_users = df[df['Title'].astype(str).str.strip().str.lower() == 'hr']
        if not hr_users.empty:
            cols_to_show = [c for c in ['employee_code', 'Employee Name', 'Title'] if c in hr_users.columns]
            st.write("### 📋 موظفو HR:")
            st.dataframe(hr_users[cols_to_show], use_container_width=True)

    st.write("### 📥 رفع ملف Excel جديد (Employees.xlsx):")
    # ملاحظة: هنا لا نضع uploader داخل فورم حتى لا نحصل على استثناءات
    uploaded_file = st.file_uploader("اختر ملف (.xlsx) لرفع وتحديث بيانات الموظفين", type=["xlsx"], key="hr_uploader")

    if uploaded_file is not None:
        try:
            new_df = pd.read_excel(uploaded_file)
            new_df = normalize_mobile_column(new_df)

            st.write("🔍 معاينة سريعة للملف الجديد:")
            st.dataframe(new_df.head(20), use_container_width=True)

            # زر تأكيد الرفع والتحديث (ليس داخل فورم)
            if st.button("✅ تأكيد ورفع الملف وتحديث النظام"):
                # حدّث df في الجلسة أولاً
                st.session_state["df"] = new_df.copy()

                # نحاول رفع الملف على GitHub إن كان التوكن موجود
                uploaded = upload_to_github(new_df, commit_message=f"Update {FILE_PATH} via Streamlit by {user.get('employee name','HR')}")
                if uploaded:
                    st.success("✅ تم رفع الملف على GitHub وتحديث النظام بنجاح. الموظفون الجدد يمكنهم الآن تسجيل الدخول.")
                else:
                    if GITHUB_TOKEN:
                        st.warning("⚠️ فشل رفع الملف إلى GitHub رغم وجود التوكن. البيانات تم تحديثها محلياً داخل التطبيق.")
                    else:
                        st.info("ℹ️ تم تحديث البيانات داخل التطبيق (محلياً). لا يوجد GitHub token في st.secrets لرفع الملف تلقائياً.")
                # إعادة تشغيل ليُظهر التحديث فوراً في بقية التبويبات
                st.experimental_rerun()

            # زر تنزيل نسخة من الملف المرفوع
            out = BytesIO()
            with pd.ExcelWriter(out, engine='openpyxl') as writer:
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
            with pd.ExcelWriter(out2, engine='openpyxl') as writer:
                df_curr.to_excel(writer, index=False)
            st.download_button("⬇️ تنزيل employees_current.xlsx", out2.getvalue(), "employees_current.xlsx")
        else:
            st.info("لا توجد بيانات حالياً للحفظ أو التنزيل.")

# ============================
# واجهة Streamlit الرئيسية
# ============================
st.set_page_config(page_title="HR System", page_icon="👥", layout="wide")
st.title("🔐 نظام شؤون الموظفين")

# ضمان وجود df في الجلسة
ensure_session_df()

# تبويبات
tab1, tab2 = st.tabs(["👨‍💼 Employees", "🧑‍💼 HR Section"])

# ----------------------------
# تبويب الموظفين - تسجيل دخول
# ----------------------------
with tab1:
    st.header("تسجيل دخول الموظفين")
    df = st.session_state.get("df", pd.DataFrame())

    with st.form("login_emp_form"):
        code = st.text_input("الكود الوظيفي", key="emp_code")
        pwd = st.text_input("كلمة السر", type="password", key="emp_pwd")
        submit_emp = st.form_submit_button("دخول")

    if submit_emp:
        if df.empty:
            st.error("لا توجد بيانات موظفين حالياً. تواصل مع مسؤول الـHR.")
        else:
            user = login(df, code, pwd)
            if user is None:
                st.error("الكود أو كلمة السر غير صحيحة.")
            else:
                # نضع حالة تسجيل الدخول في الجلسة ثم نعيد تشغيل الصفحة لعرض لوحة الموظف خارج الفورم
                st.session_state["logged_in_user"] = user
                st.session_state["is_hr_user"] = str(user.get('Title','')).strip().lower() == 'hr'
                st.experimental_rerun()

    # إذا كان المستخدم مسجّل من قبل في الجلسة، نعرض اللوحة مباشرة
    if st.session_state.get("logged_in_user") and not st.session_state.get("is_hr_user", False):
        show_employee_dashboard(st.session_state.get("logged_in_user"))

# ----------------------------
# تبويب HR - تسجيل دخول ثم لوحة
# ----------------------------
with tab2:
    st.header("لوحة HR")
    # أولاً: فورم تسجيل الدخول للـHR
    with st.form("login_hr_form"):
        code_hr = st.text_input("الكود الوظيفي (HR)", key="hr_code")
        pwd_hr = st.text_input("كلمة السر (HR)", type="password", key="hr_pwd")
        submit_hr = st.form_submit_button("دخول HR")

    if submit_hr:
        df = st.session_state.get("df", pd.DataFrame())
        if df.empty:
            # نحاول جلب من GitHub قبل الرفض
            df_loaded = load_employee_data_from_github()
            if not df_loaded.empty:
                st.session_state["df"] = df_loaded
                df = df_loaded

        if df.empty:
            st.error("لا توجد بيانات موظفين في النظام أو GitHub.")
        else:
            user_hr = login(df, code_hr, pwd_hr)
            if user_hr is None:
                st.error("خطأ في بيانات دخول HR.")
            else:
                # حفظ حالة تسجيل HR
                st.session_state["logged_in_user"] = user_hr
                st.session_state["is_hr_user"] = True
                st.experimental_rerun()

    # إن كان HR مسجل بالفعل في الجلسة، نعرض لوحة HR خارج الفورم
    if st.session_state.get("logged_in_user") and st.session_state.get("is_hr_user", False):
        show_hr_dashboard(st.session_state.get("logged_in_user"))

# ----------------------------
# ملاحظات أسفل التطبيق
# ----------------------------
st.markdown("---")
st.write("ℹ️ ملاحظات:")
st.write(f"- الملف المستعمل: **{FILE_PATH}**")
st.write("- عندما يقوم HR برفع ملف جديد ويضغط 'تأكيد ورفع الملف وتحديث النظام'، سيتم تحديث البيانات داخل التطبيق فورًا.")
st.write("- إذا كان `GITHUB_TOKEN` مضبوطًا في `st.secrets`، سيحاول التطبيق رفع الملف تلقائيًا إلى GitHub.")
st.write("- في حالة فشل رفع الملف إلى GitHub، ستبقى البيانات محدثة محليًا في الجلسة ويمكن تحميلها يدوياً.")
