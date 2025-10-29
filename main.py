# app.py
import streamlit as st
import pandas as pd
import requests
import base64
from io import BytesIO
import time

# ============================
# إعدادات GitHub من Secrets
# ============================
GITHUB_TOKEN = st.secrets.get("GITHUB_TOKEN", "")  # من الأفضل حفظ التوكن في st.secrets
REPO_OWNER = st.secrets.get("REPO_OWNER", "mohamedomar-hub")
REPO_NAME = st.secrets.get("REPO_NAME", "hr-system")
BRANCH = st.secrets.get("BRANCH", "main")
FILE_PATH = st.secrets.get("FILE_PATH", "employees.xlsx") if st.secrets.get("FILE_PATH") else "employees.xlsx"

# ============================
# دوال مساعدة للـ GitHub
# ============================
def github_headers():
    headers = {"Accept": "application/vnd.github.v3+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"
    return headers

def load_employee_data_from_github():
    """
    يجلب ملف employees.xlsx من الريبو ويعيده DataFrame.
    لو فشل يرجع DataFrame فارغ.
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
            # لو الملف مش موجود او خطأ هنعرض رسالة بس ونرجع df فاضي
            st.warning(f"⚠️ لم يتم تحميل الملف من GitHub (status: {resp.status_code}). سيتم استخدام نسخة محلية إذا وجدت.")
            return pd.DataFrame()
    except Exception as e:
        st.error(f"❌ حدث خطأ أثناء تحميل البيانات من GitHub: {e}")
        return pd.DataFrame()

def get_file_sha():
    """
    يجلب SHA الحالي للملف إن وجد (محتاج للتحديث).
    يرجع None لو الملف غير موجود أو خطأ.
    """
    try:
        url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{FILE_PATH}"
        params = {"ref": BRANCH}
        resp = requests.get(url, headers=github_headers(), params=params, timeout=30)
        if resp.status_code == 200:
            return resp.json().get("sha")
        else:
            return None
    except Exception as e:
        st.error(f"❌ خطأ في جلب SHA: {e}")
        return None

def upload_to_github(df, commit_message="تحديث بيانات الموظفين من Streamlit"):
    """
    يرفع DataFrame كملف Excel إلى GitHub (ينشئ الملف أو يعدّله).
    يرجع True لو نجح، False لو فشل.
    """
    if not GITHUB_TOKEN:
        st.info("ℹ️ لم يتم رفع الملف إلى GitHub لأن GitHub token غير موجود في st.secrets.")
        return False

    try:
        # تحويل df إلى محتوى Excel في الذاكرة
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

        if put_resp.status_code in (200, 201):
            return True
        else:
            st.error(f"❌ فشل رفع الملف إلى GitHub. Status: {put_resp.status_code}")
            try:
                st.write(put_resp.json())
            except Exception:
                pass
            return False

    except Exception as e:
        st.exception(f"❌ استثناء أثناء upload_to_github: {e}")
        return False

# ============================
# دوال التطبيق
# ============================
def ensure_session_df():
    """
    يضمن وجود df في session_state، ويحمل من GitHub عند التشغيل أول مرة.
    """
    if "df" not in st.session_state:
        df_loaded = load_employee_data_from_github()
        if df_loaded is None or df_loaded.empty:
            # إن لم يتوفر من GitHub، نبدأ df فارغ
            st.session_state["df"] = pd.DataFrame()
        else:
            st.session_state["df"] = df_loaded

def normalize_mobile_column(new_df):
    """
    تحويل Mobile إلى 11 رقم إن وجد (محاولة آمنة).
    """
    if 'Mobile' in new_df.columns:
        try:
            new_df['Mobile'] = pd.to_numeric(new_df['Mobile'], errors='coerce').fillna(0).astype(int)
            new_df['Mobile'] = new_df['Mobile'].apply(lambda x: f"{int(x):011d}" if x > 0 else "")
        except Exception:
            # لو فشل التحويل، نترك العمود كما هو
            pass
    return new_df

def login(df, code, password):
    """
    دالة تسجيل دخول: أصبحت أكثر مرونة - تقارن كسلاسل بعد التنضيف.
    """
    code_col = 'employee_code'
    pass_col = 'password'
    title_col = 'Title'
    name_col = 'Employee Name'

    missing_cols = [col for col in [code_col, pass_col, title_col, name_col] if col not in df.columns]
    if missing_cols:
        st.error(f"أعمدة مطلوبة مفقودة في شيت الموظفين: {missing_cols}")
        return None

    # تحويل الادخالات لسلاسل ومقارنة بعد التنظيف
    try:
        code_s = str(code).strip()
        pwd_s = str(password).strip()
    except Exception:
        st.error("حدث خطأ في قراءة الكود أو كلمة السر.")
        return None

    # نضمن أن قيم الأعمدة تقارن كسلاسل بعد التفريغ من NaN
    df_local = df.copy()
    df_local[code_col] = df_local[code_col].astype(str).str.strip()
    df_local[pass_col] = df_local[pass_col].astype(str).str.strip()

    matched = df_local[(df_local[code_col] == code_s) & (df_local[pass_col] == pwd_s)]
    if not matched.empty:
        user_info = matched.iloc[0].to_dict()
        user_info['employee name'] = user_info.get(name_col, "")
        return user_info
    else:
        st.error("الكود أو كلمة السر غير صحيحة.")
        return None

def show_employee_dashboard(user):
    st.title(f"مرحبا {user.get('employee name', 'غير محدد')} 👋")
    # عرض بيانات المستخدم الأساسية
    user_display = {k: v for k, v in user.items() if k not in ['password']}
    st.dataframe(pd.DataFrame([user_display]), use_container_width=True)

def show_hr_dashboard(user):
    st.title(f"مرحبا {user.get('employee name', 'غير محدد')} 👋")
    st.subheader("أنت مسؤول النظام (HR)")

    df = st.session_state.get("df", pd.DataFrame())

    # عرض قائمة موظفي HR
    if 'Title' in df.columns:
        hr_users = df[df['Title'].astype(str).str.strip().str.lower() == 'hr']
        if not hr_users.empty:
            st.write("### 📋 موظفو HR:")
            st.dataframe(hr_users[['employee_code', 'Employee Name', 'Title']] if set(['employee_code','Employee Name','Title']).issubset(hr_users.columns) else hr_users, use_container_width=True)

    st.write("### 📥 رفع ملف Excel جديد:")
    uploaded_file = st.file_uploader("اختر ملف (.xlsx) لرفع وتحديث بيانات الموظفين", type=["xlsx"], key="hr_uploader")

    if uploaded_file is not None:
        try:
            new_df = pd.read_excel(uploaded_file)
            new_df = normalize_mobile_column(new_df)

            st.write("🔍 معاينة سريعة للملف الجديد:")
            st.dataframe(new_df.head(20), use_container_width=True)

            # زر تأكيد الرفع والتحديث
            if st.button("✅ تأكيد ورفع الملف وتحديث النظام"):
                with st.spinner("⏳ جاري تحديث البيانات..."):
                    # أولًا نحدث نسخة الجلسة
                    st.session_state["df"] = new_df.copy()

                    # نحاول نرفع على GitHub
                    uploaded = upload_to_github(new_df, commit_message=f"Update employees via Streamlit by {user.get('employee name','HR')}")
                    if uploaded:
                        st.success("✅ تم رفع الملف على GitHub وتحديث النظام بنجاح. الموظفون الجدد يمكنهم الآن تسجيل الدخول.")
                    else:
                        # إذا لم ينجح الرفع على GitHub، نخبر الHR أن التحديث محلي فقط
                        st.warning("⚠️ تم تحديث البيانات داخل التطبيق (محلياً)، لكن فشل رفع الملف على GitHub. يمكنك المحاولة مرة أخرى أو حفظ نسخة يدوياً.")
                    
                    # نعيد تشغيل السكربت بحيث النماذج الأخرى تلتقط df الجديد فوراً
                    time.sleep(0.5)
                    st.experimental_rerun()

            # زر لحفظ الملف محلياً للHR (تحميل)
            output = BytesIO()
            with pd.ExcelWriter(output, engine='openpyxl') as writer:
                new_df.to_excel(writer, index=False)
            st.download_button("⬇️ تنزيل نسخة من الملف الذي رفعته", output.getvalue(), "employees_uploaded.xlsx")

        except Exception as e:
            st.exception(f"❌ حدث خطأ أثناء قراءة الملف المرفوع: {e}")

    st.write("---")
    st.write("خيارات إضافية:")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🔄 إعادة تحميل البيانات من GitHub الآن"):
            with st.spinner("جاري تحميل الملف من GitHub..."):
                df_loaded = load_employee_data_from_github()
                if not df_loaded.empty:
                    st.session_state["df"] = df_loaded
                    st.success("✅ تم إعادة تحميل البيانات من GitHub وتحديث النظام.")
                    st.experimental_rerun()
                else:
                    st.warning("⚠️ لم يتم تحميل بيانات من GitHub. تأكد أن الملف موجود وst.secrets مكوّن بشكل صحيح.")

    with col2:
        if st.button("📁 حفظ نسخة محلية من البيانات الحالية"):
            df_curr = st.session_state.get("df", pd.DataFrame())
            if not df_curr.empty:
                out = BytesIO()
                with pd.ExcelWriter(out, engine='openpyxl') as writer:
                    df_curr.to_excel(writer, index=False)
                st.download_button("⬇️ تحميل employees_current.xlsx", out.getvalue(), "employees_current.xlsx")
            else:
                st.info("لا توجد بيانات حالياً لحفظها.")

# ============================
# واجهة Streamlit الرئيسية
# ============================
st.set_page_config(page_title="HR System", page_icon="👥", layout="wide")
st.title("🔐 نظام شؤون الموظفين")

# ضمان وجود df في الجلسة
ensure_session_df()

# تبويبات الوظائف
tab1, tab2 = st.tabs(["👨‍💼 Employees", "🧑‍💼 HR Section"])

with tab1:
    st.header("تسجيل دخول الموظفين")
    df = st.session_state.get("df", pd.DataFrame())

    with st.form("login_emp"):
        code = st.text_input("الكود الوظيفي", key="emp_code")
        pwd = st.text_input("كلمة السر", type="password", key="emp_pwd")
        if st.form_submit_button("دخول"):
            if df.empty:
                st.error("لا توجد بيانات موظفين حالياً. تواصل مع مسؤول الـHR.")
            else:
                user = login(df, code, pwd)
                if user is not None and str(user.get('Title','')).strip().lower() != 'hr':
                    show_employee_dashboard(user)

with tab2:
    st.header("لوحة HR")
    with st.form("login_hr"):
        code = st.text_input("الكود الوظيفي (HR)", key="hr_code")
        pwd = st.text_input("كلمة السر (HR)", type="password", key="hr_pwd")
        if st.form_submit_button("دخول HR"):
            df = st.session_state.get("df", pd.DataFrame())
            if df.empty:
                # نتحقق من GitHub مرة أخرى قبل الرفض
                df_loaded = load_employee_data_from_github()
                if not df_loaded.empty:
                    st.session_state["df"] = df_loaded
                    df = df_loaded

            if df.empty:
                st.error("لا توجد بيانات موظفين حالياً في النظام أو GitHub.")
            else:
                user = login(df, code, pwd)
                if user is not None and str(user.get('Title','')).strip().lower() == 'hr':
                    show_hr_dashboard(user)
                else:
                    st.error("يجب تسجيل دخول حساب HR لتصل لهذه الصفحة.")

# ==================================
# ملاحظات ختامية للمستخدم (محلية)
# ==================================
st.markdown("---")
st.write("ℹ️ ملاحظات:")
st.write("- عندما يقوم HR برفع ملف جديد ويضغط 'تأكيد ورفع الملف وتحديث النظام'، سيتم تحديث البيانات داخل التطبيق فورًا.")
st.write("- إذا كان `GITHUB_TOKEN` مخزنًا في `st.secrets`، سيحاول التطبيق أيضًا رفع الملف تلقائيًا إلى GitHub.")
st.write("- في حال حدوث أي خطأ أثناء رفع الملف إلى GitHub، سيتم إعلام الـHR وستبقى البيانات محدثة محليًا داخل الجلسة (يمكن حفظها يدويًا بالضغط على زر التحميل).")
