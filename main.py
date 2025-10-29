import streamlit as st
import pandas as pd
import requests
import base64
from io import BytesIO

# إعدادات GitHub من Secrets
GITHUB_TOKEN = st.secrets.get("GITHUB_TOKEN", "")
REPO_OWNER = st.secrets.get("REPO_OWNER", "mohamedomar-hub")
REPO_NAME = st.secrets.get("REPO_NAME", "hr-system")
BRANCH = st.secrets.get("BRANCH", "main")
FILE_PATH = "employees.xlsx"

# دالة لتحميل ملف من GitHub
def load_employee_data_from_github():
    url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{FILE_PATH}?ref={BRANCH}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        content = response.json()
        file_content = base64.b64decode(content['content'])
        df = pd.read_excel(BytesIO(file_content))
        return df
    else:
        st.error(f"❌ فشل تحميل الملف من GitHub. الكود: {response.status_code}")
        return pd.DataFrame()

# دالة لرفع ملف إلى GitHub — مع سجل تفصيلي
def upload_to_github(df, commit_message="تحديث بيانات الموظفين"):
    try:
        st.write("📡 جاري رفع الملف إلى GitHub...")

        # تحويل DataFrame لملف Excel في الذاكرة
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False)
        output.seek(0)
        file_content = base64.b64encode(output.read()).decode('utf-8')
        
        # جلب SHA الحالي للملف (مطلوب للتحديث)
        url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{FILE_PATH}"
        headers = {"Authorization": f"token {GITHUB_TOKEN}"}
        params = {"ref": BRANCH}
        response = requests.get(url, headers=headers, params=params)
        
        sha = None
        if response.status_code == 200:
            sha = response.json().get('sha')
            st.write(f"✅ تم جلب SHA: {sha[:8]}...")
        else:
            st.warning(f"⚠️ الملف غير موجود على GitHub. سيتم إنشاؤه. (Status: {response.status_code})")
        
        # رفع الملف
        data = {
            "message": commit_message,
            "content": file_content,
            "branch": BRANCH
        }
        if sha:
            data["sha"] = sha
        
        put_response = requests.put(url, headers=headers, json=data)
        st.write(f"📡 حالة الرفع: {put_response.status_code}")
        if put_response.status_code not in (200, 201):
            st.write(f"📄 رد GitHub: {put_response.json()}")
        
        return put_response.status_code == 200 or put_response.status_code == 201

    except Exception as e:
        st.exception(f"❌ خطأ في upload_to_github: {e}")
        return False

# تسجيل الدخول
def login(df, code, password):
    code_col = 'employee_code'
    pass_col = 'password'
    title_col = 'Title'
    name_col = 'Employee Name'
    
    required_cols = [code_col, pass_col, title_col, name_col]
    missing_cols = [col for col in required_cols if col not in df.columns]
    if missing_cols:
        st.error(f"الأعمدة التالية مفقودة: {missing_cols}")
        return None

    try:
        code = int(code)
        password = int(password)
    except (ValueError, TypeError):
        st.error("الكود وكلمة السر يجب أن يكونا أرقامًا فقط.")
        return None

    user_row = df[(df[code_col] == code) & (df[pass_col] == password)]
    if not user_row.empty:
        user_info = user_row.iloc[0].to_dict()
        user_info['title_col'] = title_col
        user_info['employee name'] = user_info[name_col]
        return user_info
    else:
        st.error("الكود أو كلمة السر غير صحيحة.")
        return None

# عرض لوحة الموظف
def show_employee_dashboard(user, df):
    st.title(f"مرحبا {user.get('employee name', 'غير محدد')} 👋")
    user_data = {k: v for k, v in user.items() if k not in ['title_col', 'password', 'Title', 'employee_code']}
    # إصلاح: حذف 'employee name' المكرر إذا كان 'Employee Name' موجود
    if 'employee name' in user_data and 'Employee Name' in user_data:
        user_data.pop('employee name', None)
    st.dataframe(pd.DataFrame([user_data]), use_container_width=True)

# عرض لوحة HR
def show_hr_dashboard(user, df):
    st.title(f"مرحبا {user.get('employee name', 'غير محدد')} 👋")
    st.subheader("أنت مسؤول النظام (HR)")

    hr_users = df[df['Title'].str.strip().str.lower() == 'hr']
    if not hr_users.empty:
        st.write("### 📋 موظفو HR:")
        st.dataframe(hr_users[['employee_code', 'Employee Name', 'Title']], use_container_width=True)

    st.write("### 📥 رفع ملف Excel جديد:")
    uploaded_file = st.file_uploader("اختر ملف", type=["xlsx"])

    if uploaded_file is not None:
        try:
            new_df = pd.read_excel(uploaded_file)
            
            # تنسيق Mobile كـ 11 رقم
            if 'Mobile' in new_df.columns:
                new_df['Mobile'] = pd.to_numeric(new_df['Mobile'], errors='coerce').fillna(0).astype(int)
                new_df['Mobile'] = new_df['Mobile'].apply(lambda x: f"{int(x):011d}" if x > 0 else "")
            
            # عرض معلومات الـ Secrets قبل الرفع
            st.write("🔍 **معلومات الـ Secrets:**")
            st.write(f"- Token: {'✅ موجود' if GITHUB_TOKEN else '❌ مش موجود'}")
            st.write(f"- Repo: {REPO_OWNER}/{REPO_NAME}")
            st.write(f"- Branch: {BRANCH}")
            
            # حفظ على GitHub
            if upload_to_github(new_df):
                st.success("✅ تم حفظ الملف على GitHub بنجاح!")
                st.write("### 📊 البيانات الحالية:")
                st.dataframe(new_df, use_container_width=True)
                
                # زر تنزيل
                output = BytesIO()
                with pd.ExcelWriter(output, engine='openpyxl') as writer:
                    new_df.to_excel(writer, index=False)
                st.download_button("⬇️ نزّل النسخة", output.getvalue(), "employees.xlsx")
            else:
                st.error("❌ فشل حفظ الملف على GitHub.")
                
        except Exception as e:
            st.exception(f"❌ خطأ أثناء معالجة الملف: {e}")

# =======================================
# واجهة Streamlit
# =======================================
st.set_page_config(page_title="HR System", page_icon="👥")
st.title("🔐 نظام شؤون الموظفين")

# تحميل البيانات من GitHub
df = load_employee_data_from_github()

if df.empty:
    st.warning("لا توجد بيانات موظفين.")
else:
    tab1, tab2 = st.tabs(["👨‍💼 Employees", "🧑‍💼 HR Section"])

    with tab1:
        with st.form("login_emp"):
            code = st.text_input("الكود الوظيفي")
            pwd = st.text_input("كلمة السر", type="password")
            if st.form_submit_button("دخول"):
                if code and pwd:
                    user = login(df, code, pwd)
                    if user and str(user.get('Title', '')).strip().lower() != 'hr':
                        show_employee_dashboard(user, df)

    with tab2:
        with st.form("login_hr"):
            code = st.text_input("الكود الوظيفي (HR)")
            pwd = st.text_input("كلمة السر (HR)", type="password")
            if st.form_submit_button("دخول"):
                if code and pwd:
                    user = login(df, code, pwd)
                    if user and str(user.get('Title', '')).strip().lower() == 'hr':
                        show_hr_dashboard(user, df)
