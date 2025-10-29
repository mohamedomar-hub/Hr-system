import streamlit as st
import pandas as pd

# مسار ملف الموظفين الأساسي
EMPLOYEE_FILE = "employees.xlsx"

# دالة لتحميل بيانات الموظفين
@st.cache_data
def load_employee_data(file_path=EMPLOYEE_FILE):
    try:
        df = pd.read_excel(file_path)
        return df
    except FileNotFoundError:
        st.error(f"ملف الموظفين غير موجود: {file_path}")
        return pd.DataFrame()

# تسجيل الدخول — مع دعم كلمات مرور رقمية فقط
def login(df, code, password):
    code_col = 'employee_code'
    pass_col = 'password'
    title_col = 'Title'
    name_col = 'Employee Name'
    
    required_cols = [code_col, pass_col, title_col, name_col]
    missing_cols = [col for col in required_cols if col not in df.columns]
    if missing_cols:
        st.error(f"الأعمدة التالية مفقودة في ملف الموظفين: {missing_cols}")
        return None

    try:
        code = int(code)
        password = int(password)
    except (ValueError, TypeError):
        st.error("الكود الوظيفي وكلمة السر يجب أن يكونا أرقامًا فقط.")
        return None

    user_row = df[(df[code_col] == code) & (df[pass_col] == password)]
    
    if not user_row.empty:
        user_info = user_row.iloc[0].to_dict()
        user_info['title_col'] = title_col
        user_info['employee name'] = user_info[name_col]
        return user_info
    else:
        st.error("الكود الوظيفي أو كلمة السر غير صحيحة.")
        return None

# عرض لوحة HR
def show_hr_dashboard(user, df):
    st.title(f"مرحبا {user.get('employee name', 'غير محدد')} 👋")
    st.subheader("أنت مسؤول النظام (HR)")

    # عرض قائمة موظفين HR فقط
    hr_users = df[df['Title'].str.strip().str.lower() == 'hr']
    if not hr_users.empty:
        st.write("### 📋 موظفو قسم الموارد البشرية (HR):")
        st.dataframe(hr_users[['employee_code', 'Employee Name', 'Title']])

    st.write("### 📥 رفع ملف Excel جديد لتحديث البيانات:")
    uploaded_file = st.file_uploader("اختر ملف Excel", type=["xlsx"])

    if uploaded_file is not None:
        try:
            new_df = pd.read_excel(uploaded_file)
            
            # تنسيق عمود Mobile كرقم 11 رقم
            if 'Mobile' in new_df.columns:
                new_df['Mobile'] = pd.to_numeric(new_df['Mobile'], errors='coerce').fillna(0).astype(int)
                # تحويل الأرقام لنص وضبط الطول
                new_df['Mobile'] = new_df['Mobile'].apply(lambda x: f"{int(x):011d}" if x > 0 else "")
            
            # إزالة الأعمدة المكررة (مثل employee name المكررة)
            cols_to_keep = ['employee_code', 'Employee Name', 'password', 'Title', 'Mobile', 'Hiring Date', 'annual_leave_balance', 'monthly_salary']
            new_df = new_df[[c for c in cols_to_keep if c in new_df.columns]]
            
            # حفظ الملف مؤقتًا (في البيئة)
            new_df.to_excel(EMPLOYEE_FILE, index=False)
            st.success("✅ تم تحديث بيانات الموظفين بنجاح!")
            
            # عرض البيانات بعد التحديث
            st.write("### 📊 البيانات الحالية للموظفين:")
            st.dataframe(new_df)
            
            # زر تنزيل الملف
            st.download_button(
                label="⬇️ نزّل النسخة المحدثة",
                data=new_df.to_excel(index=False, engine='openpyxl'),
                file_name="employees_updated.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )
            
        except Exception as e:
            st.error(f"❌ حدث خطأ أثناء تحديث البيانات: {e}")

# عرض لوحة الموظف العادي
def show_employee_dashboard(user, df):
    st.title(f"مرحبا {user.get('employee name', 'غير محدد')} 👋")
    st.subheader("بياناتك الشخصية:")

    # استثناء الحقول الحساسة أو غير الضرورية
    user_data = {
        k: v for k, v in user.items()
        if k not in ['title_col', 'password', 'Title', 'employee_code']
    }
    
    # إذا كان فيه أعمدة مكررة (مثل employee name مرتين)، احذف المكرر
    if 'employee name' in user_data and 'Employee Name' in user_data:
        user_data.pop('employee name', None)  # نحتفظ بـ Employee Name
    
    st.dataframe(pd.DataFrame([user_data]))

# =======================================
# واجهة Streamlit
# =======================================
st.set_page_config(page_title="HR System", page_icon="👥")

st.title("🔐 نظام شؤون الموظفين - تسجيل الدخول")

# تحميل بيانات الموظفين
df = load_employee_data(EMPLOYEE_FILE)

if df.empty:
    st.warning("لا يمكن تحميل بيانات الموظفين. تأكد من وجود ملف employees.xlsx.")
else:
    # تقسيم الشاشة لـ Tabs
    tab1, tab2 = st.tabs(["👨‍💼 Employees", "🧑‍💼 HR Section"])

    with tab1:
        st.write("تسجيل الدخول كموظف عادي:")
        with st.form("login_employee"):
            code_input = st.text_input("الكود الوظيفي")
            password_input = st.text_input("كلمة السر", type="password")
            submit = st.form_submit_button("تسجيل الدخول")
            
            if submit:
                if not code_input.strip() or not password_input.strip():
                    st.warning("من فضلك أدخل الكود وكلمة السر.")
                else:
                    user = login(df, code_input, password_input)
                    if user:
                        # تأكد أنه موظف عادي (مش HR)
                        title_col = user.get('title_col')
                        user_title = str(user.get(title_col, "")).strip().lower()
                        if user_title != "hr":
                            show_employee_dashboard(user, df)
                        else:
                            st.error("أنت مسؤول النظام (HR). يرجى استخدام قسم HR للدخول.")

    with tab2:
        st.write("تسجيل الدخول كمسؤول نظام (HR):")
        with st.form("login_hr"):
            code_input = st.text_input("الكود الوظيفي (HR)")
            password_input = st.text_input("كلمة السر (HR)", type="password")
            submit = st.form_submit_button("تسجيل الدخول")
            
            if submit:
                if not code_input.strip() or not password_input.strip():
                    st.warning("من فضلك أدخل الكود وكلمة السر.")
                else:
                    user = login(df, code_input, password_input)
                    if user:
                        # تأكد أنه HR
                        title_col = user.get('title_col')
                        user_title = str(user.get(title_col, "")).strip().lower()
                        if user_title == "hr":
                            show_hr_dashboard(user, df)
                        else:
                            st.error("ليس لديك صلاحية الدخول كمسؤول نظام (HR).")
