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
    pass_col = 'password'  # في الملف، لازم يكون عمود "password" يحتوي على أرقام (أو نصوص أرقام)
    title_col = 'Title'
    name_col = 'Employee Name'
    
    required_cols = [code_col, pass_col, title_col, name_col]
    missing_cols = [col for col in required_cols if col not in df.columns]
    if missing_cols:
        st.error(f"الأعمدة التالية مفقودة في ملف الموظفين: {missing_cols}")
        return None

    # التحقق من أن الكود وكلمة السر أرقام
    try:
        code = int(code)
        password = int(password)  # ← هنا التغيير: كلمة السر لازم تكون رقم
    except (ValueError, TypeError):
        st.error("الكود الوظيفي وكلمة السر يجب أن يكونا أرقامًا فقط.")
        return None

    # البحث عن المستخدم (مقارنة كأرقام)
    user_row = df[(df[code_col] == code) & (df[pass_col] == password)]
    
    if not user_row.empty:
        user_info = user_row.iloc[0].to_dict()
        user_info['title_col'] = title_col
        user_info['employee name'] = user_info[name_col]
        return user_info
    else:
        st.error("الكود الوظيفي أو كلمة السر غير صحيحة.")
        return None

# شاشة لوحة البيانات
def show_dashboard(user, df):
    st.title(f"مرحبا {user.get('employee name', 'غير محدد')} 👋")
    
    title_col = user.get('title_col')
    user_title = user.get(title_col, "") if title_col else ""
    
    if str(user_title).strip().lower() == "hr":
        st.subheader("أنت مسؤول النظام (HR)")
        st.write("يمكنك رفع شيت الموظفين لتحديث البيانات:")
        uploaded_file = st.file_uploader("رفع ملف Excel جديد", type=["xlsx"])
        
        if uploaded_file is not None:
            try:
                new_df = pd.read_excel(uploaded_file)
                new_df.to_excel(EMPLOYEE_FILE, index=False)
                st.success("تم تحديث بيانات الموظفين بنجاح!")
                df = load_employee_data(EMPLOYEE_FILE)
                st.dataframe(df)
            except Exception as e:
                st.error(f"حدث خطأ أثناء تحديث البيانات: {e}")
        else:
            st.write("البيانات الحالية للموظفين:")
            st.dataframe(df)
    else:
        st.subheader("بياناتك الشخصية:")
        user_data = {
            k: v for k, v in user.items()
            if k not in ['title_col', 'password', 'Title', 'employee_code']
        }
        st.dataframe(pd.DataFrame([user_data]))

# =======================================
# واجهة Streamlit
# =======================================
st.set_page_config(page_title="HR System", page_icon="👥")

st.title("نظام شؤون الموظفين - تسجيل الدخول")
st.write("أدخل بياناتك لتسجيل الدخول:")

df = load_employee_data(EMPLOYEE_FILE)

if df.empty:
    st.warning("لا يمكن تحميل بيانات الموظفين. تأكد من وجود ملف employees.xlsx.")
else:
    with st.form("login_form"):
        code_input = st.text_input("الكود الوظيفي")
        password_input = st.text_input("كلمة السر", type="password")
        submit = st.form_submit_button("تسجيل الدخول")
        
        if submit:
            if not code_input.strip() or not password_input.strip():
                st.warning("من فضلك أدخل الكود وكلمة السر.")
            else:
                user = login(df, code_input, password_input)
                if user:
                    show_dashboard(user, df)
