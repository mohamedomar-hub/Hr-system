import streamlit as st
import pandas as pd
from io import BytesIO

# مسار ملف الموظفين الأساسي
EMPLOYEE_FILE = "employees.xlsx"

# دالة لتحميل بيانات الموظفين
@st.cache_data
def load_employee_data(file_path=EMPLOYEE_FILE):
    try:
        df = pd.read_excel(file_path)
        df.columns = [c.strip().lower() for c in df.columns]
        return df
    except FileNotFoundError:
        st.error(f"ملف الموظفين غير موجود: {file_path}")
        return pd.DataFrame()

# تسجيل الدخول
def login(df, code, password):
    code_col = next((c for c in df.columns if 'employee_code' in c), None)
    pass_col = next((c for c in df.columns if 'password' in c), None)
    title_col = next((c for c in df.columns if 'title' in c), None)
    
    if not code_col or not pass_col:
        st.error("لم يتم العثور على أعمدة الكود أو كلمة السر.")
        return None
    
    user = df[(df[code_col] == int(code)) & (df[pass_col] == password)]
    if not user.empty:
        user_info = user.iloc[0].to_dict()
        user_info['title_col'] = title_col
        return user_info
    else:
        st.error("الكود الوظيفي أو كلمة السر غير صحيحة.")
        return None

# شاشة لوحة البيانات
def show_dashboard(user, df):
    st.title(f"مرحبا {user.get('employee name','غير محدد')} 👋")
    
    title_col = user.get('title_col')
    user_title = user.get(title_col, "") if title_col else ""
    
    # صلاحيات HR
    if user_title.lower() == "hr":
        st.subheader("أنت مسؤول النظام (HR)")
        st.write("يمكنك رفع شيت الموظفين لتحديث البيانات:")
        uploaded_file = st.file_uploader("رفع ملف Excel جديد", type=["xlsx"])
        
        if uploaded_file is not None:
            try:
                new_df = pd.read_excel(uploaded_file)
                new_df.to_excel(EMPLOYEE_FILE, index=False)
                st.success("تم تحديث بيانات الموظفين بنجاح!")
                df = load_employee_data(EMPLOYEE_FILE)  # إعادة تحميل البيانات
            except Exception as e:
                st.error(f"حدث خطأ أثناء تحديث البيانات: {e}")
        
        st.write("البيانات الحالية للموظفين:")
        st.dataframe(df)
    else:
        st.subheader("بياناتك الشخصية:")
        user_data = {k: v for k, v in user.items() if k not in ['title_col', 'password']}
        st.dataframe(pd.DataFrame([user_data]))

# =======================================
# واجهة Streamlit
# =======================================
st.set_page_config(page_title="HR System", page_icon="👥")

st.title("نظام شؤون الموظفين - تسجيل الدخول")
st.write("أدخل بياناتك لتسجيل الدخول:")

# تحميل بيانات الموظفين
df = load_employee_data(EMPLOYEE_FILE)

with st.form("login_form"):
    code_input = st.text_input("الكود الوظيفي")
    password_input = st.text_input("كلمة السر", type="password")
    submit = st.form_submit_button("تسجيل الدخول")
    
    if submit:
        if code_input.strip() == "" or password_input.strip() == "":
            st.warning("من فضلك أدخل الكود وكلمة السر.")
        else:
            user = login(df, code_input, password_input)
            if user:
                show_dashboard(user, df)
