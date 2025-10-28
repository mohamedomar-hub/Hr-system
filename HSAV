# HR System Streamlit Version
import streamlit as st
import pandas as pd

# ---------------------------
# Load Employee Data
# ---------------------------
@st.cache_data
def load_data():
    try:
        df = pd.read_excel("employees.xlsx")
        df.columns = [c.strip().lower() for c in df.columns]  # normalize column names
        return df
    except FileNotFoundError:
        st.error("ملف employees.xlsx غير موجود في نفس فولدر المشروع.")
        return pd.DataFrame()

df = load_data()

# ---------------------------
# Login Section
# ---------------------------
st.title("نظام شؤون الموظفين")

employee_code = st.text_input("الكود الوظيفي")
password = st.text_input("كلمة السر", type="password")

if st.button("تسجيل الدخول"):
    user = df[(df['employee_code'] == employee_code) & (df['password'] == password)]
    if not user.empty:
        user_info = user.iloc[0]
        st.success(f"مرحباً {user_info['employee name']}")

        # ---------------------------
        # HR Section
        # ---------------------------
        if 'title' in df.columns and user_info['title'].lower() == "hr":
            st.info("أنت مسؤول النظام (HR) - يمكنك إضافة موظفين جدد")
            uploaded_file = st.file_uploader("رفع ملف موظفين جديد", type=["xlsx"])
            if uploaded_file:
                try:
                    new_df = pd.read_excel(uploaded_file)
                    new_df.columns = [c.strip().lower() for c in new_df.columns]
                    df = pd.concat([df, new_df], ignore_index=True)
                    st.success("تم تحديث بيانات الموظفين بنجاح!")
                    st.dataframe(df)  # عرض البيانات المحدثة
                except Exception as e:
                    st.error(f"حدث خطأ أثناء رفع الملف: {e}")

        # ---------------------------
        # Employee Dashboard
        # ---------------------------
        st.subheader("بياناتك الشخصية")
        for field in user_info.index:
            if field not in ['password']:
                st.write(f"**{field}**: {user_info[field]}")

        # ---------------------------
        # Optionally show all employees (for HR)
        # ---------------------------
        if 'title' in df.columns and user_info['title'].lower() == "hr":
            st.subheader("كل بيانات الموظفين")
            st.dataframe(df)

    else:
        st.error("الكود الوظيفي أو كلمة السر غير صحيحة.")
