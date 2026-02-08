import streamlit as st
import pandas as pd
import requests
import base64
from io import BytesIO
import os
import datetime
import shutil
import zipfile
import json
import bcrypt
from openpyxl import Workbook
from cryptography.fernet import Fernet, InvalidToken
import hashlib
import mysql.connector
from mysql.connector import Error

# ============================
# 🔴 MYSQL DATABASE CONNECTION SETUP
# ============================
def get_db_connection():
    """Establish connection to MySQL database"""
    try:
        connection = mysql.connector.connect(
            host=st.secrets.get("MYSQL_HOST", "localhost"),
            port=st.secrets.get("MYSQL_PORT", 3306),
            database=st.secrets.get("MYSQL_DATABASE", "hr_system"),
            user=st.secrets.get("MYSQL_USER", "hr_user"),
            password=st.secrets.get("MYSQL_PASSWORD", ""),
            charset='utf8mb4',
            use_unicode=True
        )
        return connection
    except Error as e:
        st.error(f"❌ خطأ في الاتصال بقاعدة البيانات: {e}")
        return None

# ============================
# 🔴 CREATE DATABASE TABLES (Run once)
# ============================
def create_database_tables():
    """Create all required tables in MySQL database"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        
        # جدول الموظفين
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            employee_code VARCHAR(50) PRIMARY KEY,
            employee_name VARCHAR(255) NOT NULL,
            title VARCHAR(100),
            manager_code VARCHAR(50),
            department VARCHAR(100),
            mobile VARCHAR(20),
            email VARCHAR(255),
            address TEXT,
            hire_date DATE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_title (title),
            INDEX idx_manager_code (manager_code)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        """)
        
        # جدول كلمات المرور
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS secure_passwords (
            employee_code VARCHAR(50) PRIMARY KEY,
            password_hash VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (employee_code) REFERENCES employees(employee_code) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        """)
        
        # جدول الإجازات
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS leaves (
            id INT AUTO_INCREMENT PRIMARY KEY,
            employee_code VARCHAR(50) NOT NULL,
            manager_code VARCHAR(50),
            start_date DATE,
            end_date DATE,
            leave_type VARCHAR(50),
            reason TEXT,
            status VARCHAR(20) DEFAULT 'Pending',
            decision_date DATE,
            comment TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_employee_code (employee_code),
            INDEX idx_status (status),
            FOREIGN KEY (employee_code) REFERENCES employees(employee_code) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        """)
        
        # جدول الإشعارات
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INT AUTO_INCREMENT PRIMARY KEY,
            recipient_code VARCHAR(50),
            recipient_title VARCHAR(100),
            message TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_read BOOLEAN DEFAULT FALSE,
            INDEX idx_recipient_code (recipient_code),
            INDEX idx_recipient_title (recipient_title)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        """)
        
        # جدول استفسارات HR
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS hr_queries (
            id INT AUTO_INCREMENT PRIMARY KEY,
            employee_code VARCHAR(50) NOT NULL,
            employee_name VARCHAR(255),
            subject VARCHAR(255),
            message TEXT,
            reply TEXT,
            status VARCHAR(20) DEFAULT 'Pending',
            date_sent TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            date_replied TIMESTAMP NULL,
            INDEX idx_employee_code (employee_code),
            INDEX idx_status (status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        """)
        
        # جدول طلبات HR
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS hr_requests (
            id INT AUTO_INCREMENT PRIMARY KEY,
            hr_code VARCHAR(50),
            employee_code VARCHAR(50) NOT NULL,
            employee_name VARCHAR(255),
            request TEXT,
            file_attached VARCHAR(255),
            status VARCHAR(20) DEFAULT 'Pending',
            response TEXT,
            response_file VARCHAR(255),
            date_sent TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            date_responded TIMESTAMP NULL,
            INDEX idx_employee_code (employee_code),
            INDEX idx_status (status),
            FOREIGN KEY (employee_code) REFERENCES employees(employee_code) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        """)
        
        # جدول الرواتب (مشفر)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS salaries (
            id INT AUTO_INCREMENT PRIMARY KEY,
            employee_code VARCHAR(50) NOT NULL,
            month VARCHAR(20),
            basic_salary VARCHAR(255),
            kpi_bonus VARCHAR(255),
            deductions VARCHAR(255),
            net_salary VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_employee_code (employee_code),
            INDEX idx_month (month),
            FOREIGN KEY (employee_code) REFERENCES employees(employee_code) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        """)
        
        # جدول رسائل الامتثال
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS compliance_messages (
            id INT AUTO_INCREMENT PRIMARY KEY,
            mr_code VARCHAR(50) NOT NULL,
            mr_name VARCHAR(255),
            compliance_recipient VARCHAR(255),
            compliance_code VARCHAR(50),
            manager_code VARCHAR(50),
            manager_name VARCHAR(255),
            message TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status VARCHAR(20) DEFAULT 'Pending',
            INDEX idx_mr_code (mr_code)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        """)
        
        # جدول تقارير IDB
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS idb_reports (
            employee_code VARCHAR(50) PRIMARY KEY,
            employee_name VARCHAR(255),
            selected_departments TEXT,
            strengths TEXT,
            development_areas TEXT,
            action_plan TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (employee_code) REFERENCES employees(employee_code) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        """)
        
        # جدول شهادات التطوير
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS certifications_log (
            id INT AUTO_INCREMENT PRIMARY KEY,
            employee_code VARCHAR(50) NOT NULL,
            file_name VARCHAR(255),
            description TEXT,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_employee_code (employee_code),
            FOREIGN KEY (employee_code) REFERENCES employees(employee_code) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        """)
        
        # جدول بيانات التوظيف
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS recruitment_data (
            id INT AUTO_INCREMENT PRIMARY KEY,
            candidate_name VARCHAR(255),
            email VARCHAR(255),
            phone VARCHAR(50),
            position VARCHAR(100),
            cv_filename VARCHAR(255),
            submission_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status VARCHAR(50) DEFAULT 'Pending',
            INDEX idx_position (position)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        """)
        
        conn.commit()
        cursor.close()
        conn.close()
        return True
        
    except Error as e:
        st.error(f"❌ خطأ في إنشاء الجداول: {e}")
        return False

# ============================
# SALARY ENCRYPTION SETUP
# ============================
SALARY_SECRET_KEY = st.secrets.get("SALARY_SECRET_KEY")
if not SALARY_SECRET_KEY:
    st.error("❌ Missing SALARY_SECRET_KEY in Streamlit Secrets.")
    st.stop()

def get_fernet_from_secret(secret: str) -> Fernet:
    key = hashlib.sha256(secret.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(key)
    return Fernet(fernet_key)

fernet_salary = get_fernet_from_secret(SALARY_SECRET_KEY)

def encrypt_salary_value(value) -> str:
    try:
        if pd.isna(value):
            return ""
        num_str = str(float(value))
        encrypted = fernet_salary.encrypt(num_str.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    except Exception:
        return ""

def decrypt_salary_value(encrypted_str: str) -> float:
    try:
        if not encrypted_str or pd.isna(encrypted_str):
            return 0.0
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_str.encode())
        decrypted = fernet_salary.decrypt(encrypted_bytes)
        return float(decrypted.decode())
    except (InvalidToken, ValueError, Exception):
        return 0.0

# ============================
# 🔴 MYSQL DATA LOADING FUNCTIONS
# ============================
def load_employees_from_mysql():
    """Load employees data from MySQL database"""
    conn = get_db_connection()
    if not conn:
        return pd.DataFrame()
    
    try:
        query = """
        SELECT 
            employee_code AS `Employee Code`,
            employee_name AS `Employee Name`,
            title AS `Title`,
            manager_code AS `Manager Code`,
            department AS `Department`,
            mobile AS `Mobile`,
            email AS `E-Mail`,
            address AS `Address as 702 bricks`,
            hire_date AS `Hire Date`
        FROM employees
        """
        df = pd.read_sql(query, conn)
        conn.close()
        return sanitize_employee_data(df)
        
    except Error as e:
        st.error(f"❌ خطأ في تحميل الموظفين: {e}")
        return pd.DataFrame()

def save_employees_to_mysql(df):
    """Save employees data to MySQL database"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        
        for _, row in df.iterrows():
            sql = """
            INSERT INTO employees 
            (employee_code, employee_name, title, manager_code, department, mobile, email, address, hire_date)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                employee_name = VALUES(employee_name),
                title = VALUES(title),
                manager_code = VALUES(manager_code),
                department = VALUES(department),
                mobile = VALUES(mobile),
                email = VALUES(email),
                address = VALUES(address),
                hire_date = VALUES(hire_date),
                updated_at = CURRENT_TIMESTAMP
            """
            values = (
                str(row.get('Employee Code', '')).strip().replace('.0', ''),
                str(row.get('Employee Name', '')),
                str(row.get('Title', '')),
                str(row.get('Manager Code', '')).strip().replace('.0', '') if pd.notna(row.get('Manager Code')) else None,
                str(row.get('Department', '')),
                str(row.get('Mobile', '')),
                str(row.get('E-Mail', '')),
                str(row.get('Address as 702 bricks', '')),
                row.get('Hire Date') if pd.notna(row.get('Hire Date')) else None
            )
            cursor.execute(sql, values)
        
        conn.commit()
        cursor.close()
        conn.close()
        return True
        
    except Error as e:
        st.error(f"❌ خطأ في حفظ الموظفين: {e}")
        return False

def load_password_hashes_from_mysql():
    """Load password hashes from MySQL"""
    conn = get_db_connection()
    if not conn:
        return {}
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT employee_code, password_hash FROM secure_passwords")
        result = cursor.fetchall()
        cursor.close()
        conn.close()
        
        hashes = {}
        for row in result:
            hashes[row['employee_code']] = row['password_hash']
        return hashes
        
    except Error as e:
        st.error(f"❌ خطأ في تحميل كلمات المرور: {e}")
        return {}

def save_password_hash_to_mysql(employee_code, password_hash):
    """Save single password hash to MySQL"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        sql = """
        INSERT INTO secure_passwords (employee_code, password_hash)
        VALUES (%s, %s)
        ON DUPLICATE KEY UPDATE
            password_hash = VALUES(password_hash),
            updated_at = CURRENT_TIMESTAMP
        """
        cursor.execute(sql, (employee_code, password_hash))
        conn.commit()
        cursor.close()
        conn.close()
        return True
        
    except Error as e:
        st.error(f"❌ خطأ في حفظ كلمة المرور: {e}")
        return False

def initialize_passwords_from_data(data_list):
    """Initialize passwords from employee data"""
    for row in data_list:
        emp_code = str(row.get("Employee Code", "")).strip().replace(".0", "")
        pwd = str(row.get("Password", "")).strip()
        if emp_code and pwd:
            hashed = hash_password(pwd)
            save_password_hash_to_mysql(emp_code, hashed)

def load_leaves_from_mysql():
    """Load leaves data from MySQL"""
    conn = get_db_connection()
    if not conn:
        return pd.DataFrame()
    
    try:
        query = """
        SELECT 
            id AS `ID`,
            employee_code AS `Employee Code`,
            manager_code AS `Manager Code`,
            start_date AS `Start Date`,
            end_date AS `End Date`,
            leave_type AS `Leave Type`,
            reason AS `Reason`,
            status AS `Status`,
            decision_date AS `Decision Date`,
            comment AS `Comment`
        FROM leaves
        ORDER BY created_at DESC
        """
        df = pd.read_sql(query, conn)
        conn.close()
        
        date_cols = ["Start Date", "End Date", "Decision Date"]
        for col in date_cols:
            if col in df.columns:
                df[col] = pd.to_datetime(df[col], errors="coerce")
        
        return df
        
    except Error as e:
        st.error(f"❌ خطأ في تحميل الإجازات: {e}")
        return pd.DataFrame()

def save_leave_to_mysql(leave_data):
    """Save single leave request to MySQL"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        sql = """
        INSERT INTO leaves 
        (employee_code, manager_code, start_date, end_date, leave_type, reason, status, decision_date, comment)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        values = (
            leave_data.get('Employee Code'),
            leave_data.get('Manager Code'),
            leave_data.get('Start Date'),
            leave_data.get('End Date'),
            leave_data.get('Leave Type'),
            leave_data.get('Reason'),
            leave_data.get('Status', 'Pending'),
            leave_data.get('Decision Date'),
            leave_data.get('Comment')
        )
        cursor.execute(sql, values)
        conn.commit()
        cursor.close()
        conn.close()
        return True
        
    except Error as e:
        st.error(f"❌ خطأ في حفظ الإجازة: {e}")
        return False

def update_leave_status_in_mysql(leave_id, status, decision_date, comment=None):
    """Update leave status in MySQL"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        sql = """
        UPDATE leaves 
        SET status = %s, decision_date = %s, comment = %s
        WHERE id = %s
        """
        cursor.execute(sql, (status, decision_date, comment, leave_id))
        conn.commit()
        cursor.close()
        conn.close()
        return True
        
    except Error as e:
        st.error(f"❌ خطأ في تحديث الإجازة: {e}")
        return False

def load_notifications_from_mysql():
    """Load notifications from MySQL"""
    conn = get_db_connection()
    if not conn:
        return pd.DataFrame()
    
    try:
        query = """
        SELECT 
            id AS `ID`,
            recipient_code AS `Recipient Code`,
            recipient_title AS `Recipient Title`,
            message AS `Message`,
            timestamp AS `Timestamp`,
            is_read AS `Is Read`
        FROM notifications
        ORDER BY timestamp DESC
        """
        df = pd.read_sql(query, conn)
        conn.close()
        return df
        
    except Error as e:
        st.error(f"❌ خطأ في تحميل الإشعارات: {e}")
        return pd.DataFrame()

def add_notification_to_mysql(recipient_code, recipient_title, message):
    """Add notification to MySQL"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        sql = """
        INSERT INTO notifications (recipient_code, recipient_title, message)
        VALUES (%s, %s, %s)
        """
        cursor.execute(sql, (recipient_code, recipient_title, message))
        conn.commit()
        cursor.close()
        conn.close()
        return True
        
    except Error as e:
        st.error(f"❌ خطأ في إضافة الإشعار: {e}")
        return False

def mark_notifications_as_read_mysql(user_code, user_title):
    """Mark notifications as read for user"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        sql = """
        UPDATE notifications 
        SET is_read = TRUE
        WHERE (recipient_code = %s OR recipient_title = %s) AND is_read = FALSE
        """
        cursor.execute(sql, (user_code, user_title))
        conn.commit()
        cursor.close()
        conn.close()
        return True
        
    except Error as e:
        st.error(f"❌ خطأ في تحديث الإشعارات: {e}")
        return False

def get_unread_count_mysql(user_code, user_title):
    """Get unread notifications count"""
    conn = get_db_connection()
    if not conn:
        return 0
    
    try:
        cursor = conn.cursor()
        sql = """
        SELECT COUNT(*) FROM notifications 
        WHERE (recipient_code = %s OR recipient_title = %s) AND is_read = FALSE
        """
        cursor.execute(sql, (user_code, user_title))
        count = cursor.fetchone()[0]
        cursor.close()
        conn.close()
        return count
        
    except Error as e:
        st.error(f"❌ خطأ في حساب الإشعارات: {e}")
        return 0

def load_hr_queries_from_mysql():
    """Load HR queries from MySQL"""
    conn = get_db_connection()
    if not conn:
        return pd.DataFrame()
    
    try:
        query = """
        SELECT 
            id AS `ID`,
            employee_code AS `Employee Code`,
            employee_name AS `Employee Name`,
            subject AS `Subject`,
            message AS `Message`,
            reply AS `Reply`,
            status AS `Status`,
            date_sent AS `Date Sent`,
            date_replied AS `Date Replied`
        FROM hr_queries
        ORDER BY date_sent DESC
        """
        df = pd.read_sql(query, conn)
        conn.close()
        return df
        
    except Error as e:
        st.error(f"❌ خطأ في تحميل استفسارات HR: {e}")
        return pd.DataFrame()

def save_hr_query_to_mysql(query_data):
    """Save HR query to MySQL"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        sql = """
        INSERT INTO hr_queries 
        (employee_code, employee_name, subject, message, status, date_sent)
        VALUES (%s, %s, %s, %s, %s, %s)
        """
        values = (
            query_data.get('Employee Code'),
            query_data.get('Employee Name'),
            query_data.get('Subject'),
            query_data.get('Message'),
            query_data.get('Status', 'Pending'),
            query_data.get('Date Sent')
        )
        cursor.execute(sql, values)
        conn.commit()
        cursor.close()
        conn.close()
        return True
        
    except Error as e:
        st.error(f"❌ خطأ في حفظ الاستفسار: {e}")
        return False

def update_hr_query_reply_mysql(query_id, reply, status='Replied'):
    """Update HR query reply in MySQL"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        sql = """
        UPDATE hr_queries 
        SET reply = %s, status = %s, date_replied = CURRENT_TIMESTAMP
        WHERE id = %s
        """
        cursor.execute(sql, (reply, status, query_id))
        conn.commit()
        cursor.close()
        conn.close()
        return True
        
    except Error as e:
        st.error(f"❌ خطأ في تحديث الرد: {e}")
        return False

def load_salaries_from_mysql():
    """Load salaries from MySQL (encrypted)"""
    conn = get_db_connection()
    if not conn:
        return pd.DataFrame()
    
    try:
        query = """
        SELECT 
            employee_code AS `Employee Code`,
            month AS `Month`,
            basic_salary AS `Basic Salary`,
            kpi_bonus AS `KPI Bonus`,
            deductions AS `Deductions`,
            net_salary AS `Net Salary`
        FROM salaries
        ORDER BY month DESC
        """
        df = pd.read_sql(query, conn)
        conn.close()
        return df
        
    except Error as e:
        st.error(f"❌ خطأ في تحميل الرواتب: {e}")
        return pd.DataFrame()

def save_salary_record_to_mysql(salary_data):
    """Save salary record to MySQL (encrypted)"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        sql = """
        INSERT INTO salaries 
        (employee_code, month, basic_salary, kpi_bonus, deductions, net_salary)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            basic_salary = VALUES(basic_salary),
            kpi_bonus = VALUES(kpi_bonus),
            deductions = VALUES(deductions),
            net_salary = VALUES(net_salary),
            updated_at = CURRENT_TIMESTAMP
        """
        values = (
            salary_data.get('Employee Code'),
            salary_data.get('Month'),
            salary_data.get('Basic Salary'),
            salary_data.get('KPI Bonus'),
            salary_data.get('Deductions'),
            salary_data.get('Net Salary')
        )
        cursor.execute(sql, values)
        conn.commit()
        cursor.close()
        conn.close()
        return True
        
    except Error as e:
        st.error(f"❌ خطأ في حفظ الراتب: {e}")
        return False

def load_compliance_messages_from_mysql():
    """Load compliance messages from MySQL"""
    conn = get_db_connection()
    if not conn:
        return pd.DataFrame()
    
    try:
        query = """
        SELECT 
            id AS `ID`,
            mr_code AS `MR Code`,
            mr_name AS `MR Name`,
            compliance_recipient AS `Compliance Recipient`,
            compliance_code AS `Compliance Code`,
            manager_code AS `Manager Code`,
            manager_name AS `Manager Name`,
            message AS `Message`,
            timestamp AS `Timestamp`,
            status AS `Status`
        FROM compliance_messages
        ORDER BY timestamp DESC
        """
        df = pd.read_sql(query, conn)
        conn.close()
        return df
        
    except Error as e:
        st.error(f"❌ خطأ في تحميل رسائل الامتثال: {e}")
        return pd.DataFrame()

def save_compliance_message_to_mysql(message_data):
    """Save compliance message to MySQL"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        sql = """
        INSERT INTO compliance_messages 
        (mr_code, mr_name, compliance_recipient, compliance_code, manager_code, manager_name, message, status)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        values = (
            message_data.get('MR Code'),
            message_data.get('MR Name'),
            message_data.get('Compliance Recipient'),
            message_data.get('Compliance Code'),
            message_data.get('Manager Code'),
            message_data.get('Manager Name'),
            message_data.get('Message'),
            message_data.get('Status', 'Pending')
        )
        cursor.execute(sql, values)
        conn.commit()
        cursor.close()
        conn.close()
        return True
        
    except Error as e:
        st.error(f"❌ خطأ في حفظ رسالة الامتثال: {e}")
        return False

def load_idb_reports_from_mysql():
    """Load IDB reports from MySQL"""
    conn = get_db_connection()
    if not conn:
        return pd.DataFrame()
    
    try:
        query = """
        SELECT 
            employee_code AS `Employee Code`,
            employee_name AS `Employee Name`,
            selected_departments AS `Selected Departments`,
            strengths AS `Strengths`,
            development_areas AS `Development Areas`,
            action_plan AS `Action Plan`,
            updated_at AS `Updated At`
        FROM idb_reports
        """
        df = pd.read_sql(query, conn)
        conn.close()
        return df
        
    except Error as e:
        st.error(f"❌ خطأ في تحميل تقارير IDB: {e}")
        return pd.DataFrame()

def save_idb_report_to_mysql(employee_code, employee_name, selected_deps, strengths, development, action):
    """Save IDB report to MySQL"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        sql = """
        INSERT INTO idb_reports 
        (employee_code, employee_name, selected_departments, strengths, development_areas, action_plan)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            employee_name = VALUES(employee_name),
            selected_departments = VALUES(selected_departments),
            strengths = VALUES(strengths),
            development_areas = VALUES(development_areas),
            action_plan = VALUES(action_plan),
            updated_at = CURRENT_TIMESTAMP
        """
        values = (
            employee_code,
            employee_name,
            str(selected_deps),
            str(strengths),
            str(development),
            action
        )
        cursor.execute(sql, values)
        conn.commit()
        cursor.close()
        conn.close()
        return True
        
    except Error as e:
        st.error(f"❌ خطأ في حفظ تقرير IDB: {e}")
        return False

def load_certifications_from_mysql():
    """Load certifications from MySQL"""
    conn = get_db_connection()
    if not conn:
        return pd.DataFrame()
    
    try:
        query = """
        SELECT 
            employee_code AS `Employee Code`,
            file_name AS `File`,
            description AS `Description`,
            uploaded_at AS `Uploaded At`
        FROM certifications_log
        ORDER BY uploaded_at DESC
        """
        df = pd.read_sql(query, conn)
        conn.close()
        return df
        
    except Error as e:
        st.error(f"❌ خطأ في تحميل الشهادات: {e}")
        return pd.DataFrame()

def save_certification_to_mysql(employee_code, filename, description):
    """Save certification to MySQL"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        sql = """
        INSERT INTO certifications_log (employee_code, file_name, description)
        VALUES (%s, %s, %s)
        """
        cursor.execute(sql, (employee_code, filename, description))
        conn.commit()
        cursor.close()
        conn.close()
        return True
        
    except Error as e:
        st.error(f"❌ خطأ في حفظ الشهادة: {e}")
        return False

def load_recruitment_data_from_mysql():
    """Load recruitment data from MySQL"""
    conn = get_db_connection()
    if not conn:
        return pd.DataFrame()
    
    try:
        query = """
        SELECT 
            id,
            candidate_name AS `Candidate Name`,
            email AS `Email`,
            phone AS `Phone`,
            position AS `Position`,
            cv_filename AS `CV File`,
            submission_date AS `Submission Date`,
            status AS `Status`
        FROM recruitment_data
        ORDER BY submission_date DESC
        """
        df = pd.read_sql(query, conn)
        conn.close()
        return df
        
    except Error as e:
        st.error(f"❌ خطأ في تحميل بيانات التوظيف: {e}")
        return pd.DataFrame()

def save_recruitment_record_to_mysql(candidate_data):
    """Save recruitment record to MySQL"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        sql = """
        INSERT INTO recruitment_data 
        (candidate_name, email, phone, position, cv_filename, status)
        VALUES (%s, %s, %s, %s, %s, %s)
        """
        values = (
            candidate_data.get('Candidate Name'),
            candidate_data.get('Email'),
            candidate_data.get('Phone'),
            candidate_data.get('Position'),
            candidate_data.get('CV File'),
            candidate_data.get('Status', 'Pending')
        )
        cursor.execute(sql, values)
        conn.commit()
        cursor.close()
        conn.close()
        return True
        
    except Error as e:
        st.error(f"❌ خطأ في حفظ بيانات التوظيف: {e}")
        return False

# ============================
# DATA SANITIZATION FUNCTION
# ============================
def sanitize_employee_data(df: pd.DataFrame) -> pd.DataFrame:
    """Apply security rules to employee data"""
    df = df.copy()
    
    # Rule 1 & 2: drop sensitive columns if present
    sensitive_columns_to_drop = ['annual_leave_balance', 'monthly_salary']
    for col in sensitive_columns_to_drop:
        if col in df.columns:
            df = df.drop(columns=[col])
    
    # Rule 3: hide email except for BUM, AM, DM
    if 'E-Mail' in df.columns and 'Title' in df.columns:
        allowed_titles = {'BUM', 'AM', 'DM'}
        mask = ~df['Title'].astype(str).str.upper().isin(allowed_titles)
        df.loc[mask, 'E-Mail'] = ""
    
    return df

# ============================
# Styling - Modern Light Mode CSS
# ============================
st.set_page_config(page_title="HRAS — Averroes Admin", page_icon="👥", layout="wide")
hide_streamlit_style = """
<style>
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
div[data-testid="stDeployButton"] { display: none; }
</style>
"""
st.markdown(hide_streamlit_style, unsafe_allow_html=True)

updated_css = """
<style>
:root {
--primary: #05445E;
--secondary: #0A5C73;
--text-main: #2E2E2E;
--text-muted: #6B7280;
--card-bg: #FFFFFF;
--soft-bg: #F2F6F8;
--border-soft: #E5E7EB;
}
html, body, p, span, label {
color: var(--text-main) !important;
}
h1, h2, h3, h4, h5 {
color: var(--primary) !important;
font-weight: 600;
}
section[data-testid="stSidebar"] h4,
section[data-testid="stSidebar"] h5,
section[data-testid="stSidebar"] p {
color: #FFFFFF !important;
font-weight: 600;
}
label {
color: var(--primary) !important;
font-weight: 500;
}
.card {
background-color: var(--card-bg);
border-radius: 16px;
padding: 18px;
box-shadow: 0 4px 12px rgba(0,0,0,0.06);
border: 1px solid var(--border-soft);
}
.info-text {
color: var(--text-muted) !important;
font-size: 14px;
}
.stButton > button {
background-color: var(--primary) !important;
color: white !important;
border: none !important;
font-weight: 600;
padding: 0.5rem 1rem;
border-radius: 6px;
}
.stButton > button:hover {
background-color: #dc2626 !important;
color: white !important;
}
[data-testid="stAppViewContainer"] {
background-color: #F2F2F2 !important;
}
</style>
"""
st.markdown(updated_css, unsafe_allow_html=True)

# ============================
# Password Functions (bcrypt)
# ============================
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed.encode('utf-8'))

# ============================
# Login Function
# ============================
def login(df, code, password):
    if df is None or df.empty:
        return None
    
    col_map = {c.lower().strip(): c for c in df.columns}
    code_col = col_map.get("employee_code") or col_map.get("employee code")
    if not code_col:
        return None
    
    df_local = df.copy()
    df_local[code_col] = df_local[code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
    code_s = str(code).strip()
    matched = df_local[df_local[code_col] == code_s]
    if matched.empty:
        return None
    
    hashes = load_password_hashes_from_mysql()
    stored_hash = hashes.get(code_s)
    if stored_hash and verify_password(password, stored_hash):
        return matched.iloc[0].to_dict()
    return None

# ============================
# Main App Initialization
# ============================
if 'db_initialized' not in st.session_state:
    if create_database_tables():
        st.session_state.db_initialized = True
    else:
        st.error("❌ فشل في تهيئة قاعدة البيانات. تحقق من اتصال MySQL.")

if "df" not in st.session_state:
    df_loaded = load_employees_from_mysql()
    if not df_loaded.empty:
        st.session_state["df"] = df_loaded
    else:
        st.session_state["df"] = pd.DataFrame()

if not st.session_state.get("passwords_initialized"):
    df_init = st.session_state.get("df", pd.DataFrame())
    if not df_init.empty:
        initialize_passwords_from_data(df_init.to_dict(orient='records'))
        st.session_state["passwords_initialized"] = True

# ============================
# Authentication
# ============================
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
    st.session_state["user"] = None
    st.session_state["user_title"] = None
    st.session_state["user_code"] = None

if not st.session_state["authenticated"]:
    st.title("🔐 HRAS — Login")
    with st.form("login_form"):
        code = st.text_input("Employee Code", placeholder="Enter your employee code")
        password = st.text_input("Password", type="password", placeholder="Enter your password")
        submitted = st.form_submit_button("Login", use_container_width=True)
        
        if submitted:
            user = login(st.session_state["df"], code, password)
            if user:
                st.session_state["authenticated"] = True
                st.session_state["user"] = user
                st.session_state["user_title"] = user.get("Title", "").strip().upper()
                st.session_state["user_code"] = str(user.get("Employee Code", "")).strip()
                st.rerun()
            else:
                st.error("❌ Invalid employee code or password")
    st.stop()

# ============================
# Sidebar Navigation
# ============================
user = st.session_state["user"]
user_title = st.session_state["user_title"]
user_code = st.session_state["user_code"]

with st.sidebar:
    st.markdown(f"### 👤 Welcome, {user.get('Employee Name', 'User')}")
    st.markdown(f"**Code:** {user_code}")
    st.markdown(f"**Title:** {user_title}")
    
    # Unread notifications badge
    unread_count = get_unread_count_mysql(user_code, user_title)
    if unread_count > 0:
        st.markdown(f"🔔 **You have {unread_count} unread notifications**")
    
    st.markdown("---")
    
    # Navigation based on role
    pages = ["🏠 Dashboard", "👤 My Profile", "📅 Leave Requests"]
    
    if user_title in ["HR", "ADMIN"]:
        pages.extend(["👥 Employees Management", "📧 HR Queries", "📤 HR Requests", "💰 Salary Management", "📊 Recruitment"])
    
    if user_title == "MR":
        pages.extend(["📝 IDB & Self Development", "🎓 Certifications", "✉️ Compliance Messages"])
    
    if user_title in ["DM", "AM", "BUM"]:
        pages.append("📋 Compliance Reports")
    
    if user_title in ["ADMIN"]:
        pages.append("⚙️ System Settings")
    
    page = st.selectbox("Navigation", pages, key="nav_page")
    
    if st.button("🚪 Logout", use_container_width=True):
        st.session_state["authenticated"] = False
        st.session_state["user"] = None
        st.rerun()

# ============================
# Page: Dashboard
# ============================
if page == "🏠 Dashboard":
    st.title("🏠 Dashboard")
    
    # Notifications section
    st.subheader("🔔 Notifications")
    notifications = load_notifications_from_mysql()
    user_notifications = notifications[
        (notifications['Recipient Code'] == user_code) | 
        (notifications['Recipient Title'] == user_title)
    ]
    
    if not user_notifications.empty:
        for idx, row in user_notifications.iterrows():
            with st.expander(f"📌 {row['Message'][:50]}...", expanded=not row['Is Read']):
                st.write(f"**Message:** {row['Message']}")
                st.write(f"**Time:** {row['Timestamp']}")
                if not row['Is Read']:
                    if st.button("Mark as Read", key=f"read_{row['ID']}"):
                        mark_notifications_as_read_mysql(user_code, user_title)
                        st.rerun()
    else:
        st.info("📭 No notifications at the moment")
    
    # Quick stats
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Employees", len(st.session_state["df"]))
    with col2:
        leaves_df = load_leaves_from_mysql()
        pending_leaves = len(leaves_df[leaves_df['Status'] == 'Pending']) if not leaves_df.empty else 0
        st.metric("Pending Leaves", pending_leaves)
    with col3:
        st.metric("Your Title", user_title)

# ============================
# Page: My Profile
# ============================
elif page == "👤 My Profile":
    st.title("👤 My Profile")
    
    # Display user info
    col1, col2 = st.columns([2, 1])
    with col1:
        st.subheader(f"{user.get('Employee Name', '')}")
        st.write(f"**Employee Code:** {user_code}")
        st.write(f"**Title:** {user_title}")
        st.write(f"**Department:** {user.get('Department', 'N/A')}")
        st.write(f"**Manager Code:** {user.get('Manager Code', 'N/A')}")
        st.write(f"**Mobile:** {user.get('Mobile', 'N/A')}")
        st.write(f"**Email:** {user.get('E-Mail', 'N/A')}")
        st.write(f"**Address:** {user.get('Address as 702 bricks', 'N/A')}")
        st.write(f"**Hire Date:** {user.get('Hire Date', 'N/A')}")
    
    with col2:
        st.subheader("🔐 Change Password")
        with st.form("change_password"):
            current_pwd = st.text_input("Current Password", type="password")
            new_pwd = st.text_input("New Password", type="password")
            confirm_pwd = st.text_input("Confirm New Password", type="password")
            submit_pwd = st.form_submit_button("Change Password")
            
            if submit_pwd:
                hashes = load_password_hashes_from_mysql()
                stored_hash = hashes.get(user_code)
                if stored_hash and verify_password(current_pwd, stored_hash):
                    if new_pwd == confirm_pwd and len(new_pwd) >= 6:
                        new_hash = hash_password(new_pwd)
                        if save_password_hash_to_mysql(user_code, new_hash):
                            st.success("✅ Password changed successfully!")
                        else:
                            st.error("❌ Failed to save new password")
                    else:
                        st.error("❌ Passwords don't match or too short (min 6 chars)")
                else:
                    st.error("❌ Current password is incorrect")

# ============================
# Page: Leave Requests
# ============================
elif page == "📅 Leave Requests":
    st.title("📅 Leave Requests")
    
    tab1, tab2 = st.tabs(["➕ New Request", "📋 My Requests"])
    
    with tab1:
        st.subheader("Submit New Leave Request")
        with st.form("leave_request"):
            start_date = st.date_input("Start Date")
            end_date = st.date_input("End Date")
            leave_type = st.selectbox("Leave Type", ["Annual", "Sick", "Emergency", "Other"])
            reason = st.text_area("Reason")
            submit = st.form_submit_button("Submit Request")
            
            if submit:
                if end_date < start_date:
                    st.error("❌ End date cannot be before start date")
                else:
                    leave_data = {
                        'Employee Code': user_code,
                        'Employee Name': user.get('Employee Name', ''),
                        'Manager Code': user.get('Manager Code', ''),
                        'Start Date': start_date,
                        'End Date': end_date,
                        'Leave Type': leave_type,
                        'Reason': reason,
                        'Status': 'Pending'
                    }
                    if save_leave_to_mysql(leave_data):
                        # Notify manager
                        manager_code = user.get('Manager Code', '')
                        if manager_code:
                            add_notification_to_mysql(
                                manager_code, 
                                "", 
                                f"New leave request from {user.get('Employee Name', '')} ({user_code})"
                            )
                        st.success("✅ Leave request submitted successfully!")
                        st.rerun()
                    else:
                        st.error("❌ Failed to submit request")
    
    with tab2:
        st.subheader("My Leave Requests")
        leaves_df = load_leaves_from_mysql()
        my_leaves = leaves_df[leaves_df['Employee Code'] == user_code] if not leaves_df.empty else pd.DataFrame()
        
        if not my_leaves.empty:
            st.dataframe(my_leaves[['Start Date', 'End Date', 'Leave Type', 'Status', 'Reason']], use_container_width=True)
        else:
            st.info("📭 You haven't submitted any leave requests yet")

# ============================
# Page: Employees Management (HR/ADMIN only)
# ============================
elif page == "👥 Employees Management" and user_title in ["HR", "ADMIN"]:
    st.title("👥 Employees Management")
    
    tab1, tab2 = st.tabs(["📋 View Employees", "✏️ Edit Employees"])
    
    with tab1:
        st.subheader("All Employees")
        df = st.session_state["df"]
        if not df.empty:
            st.dataframe(df, use_container_width=True)
            
            # Export to Excel
            if st.button("📥 Export to Excel"):
                output = BytesIO()
                with pd.ExcelWriter(output, engine='openpyxl') as writer:
                    df.to_excel(writer, index=False, sheet_name='Employees')
                st.download_button(
                    label="Download Excel file",
                    data=output.getvalue(),
                    file_name=f"employees_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )
    
    with tab2:
        st.subheader("Edit Employee Data")
        df_edit = st.session_state["df"].copy()
        edited_df = st.data_editor(df_edit, num_rows="dynamic", use_container_width=True)
        
        if st.button("💾 Save Changes", type="primary"):
            if save_employees_to_mysql(edited_df):
                st.session_state["df"] = load_employees_from_mysql()
                st.success("✅ Changes saved successfully!")
                st.rerun()
            else:
                st.error("❌ Failed to save changes")

# ============================
# Page: HR Queries
# ============================
elif page == "📧 HR Queries" and user_title in ["HR", "ADMIN"]:
    st.title("📧 HR Queries")
    
    tab1, tab2 = st.tabs(["📥 Received Queries", "📤 Send Query"])
    
    with tab1:
        st.subheader("Employee Queries")
        queries_df = load_hr_queries_from_mysql()
        if not queries_df.empty:
            pending = queries_df[queries_df['Status'] == 'Pending']
            replied = queries_df[queries_df['Status'] != 'Pending']
            
            st.subheader(f"⏳ Pending ({len(pending)})")
            for idx, row in pending.iterrows():
                with st.expander(f"{row['Employee Name']} - {row['Subject']}"):
                    st.write(f"**Message:** {row['Message']}")
                    st.write(f"**Sent:** {row['Date Sent']}")
                    reply = st.text_area("Reply", key=f"reply_{row['ID']}")
                    if st.button("Send Reply", key=f"send_{row['ID']}"):
                        if update_hr_query_reply_mysql(row['ID'], reply):
                            st.success("✅ Reply sent!")
                            st.rerun()
            
            st.subheader(f"✅ Replied ({len(replied)})")
            st.dataframe(replied, use_container_width=True)
        else:
            st.info("📭 No queries received")
    
    with tab2:
        st.subheader("Send Query to HR")
        with st.form("send_query"):
            subject = st.text_input("Subject")
            message = st.text_area("Message")
            submit = st.form_submit_button("Send")
            if submit:
                query_data = {
                    'Employee Code': user_code,
                    'Employee Name': user.get('Employee Name', ''),
                    'Subject': subject,
                    'Message': message,
                    'Status': 'Pending',
                    'Date Sent': datetime.datetime.now()
                }
                if save_hr_query_to_mysql(query_data):
                    st.success("✅ Query sent successfully!")
                    st.rerun()
                else:
                    st.error("❌ Failed to send query")

# ============================
# Page: HR Requests
# ============================
elif page == "📤 HR Requests" and user_title in ["HR", "ADMIN"]:
    st.title("📤 HR Requests")
    
    if user_title == "HR":
        st.subheader("Requests to Employees")
        requests_df = load_hr_requests_from_mysql()
        if not requests_df.empty:
            pending = requests_df[requests_df['Status'] == 'Pending']
            st.dataframe(pending, use_container_width=True)
    else:
        st.subheader("My Requests to HR")
        with st.form("hr_request"):
            request_text = st.text_area("Request Details")
            uploaded_file = st.file_uploader("Attach File (optional)")
            submit = st.form_submit_button("Send Request")
            if submit:
                file_name = uploaded_file.name if uploaded_file else None
                request_data = {
                    'HR Code': 'HR001',  # Default HR code
                    'Employee Code': user_code,
                    'Employee Name': user.get('Employee Name', ''),
                    'Request': request_text,
                    'File Attached': file_name,
                    'Status': 'Pending'
                }
                if save_hr_request_to_mysql(request_data):
                    st.success("✅ Request sent to HR!")
                    st.rerun()
                else:
                    st.error("❌ Failed to send request")

# ============================
# Page: Salary Management (HR/ADMIN only)
# ============================
elif page == "💰 Salary Management" and user_title in ["HR", "ADMIN"]:
    st.title("💰 Salary Management")
    
    tab1, tab2 = st.tabs(["📊 View Salaries", "➕ Add Salary"])
    
    with tab1:
        st.subheader("Employee Salaries")
        salaries_df = load_salaries_from_mysql()
        if not salaries_df.empty:
            # Decrypt salary values for display
            salaries_df['Basic Salary'] = salaries_df['Basic Salary'].apply(lambda x: f"{decrypt_salary_value(x):,.2f} EGP" if x else "N/A")
            salaries_df['KPI Bonus'] = salaries_df['KPI Bonus'].apply(lambda x: f"{decrypt_salary_value(x):,.2f} EGP" if x else "N/A")
            salaries_df['Deductions'] = salaries_df['Deductions'].apply(lambda x: f"{decrypt_salary_value(x):,.2f} EGP" if x else "N/A")
            salaries_df['Net Salary'] = salaries_df['Net Salary'].apply(lambda x: f"{decrypt_salary_value(x):,.2f} EGP" if x else "N/A")
            st.dataframe(salaries_df, use_container_width=True)
        else:
            st.info("📭 No salary records found")
    
    with tab2:
        st.subheader("Add New Salary Record")
        with st.form("add_salary"):
            emp_code = st.text_input("Employee Code")
            month = st.selectbox("Month", ["January", "February", "March", "April", "May", "June", 
                                          "July", "August", "September", "October", "November", "December"])
            basic = st.number_input("Basic Salary (EGP)", min_value=0.0, step=100.0)
            kpi = st.number_input("KPI Bonus (EGP)", min_value=0.0, step=100.0)
            deductions = st.number_input("Deductions (EGP)", min_value=0.0, step=100.0)
            net = basic + kpi - deductions
            
            st.write(f"**Calculated Net Salary:** {net:,.2f} EGP")
            submit = st.form_submit_button("Save Salary")
            
            if submit:
                salary_data = {
                    'Employee Code': emp_code,
                    'Month': month,
                    'Basic Salary': encrypt_salary_value(basic),
                    'KPI Bonus': encrypt_salary_value(kpi),
                    'Deductions': encrypt_salary_value(deductions),
                    'Net Salary': encrypt_salary_value(net)
                }
                if save_salary_record_to_mysql(salary_data):
                    st.success("✅ Salary record saved successfully!")
                    st.rerun()
                else:
                    st.error("❌ Failed to save salary record")

# ============================
# Page: IDB & Self Development (MR only)
# ============================
elif page == "📝 IDB & Self Development" and user_title == "MR":
    st.title("📝 IDB & Self Development")
    
    st.subheader("Individual Development Plan")
    reports_df = load_idb_reports_from_mysql()
    my_report = reports_df[reports_df['Employee Code'] == user_code] if not reports_df.empty else pd.DataFrame()
    
    if not my_report.empty:
        st.info("✅ You already have an IDB report. Edit it below:")
        current = my_report.iloc[0]
        selected_deps = st.multiselect("Target Departments", 
                                      ["Sales", "Marketing", "Operations", "Finance", "HR", "IT"],
                                      default=eval(current['Selected Departments']) if pd.notna(current['Selected Departments']) else [])
        strengths = st.text_area("Strengths", value=current['Strengths'] if pd.notna(current['Strengths']) else "")
        development = st.text_area("Development Areas", value=current['Development Areas'] if pd.notna(current['Development Areas']) else "")
        action = st.text_area("Action Plan", value=current['Action Plan'] if pd.notna(current['Action Plan']) else "")
    else:
        selected_deps = st.multiselect("Target Departments", 
                                      ["Sales", "Marketing", "Operations", "Finance", "HR", "IT"])
        strengths = st.text_area("Strengths")
        development = st.text_area("Development Areas")
        action = st.text_area("Action Plan")
    
    if st.button("💾 Save IDB Report", type="primary"):
        if save_idb_report_to_mysql(user_code, user.get('Employee Name', ''), selected_deps, strengths, development, action):
            st.success("✅ IDB report saved successfully!")
            st.rerun()
        else:
            st.error("❌ Failed to save report")

# ============================
# Page: Certifications (MR only)
# ============================
elif page == "🎓 Certifications" and user_title == "MR":
    st.title("🎓 Certifications & Development")
    
    tab1, tab2 = st.tabs(["📤 Upload Certificate", "📋 My Certificates"])
    
    with tab1:
        st.subheader("Upload New Certificate")
        with st.form("upload_cert"):
            description = st.text_area("Description / Certification Name")
            uploaded_file = st.file_uploader("Certificate File (PDF/Image)")
            submit = st.form_submit_button("Upload")
            
            if submit and uploaded_file:
                # In real app: save file to server and store path in DB
                # For demo: just store filename
                if save_certification_to_mysql(user_code, uploaded_file.name, description):
                    st.success("✅ Certificate uploaded successfully!")
                    st.rerun()
                else:
                    st.error("❌ Failed to upload certificate")
    
    with tab2:
        st.subheader("My Certifications")
        certs_df = load_certifications_from_mysql()
        my_certs = certs_df[certs_df['Employee Code'] == user_code] if not certs_df.empty else pd.DataFrame()
        if not my_certs.empty:
            st.dataframe(my_certs[['File', 'Description', 'Uploaded At']], use_container_width=True)
        else:
            st.info("📭 No certifications uploaded yet")

# ============================
# Page: Compliance Messages (MR only)
# ============================
elif page == "✉️ Compliance Messages" and user_title == "MR":
    st.title("✉️ Compliance Messages")
    
    st.subheader("Send Compliance Message")
    with st.form("compliance_msg"):
        compliance_recipient = st.text_input("Compliance Recipient Name")
        compliance_code = st.text_input("Compliance Employee Code")
        manager_code = st.text_input("Manager Code (DM/AM)")
        manager_name = st.text_input("Manager Name")
        message = st.text_area("Compliance Message")
        submit = st.form_submit_button("Send Message")
        
        if submit:
            msg_data = {
                'MR Code': user_code,
                'MR Name': user.get('Employee Name', ''),
                'Compliance Recipient': compliance_recipient,
                'Compliance Code': compliance_code,
                'Manager Code': manager_code,
                'Manager Name': manager_name,
                'Message': message,
                'Status': 'Pending'
            }
            if save_compliance_message_to_mysql(msg_data):
                st.success("✅ Compliance message sent successfully!")
                # Notify DM/AM
                if manager_code:
                    add_notification_to_mysql(
                        manager_code, 
                        "", 
                        f"New compliance message from MR {user.get('Employee Name', '')}"
                    )
                st.rerun()
            else:
                st.error("❌ Failed to send message")

# ============================
# Page: Compliance Reports (DM/AM/BUM only)
# ============================
elif page == "📋 Compliance Reports" and user_title in ["DM", "AM", "BUM"]:
    st.title("📋 Compliance Reports")
    
    st.subheader("MR Compliance Messages")
    messages_df = load_compliance_messages_from_mysql()
    if not messages_df.empty:
        # Filter by team (simplified: show all for now)
        team_messages = messages_df[messages_df['Manager Code'] == user_code] if user_code else messages_df
        st.dataframe(team_messages[['MR Name', 'Compliance Recipient', 'Message', 'Timestamp', 'Status']], use_container_width=True)
    else:
        st.info("📭 No compliance messages received")

# ============================
# Page: Recruitment (HR/ADMIN only)
# ============================
elif page == "📊 Recruitment" and user_title in ["HR", "ADMIN"]:
    st.title("📊 Recruitment Management")
    
    tab1, tab2 = st.tabs(["📥 Candidates", "➕ Add Candidate"])
    
    with tab1:
        st.subheader("Candidate Pipeline")
        recruitment_df = load_recruitment_data_from_mysql()
        if not recruitment_df.empty:
            st.dataframe(recruitment_df, use_container_width=True)
        else:
            st.info("📭 No candidates in pipeline")
    
    with tab2:
        st.subheader("Add New Candidate")
        with st.form("add_candidate"):
            name = st.text_input("Candidate Name")
            email = st.text_input("Email")
            phone = st.text_input("Phone")
            position = st.text_input("Applied Position")
            cv_file = st.file_uploader("CV File")
            submit = st.form_submit_button("Add Candidate")
            
            if submit:
                cv_filename = cv_file.name if cv_file else None
                candidate_data = {
                    'Candidate Name': name,
                    'Email': email,
                    'Phone': phone,
                    'Position': position,
                    'CV File': cv_filename,
                    'Status': 'Pending'
                }
                if save_recruitment_record_to_mysql(candidate_data):
                    st.success("✅ Candidate added successfully!")
                    st.rerun()
                else:
                    st.error("❌ Failed to add candidate")

# ============================
# Page: System Settings (ADMIN only)
# ============================
elif page == "⚙️ System Settings" and user_title == "ADMIN":
    st.title("⚙️ System Settings")
    
    st.subheader("Database Status")
    conn = get_db_connection()
    if conn:
        st.success("✅ Connected to MySQL database")
        conn.close()
    else:
        st.error("❌ Database connection failed")
    
    st.subheader("Initialize Passwords")
    if st.button("🔄 Re-initialize Passwords from Employee Data"):
        df_init = st.session_state.get("df", pd.DataFrame())
        if not df_init.empty:
            initialize_passwords_from_data(df_init.to_dict(orient='records'))
            st.success("✅ Passwords re-initialized successfully!")
        else:
            st.error("❌ No employee data found")

# ============================
# Footer
# ============================
st.markdown("---")
st.markdown(
    "<div style='text-align: center; color: #6B7280; font-size: 14px;'>"
    "HRAS — Averroes Human Resources Administration System • Powered by MySQL Database"
    "</div>",
    unsafe_allow_html=True
)
