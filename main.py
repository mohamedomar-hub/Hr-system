import streamlit as st
import pandas as pd
import numpy as np
import json
import hashlib
import base64
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
import sqlite3
import bcrypt
import os
import re
import time
from io import BytesIO
import zipfile
import requests
from PIL import Image
import logging
from typing import Dict, List, Any, Optional, Union
import plotly.express as px
import plotly.graph_objects as go
from streamlit_lottie import st_lottie
import altair as alt
from babel.numbers import format_currency
import calendar
import math

# ============================
# CONSTANTS & FILE PATHS
# ============================
EMPLOYEES_FILE_PATH = "employees.json"
LEAVES_FILE_PATH = "leaves.json"
NOTIFICATIONS_FILE_PATH = "notifications.json"
HR_QUERIES_FILE_PATH = "hr_queries.json"
HR_REQUESTS_FILE_PATH = "hr_requests.json"
IDB_REPORTS_FILE = "idb_reports.json"
CERTIFICATES_FILE = "certificates.json"
RECRUITMENT_DATA_FILE = "recruitment_data.json"
SECURE_PASSWORDS_FILE = "secure_passwords.json"
STRUCTURE_SHEET_FILE = "structure_sheet.json"
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
        return fernet_salary.encrypt(str(value).encode()).decode()
    except Exception as e:
        st.error(f"Encryption error: {e}")
        return str(value)

def decrypt_salary_value(value) -> str:
    try:
        return fernet_salary.decrypt(value.encode()).decode()
    except Exception:
        return str(value)

def load_json_file(filepath: str, default_columns: List[str] = None):
    if default_columns is None:
        default_columns = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        df = pd.DataFrame(data)
        for col in default_columns:
            if col not in df.columns:
                df[col] = ""
        return df
    except FileNotFoundError:
        return pd.DataFrame(columns=default_columns)
    except Exception as e:
        st.error(f"Error loading {filepath}: {e}")
        return pd.DataFrame(columns=default_columns)

def save_json_file(df, filepath: str):
    try:
        # Ensure the directory exists
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        # Convert all datetime columns to string
        df_to_save = df.copy()
        for col in df_to_save.columns:
            if pd.api.types.is_datetime64_any_dtype(df_to_save[col]):
                df_to_save[col] = df_to_save[col].astype(str)
        # Convert DataFrame to list of dictionaries
        data = df_to_save.to_dict(orient='records')
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        st.error(f"Error saving {filepath}: {e}")
        return False

def load_employees():
    df = load_json_file(EMPLOYEES_FILE_PATH)
    if not df.empty:
        # Ensure 'Employee Code' is treated as string and stripped
        code_col_map = {c.lower().strip(): c for c in df.columns}
        emp_code_col = code_col_map.get("employee_code") or code_col_map.get("employee code") or code_col_map.get("code")
        if emp_code_col:
            df[emp_code_col] = df[emp_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
    return df

def save_employees(df):
    return save_json_file(df, EMPLOYEES_FILE_PATH)

def load_leaves():
    df = load_json_file(LEAVES_FILE_PATH, default_columns=["Employee Code", "Manager Code", "Start Date", "End Date", "Leave Type", "Reason", "Status", "Decision Date", "Comment"])
    # Convert dates
    if not df.empty:
        df["Start Date"] = pd.to_datetime(df["Start Date"], errors="coerce")
        df["End Date"] = pd.to_datetime(df["End Date"], errors="coerce")
        df["Decision Date"] = pd.to_datetime(df["Decision Date"], errors="coerce")
    return df

def save_leaves(df):
    return save_json_file(df, LEAVES_FILE_PATH)

def load_notifications():
    df = load_json_file(NOTIFICATIONS_FILE_PATH, default_columns=["ID", "Sender", "Recipient Code", "Recipient Title", "Message", "Timestamp", "Is Read"])
    if not df.empty and "ID" in df.columns:
        df["ID"] = pd.to_numeric(df["ID"], errors="coerce", downcast="integer")
    return df

def save_notifications(df):
    return save_json_file(df, NOTIFICATIONS_FILE_PATH)

def add_notification(sender_code: str, recipient_title: str, message: str):
    notifications = load_notifications()
    new_id = int(notifications["ID"].max()) + 1 if not notifications.empty and "ID" in notifications.columns else 1
    new_row = {
        "ID": new_id,
        "Sender": sender_code,
        "Recipient Code": "",
        "Recipient Title": recipient_title,
        "Message": message,
        "Timestamp": datetime.now().isoformat(),
        "Is Read": False
    }
    new_df = pd.DataFrame([new_row])
    notifications = pd.concat([notifications, new_df], ignore_index=True)
    save_notifications(notifications)

def load_hr_queries():
    df = load_json_file(HR_QUERIES_FILE_PATH, default_columns=["ID", "Employee Code", "Employee Name", "Subject", "Message", "Status", "Date Sent", "Reply", "Date Replied"])
    if not df.empty:
        for col in ["Date Sent", "Date Replied"]:
            if col in df.columns:
                df[col] = pd.to_datetime(df[col], errors="coerce").astype(str)
        if "ID" in df.columns:
            df["ID"] = pd.to_numeric(df["ID"], errors="coerce", downcast="integer")
    return df

def save_hr_queries(df):
    df = df.copy()
    for col in ["Date Sent", "Date Replied"]:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors="coerce").astype(str)
    if "ID" in df.columns:
        df["ID"] = pd.to_numeric(df["ID"], errors="coerce")
        if df["ID"].isna().any():
            existing_max = int(df["ID"].max(skipna=True)) if not df["ID"].isna().all() else 0
            for idx in df[df["ID"].isna()].index:
                existing_max += 1
                df.at[idx, "ID"] = existing_max
        df["ID"] = df["ID"].astype(int)
    return save_json_file(df, HR_QUERIES_FILE_PATH)

def load_hr_requests():
    df = load_json_file(HR_REQUESTS_FILE_PATH, default_columns=["ID", "HR Code", "Employee Code", "Employee Name", "Request", "File Attached", "Status", "Response", "Response File", "Date Sent", "Date Responded"])
    if not df.empty:
        for col in ["Date Sent", "Date Responded"]:
            if col in df.columns:
                df[col] = pd.to_datetime(df[col], errors="coerce").astype(str)
        if "ID" in df.columns:
            df["ID"] = pd.to_numeric(df["ID"], errors="coerce", downcast="integer")
    return df

def save_hr_requests(df):
    df = df.copy()
    for col in ["Date Sent", "Date Responded"]:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors="coerce").astype(str)
    if "ID" in df.columns:
        df["ID"] = pd.to_numeric(df["ID"], errors="coerce")
        if df["ID"].isna().any():
            existing_max = int(df["ID"].max(skipna=True)) if not df["ID"].isna().all() else 0
            for idx in df[df["ID"].isna()].index:
                existing_max += 1
                df.at[idx, "ID"] = existing_max
        df["ID"] = df["ID"].astype(int)
    return save_json_file(df, HR_REQUESTS_FILE_PATH)

def load_idb_reports():
    df = load_json_file(IDB_REPORTS_FILE, default_columns=["Employee Code", "Employee Name", "Selected Departments", "Strengths", "Development Areas", "Action Plan", "Updated At"])
    return df

def save_idb_report(employee_code: str, employee_name: str, selected_deps: List[str], strengths: List[str], development: List[str], action_plan: str):
    reports = load_idb_reports()
    now = datetime.now().strftime('%d-%m-%Y %H:%M:%S')
    new_entry = {
        "Employee Code": employee_code,
        "Employee Name": employee_name,
        "Selected Departments": selected_deps,
        "Strengths": strengths,
        "Development Areas": development,
        "Action Plan": action_plan,
        "Updated At": now
    }
    existing_idx = reports[reports["Employee Code"] == employee_code].index
    if len(existing_idx) > 0:
        reports.loc[existing_idx[0], :] = new_entry
    else:
        reports = pd.concat([reports, pd.DataFrame([new_entry])], ignore_index=True)
    return save_json_file(reports, IDB_REPORTS_FILE)

def load_certificates():
    df = load_json_file(CERTIFICATES_FILE, default_columns=["Employee Code", "Employee Name", "Certificate Name", "File", "Upload Date", "Expiration Date", "Status"])
    return df

def save_certificates(df):
    return save_json_file(df, CERTIFICATES_FILE)

def load_recruitment_data():
    df = load_json_file(RECRUITMENT_DATA_FILE)
    return df

def save_recruitment_data(df):
    return save_json_file(df, RECRUITMENT_DATA_FILE)

def load_structure_sheet():
    df = load_json_file(STRUCTURE_SHEET_FILE)
    return df

def save_structure_sheet(df):
    return save_json_file(df, STRUCTURE_SHEET_FILE)

def load_password_hashes():
    if os.path.exists(SECURE_PASSWORDS_FILE):
        with open(SECURE_PASSWORDS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_password_hashes(hashes):
    with open(SECURE_PASSWORDS_FILE, "w", encoding="utf-8") as f:
        json.dump(hashes, f, indent=2)

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed.encode('utf-8'))

def initialize_passwords_from_data(data_list):
    hashes = load_password_hashes()
    for row in data_list:
        emp_code = str(row.get('Employee Code', ''))
        password = str(row.get('Password', ''))
        if emp_code and password and emp_code not in hashes:
            hashes[emp_code] = hash_password(password)
    save_password_hashes(hashes)

# Initialize session state
if "logged_in_user" not in st.session_state:
    st.session_state["logged_in_user"] = None
if "current_page" not in st.session_state:
    st.session_state["current_page"] = "Login"
if "external_password_page" not in st.session_state:
    st.session_state["external_password_page"] = False

def page_login():
    st.subheader("🔐 Login")
    username = st.text_input("Employee Code")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        df = load_employees()
        if df.empty:
            st.error("No employee data found.")
            return
        code_col_map = {c.lower().strip(): c for c in df.columns}
        emp_code_col = code_col_map.get("employee_code") or code_col_map.get("employee code") or code_col_map.get("code")
        if not emp_code_col:
            st.error("Employee Code column not found.")
            return
        df[emp_code_col] = df[emp_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
        user_row = df[df[emp_code_col] == username.strip()]
        if user_row.empty:
            st.error("Employee code not found.")
            return
        user = user_row.iloc[0].to_dict()
        emp_code = str(user.get('Employee Code', ''))
        # Load password hash
        hashes = load_password_hashes()
        if emp_code not in hashes:
            st.error("No password set for this user.")
            return
        stored_hash = hashes[emp_code]
        if verify_password(password, stored_hash):
            st.session_state["logged_in_user"] = user
            st.session_state["current_page"] = "My Profile"
            st.success("Login successful!")
            st.rerun()
        else:
            st.error("Incorrect password.")

def page_forgot_password():
    st.subheader("🔒 Reset Password")
    st.info("Please contact HR to reset your password.")

def mark_all_as_read(user):
    notifications = load_notifications()
    if notifications.empty:
        return
    user_code = None
    user_title = None
    for key, val in user.items():
        if key == "Employee Code":
            user_code = str(val).strip().replace(".0", "")
        if key == "Title":
            user_title = str(val).strip().upper()
    mask = (
        (notifications["Recipient Code"].astype(str) == user_code) |
        (notifications["Recipient Title"].astype(str).str.upper() == user_title)
    )
    notifications.loc[mask, "Is Read"] = True
    save_notifications(notifications)

def format_relative_time(ts):
    if not ts or pd.isna(ts):
        return "N/A"
    try:
        dt = pd.to_datetime(ts)
        now = pd.Timestamp.now()
        diff = now - dt
        seconds = int(diff.total_seconds())
        if seconds < 60:
            return "الآن"
        elif seconds < 3600:
            return f"قبل {seconds // 60} دقيقة"
        elif seconds < 86400:
            return f"قبل {seconds // 3600} ساعة"
        else:
            return dt.strftime("%d-%m-%Y")
    except Exception:
        return str(ts)

def page_notifications(user):
    st.subheader("🔔 Notifications")
    notifications = load_notifications()
    if notifications.empty:
        st.info("No notifications.")
        return
    user_code = None
    user_title = None
    for key, val in user.items():
        if key == "Employee Code":
            user_code = str(val).strip().replace(".0", "")
        if key == "Title":
            user_title = str(val).strip().upper()
    mask = (
        (notifications["Recipient Code"].astype(str) == user_code) |
        (notifications["Recipient Title"].astype(str).str.upper() == user_title)
    )
    user_notifs = notifications[mask].copy()
    user_notifs = user_notifs.sort_values(by="Timestamp", ascending=False).reset_index(drop=True)
    filter_option = st.radio("Filter", ("All", "Unread", "Read"), horizontal=True)
    if filter_option == "Unread":
        filtered_notifs = user_notifs[user_notifs["Is Read"] == False]
    elif filter_option == "Read":
        filtered_notifs = user_notifs[user_notifs["Is Read"]]
    else:
        filtered_notifs = user_notifs.copy()
    if not user_notifs[user_notifs["Is Read"] == False].empty:
        col1, col2 = st.columns([4, 1])
        with col2:
            if st.button("✅ Mark all as read", key="mark_all_read_btn"):
                mark_all_as_read(user)
                st.success("All notifications marked as read.")
                st.rerun()
    if filtered_notifs.empty:
        st.info(f"No {filter_option.lower()} notifications.")
        return
    for idx, row in filtered_notifs.iterrows():
        if "approved" in str(row["Message"]).lower():
            icon = "✅"
            color = "#059669"
            bg_color = "#f0fdf4"
        elif "rejected" in str(row["Message"]).lower():
            icon = "❌"
            color = "#dc2626"
            bg_color = "#fef2f2"
        else:
            icon = "📝"
            color = "#05445E"
            bg_color = "#f8fafc"
        status_badge = "✅" if row["Is Read"] else "🆕"
        time_formatted = format_relative_time(row["Timestamp"])
        st.markdown(
            f"""
            <div style="
                background-color: {bg_color};
                border-left: 4px solid {color};
                padding: 12px;
                margin: 10px 0;
                border-radius: 8px;
                box-shadow: 0 2px 6px rgba(0,0,0,0.05);
            ">
                <div style="
                    display: flex;
                    justify-content: space-between;
                    align-items: flex-start;
                ">
                    <div style="
                        display: flex;
                        align-items: center;
                        gap: 10px;
                        flex: 1;
                    ">
                        <span style="font-size: 1.2em; color: {color};">{icon}</span>
                        <span style="color: {color}; font-weight: bold;">{status_badge}</span>
                    </div>
                    <span style="font-size: 0.8em; color: #6B7280;">{time_formatted}</span>
                </div>
                <div style="margin-top: 8px;">
                    <p style="margin: 0; color: var(--text-main);">{row["Message"]}</p>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

def page_my_profile(user):
    st.subheader("👤 My Profile")
    if not user:
        st.error("No user logged in.")
        return
    st.write("**Employee Information:**")
    profile_data = {}
    for key, value in user.items():
        clean_key = key.replace('_', ' ').title()
        profile_data[clean_key] = value
    profile_df = pd.DataFrame(list(profile_data.items()), columns=["Field", "Value"])
    st.dataframe(profile_df, use_container_width=True)

def page_team_structure(user):
    st.subheader("🏗️ Team Structure")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.error("No employee data available.")
        return
    code_col_map = {c.lower().strip(): c for c in df.columns}
    emp_code_col = code_col_map.get("employee_code") or code_col_map.get("employee code") or code_col_map.get("code")
    emp_name_col = code_col_map.get("employee_name") or code_col_map.get("employee name") or code_col_map.get("name")
    title_col = code_col_map.get("title") or code_col_map.get("job title") or code_col_map.get("position")
    mgr_code_col = code_col_map.get("manager_code") or code_col_map.get("manager code") or code_col_map.get("reporting_to")
    if not all([emp_code_col, emp_name_col, title_col, mgr_code_col]):
        st.error("Required columns (Employee Code, Employee Name, Title, Manager Code) not found.")
        return
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    user_title = str(user.get("Title", "")).strip().upper()
    if user_title not in ["BUM", "AM", "DM"]:
        st.error("Access denied. Only BUM, AM, DM can view team structure.")
        return
    def build_team_hierarchy_recursive(df, manager_code, manager_title):
        if pd.isna(manager_code) or manager_code == "":
            return None
        mgr_row = df[df[emp_code_col] == str(manager_code)]
        if mgr_row.empty:
            return None
        if manager_title == "BUM":
            subordinate_types = ["AM", "DM"]
        elif manager_title == "AM":
            subordinate_types = ["DM"]
        elif manager_title == "DM":
            subordinate_types = ["MR"]
        else:
            subordinate_types = []
        direct_subs = df[df[mgr_code_col] == str(manager_code)]
        if subordinate_types:
            direct_subs = direct_subs[direct_subs[title_col].isin(subordinate_types)]
        node = {
            "Manager": f"{mgr_row.iloc[0][emp_name_col]} ({mgr_row.iloc[0][title_col]})",
            "Manager Code": str(manager_code),
            "Team": [],
            "Summary": {"AM": 0, "DM": 0, "MR": 0, "Total": 0}
        }
        for _, sub_row in direct_subs.iterrows():
            sub_code = sub_row[emp_code_col]
            sub_title = sub_row[title_col]
            child_node = build_team_hierarchy_recursive(df, sub_code, sub_title)
            if not child_node:
                leaf_node = {
                    "Manager": f"{sub_row.get(emp_name_col, sub_code)} ({sub_title})",
                    "Manager Code": str(sub_code),
                    "Team": [],
                    "Summary": {"AM": 0, "DM": 0, "MR": 0, "Total": 0}
                }
                if sub_title == "AM":
                    leaf_node["Summary"]["AM"] = 1
                elif sub_title == "DM":
                    leaf_node["Summary"]["DM"] = 1
                elif sub_title == "MR":
                    leaf_node["Summary"]["MR"] = 1
                leaf_node["Summary"]["Total"] = sum(leaf_node["Summary"].values())
                node["Team"].append(leaf_node)
            else:
                node["Team"].append(child_node)
        def collect_descendants_codes(start_code):
            descendants = set()
            stack = [str(start_code)]
            while stack:
                cur = stack.pop()
                direct = df[df[mgr_code_col] == str(cur)]
                for _, r in direct.iterrows():
                    code = r[emp_code_col]
                    title = r[title_col]
                    if code not in descendants:
                        descendants.add(code)
                        if title in ["AM", "DM", "BUM"]:
                            stack.append(code)
            return list(descendants)
        all_desc = collect_descendants_codes(manager_code)
        if all_desc:
            desc_df = df[df[emp_code_col].isin(all_desc)]
            node["Summary"]["AM"] = int((desc_df[title_col] == "AM").sum())
            node["Summary"]["DM"] = int((desc_df[title_col] == "DM").sum())
            node["Summary"]["MR"] = int((desc_df[title_col] == "MR").sum())
            node["Summary"]["Total"] = int(len(desc_df))
        return node
    user_node = build_team_hierarchy_recursive(df, user_code, user_title)
    if user_node:
        def display_tree(node, level=0, is_last_child=True):
            if not node:
                return
            am_count = node["Summary"]["AM"]
            dm_count = node["Summary"]["DM"]
            mr_count = node["Summary"]["MR"]
            total_count = node["Summary"]["Total"]
            summary_parts = []
            if am_count > 0:
                summary_parts.append(f"🟢 {am_count} AM")
            if dm_count > 0:
                summary_parts.append(f"🔵 {dm_count} DM")
            if mr_count > 0:
                summary_parts.append(f"🟣 {mr_count} MR")
            if total_count > 0:
                summary_parts.append(f"🔢 {total_count} Total")
            summary_str = "| ".join(summary_parts) if summary_parts else "No direct reports"
            manager_info = node.get("Manager", "Unknown")
            manager_code = node.get("Manager Code", "N/A")
            role = "MR"
            if "(" in manager_info and ")" in manager_info:
                role_part = manager_info.split("(")[-1].split(")")[0].strip()
                if role_part in ["MR", "DM", "AM", "BUM"]:
                    role = role_part
            ROLE_ICONS = {
                "MR": "👤",
                "DM": " defaultManager",
                "AM": " defaultManager",
                "BUM": " defaultManager"
            }
            ROLE_COLORS = {
                "MR": "#8B0000",
                "DM": "#05445E",
                "AM": "#0A5C73",
                "BUM": "#006400"
            }
            icon = ROLE_ICONS.get(role, "👤")
            color = ROLE_COLORS.get(role, "#2E2E2E")
            prefix = ""
            if level > 0:
                for i in range(level - 1):
                    prefix += "│ "
                if is_last_child:
                    prefix += "└── "
                else:
                    prefix += "├── "
            st.markdown(
                f"""
                <div class="team-node">
                    <div class="team-node-header">
                        <span style="color: {color};">{prefix}{icon} <strong>{manager_info}</strong> (Code: {manager_code})</span>
                        <span class="team-node-summary">{summary_str}</span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
            for i, child in enumerate(node["Team"]):
                is_last = (i == len(node["Team"]) - 1)
                display_tree(child, level + 1, is_last)
        display_tree(user_node)
    else:
        st.info("No team structure found for you.")

def page_employee_development(user):
    st.subheader("🎓 Employee Development")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.error("No employee data available.")
        return
    code_col_map = {c.lower().strip(): c for c in df.columns}
    emp_code_col = code_col_map.get("employee_code") or code_col_map.get("employee code") or code_col_map.get("code")
    emp_name_col = code_col_map.get("employee_name") or code_col_map.get("employee name") or code_col_map.get("name")
    title_col = code_col_map.get("title") or code_col_map.get("job title") or code_col_map.get("position")
    mgr_code_col = code_col_map.get("manager_code") or code_col_map.get("manager code") or code_col_map.get("reporting_to")
    if not all([emp_code_col, emp_name_col, title_col, mgr_code_col]):
        st.error("Required columns not found.")
        return
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    user_title = str(user.get("Title", "")).strip().upper()
    if user_title not in ["BUM", "AM", "DM"]:
        st.error("Access denied. Only BUM, AM, DM can view employee development.")
        return
    def collect_subordinates_codes(start_code, start_title):
        subordinates = set()
        stack = [(str(start_code), start_title)]
        while stack:
            code, title = stack.pop()
            if title == "BUM":
                next_levels = ["AM", "DM"]
            elif title == "AM":
                next_levels = ["DM"]
            elif title == "DM":
                next_levels = ["MR"]
            else:
                continue
            direct = df[(df[mgr_code_col] == code) & (df[title_col].isin(next_levels))]
            for _, r in direct.iterrows():
                sub_code = r[emp_code_col]
                sub_title = r[title_col]
                if sub_code not in subordinates:
                    subordinates.add(sub_code)
                    if sub_title in ["AM", "DM", "BUM"]:
                        stack.append((sub_code, sub_title))
        return list(subordinates)
    subordinate_codes = collect_subordinates_codes(user_code, user_title)
    idb_df = load_idb_reports()
    certs_df = load_certificates()
    if not idb_df.empty:
        idb_df = idb_df[idb_df["Employee Code"].isin(subordinate_codes)].copy()
        if "Employee Name" not in idb_df.columns:
            idb_df = idb_df.merge(
                df[[emp_code_col, emp_name_col]].rename(columns={emp_code_col: "Employee Code", emp_name_col: "Employee Name"}),
                on="Employee Code", how="left"
            )
        idb_df["Selected Departments"] = idb_df["Selected Departments"].apply(
            lambda x: ", ".join(eval(x)) if isinstance(x, str) else ", ".join(x) if isinstance(x) else ""
        )
        idb_df["Strengths"] = idb_df["Strengths"].apply(
            lambda x: "; ".join(eval(x)) if isinstance(x, str) else "; ".join(x) if isinstance(x) else ""
        )
        idb_df["Development Areas"] = idb_df["Development Areas"].apply(
            lambda x: "; ".join(eval(x)) if isinstance(x, str) else "; ".join(x) if isinstance(x) else ""
        )
        display_cols = ["Employee Code", "Employee Name", "Selected Departments", "Strengths", "Development Areas", "Action Plan", "Updated At"]
        st.markdown("### 📋 IDB Reports")
        st.dataframe(idb_df[display_cols], use_container_width=True)
        buf = BytesIO()
        with pd.ExcelWriter(buf, engine="openpyxl") as writer:
            idb_df[display_cols].to_excel(writer, index=False)
        buf.seek(0)
        st.download_button(
            "📥 Download IDB Reports (Excel)",
            data=buf,
            file_name="IDB_Reports.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
    if not certs_df.empty:
        certs_df = certs_df[certs_df["Employee Code"].isin(subordinate_codes)].copy()
        st.markdown("### 📜 Certifications")
        st.dataframe(certs_df, use_container_width=True)
        buf = BytesIO()
        with pd.ExcelWriter(buf, engine="openpyxl") as writer:
            certs_df.to_excel(writer, index=False)
        buf.seek(0)
        st.download_button(
            "📥 Download Certifications (Excel)",
            data=buf,
            file_name="Certificates.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
    if idb_df.empty and (certs_df.empty or certs_df[certs_df["Employee Code"].isin(subordinate_codes)].empty):
        st.info("No development data found for your subordinates.")

def page_ask_hr(user):
    st.subheader("❓ Ask HR")
    subject = st.text_input("Subject")
    message = st.text_area("Message")
    if st.button("Send to HR"):
        employee_code = user.get("Employee Code", "")
        employee_name = user.get("Employee Name", employee_code)
        queries = load_hr_queries()
        new_id = int(queries["ID"].max()) + 1 if not queries.empty and "ID" in queries.columns else 1
        new_row = {
            "ID": new_id,
            "Employee Code": employee_code,
            "Employee Name": employee_name,
            "Subject": subject,
            "Message": message,
            "Status": "Pending",
            "Date Sent": datetime.now().strftime('%d-%m-%Y %H:%M'),
            "Reply": "",
            "Date Replied": ""
        }
        new_df = pd.DataFrame([new_row])
        queries = pd.concat([queries, new_df], ignore_index=True)
        save_hr_queries(queries)
        add_notification("", "HR", f"New query from {employee_name} ({employee_code}).")
        st.success("✅ Message sent to HR successfully!")

def page_request_hr(user):
    st.subheader("📄 Request HR")
    request_text = st.text_area("Request Details")
    uploaded_file = st.file_uploader("Attach File (optional)", type=["pdf", "docx", "xlsx", "png", "jpg"])
    def save_request_file(uploaded_file, emp_code, req_id):
        filename = f"req_{emp_code}_{req_id}_{uploaded_file.name}"
        filepath = os.path.join("hr_attachments", filename)
        os.makedirs("hr_attachments", exist_ok=True)
        with open(filepath, "wb") as f:
            f.write(uploaded_file.getbuffer())
        return filename
    if st.button("Submit Request"):
        if not request_text.strip():
            st.error("Request details cannot be empty.")
            return
        employee_code = user.get("Employee Code", "")
        employee_name = user.get("Employee Name", employee_code)
        requests_df = load_hr_requests()
        new_id = int(requests_df["ID"].max()) + 1 if not requests_df.empty and "ID" in requests_df.columns else 1
        file_name = ""
        if uploaded_file:
            file_name = save_request_file(uploaded_file, employee_code, new_id)
        new_row = {
            "ID": new_id,
            "HR Code": "",
            "Employee Code": employee_code,
            "Employee Name": employee_name,
            "Request": request_text,
            "File Attached": file_name,
            "Status": "Pending",
            "Response": "",
            "Response File": "",
            "Date Sent": datetime.now().strftime('%d-%m-%Y %H:%M'),
            "Date Responded": ""
        }
        new_df = pd.DataFrame([new_row])
        requests_df = pd.concat([requests_df, new_df], ignore_index=True)
        save_hr_requests(requests_df)
        add_notification("", "HR", f"New request from {employee_name} ({employee_code}).")
        st.success("✅ Request sent to HR successfully!")

def page_ask_employees(user):
    st.subheader("📢 Ask Employees (HR)")
    if user.get("Title", "").upper() != "HR":
        st.error("Access denied. HR only.")
        return
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.error("No employee data available.")
        return
    code_col_map = {c.lower().strip(): c for c in df.columns}
    emp_code_col = code_col_map.get("employee_code") or code_col_map.get("employee code") or code_col_map.get("code")
    emp_name_col = code_col_map.get("employee_name") or code_col_map.get("employee name") or code_col_map.get("name")
    if not emp_code_col or not emp_name_col:
        st.error("Employee Code or Name column not found.")
        return
    df[emp_code_col] = df[emp_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
    all_codes = df[emp_code_col].tolist()
    selected_codes = st.multiselect("Select Employee Codes", options=all_codes)
    subject = st.text_input("Subject")
    message = st.text_area("Message")
    if st.button("Send to Selected Employees"):
        if not selected_codes:
            st.error("Please select at least one employee.")
            return
        if not subject.strip() or not message.strip():
            st.error("Subject and message cannot be empty.")
            return
        for code in selected_codes:
            add_notification("", "", f"Broadcast from HR: {subject} - {message}", recipient_code=code)
        st.success("✅ Message sent to selected employees.")

def page_directory(user):
    st.subheader("📁 Directory")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.error("No employee data available.")
        return
    code_col_map = {c.lower().strip(): c for c in df.columns}
    emp_code_col = code_col_map.get("employee_code") or code_col_map.get("employee code") or code_col_map.get("code")
    emp_name_col = code_col_map.get("employee_name") or code_col_map.get("employee name") or code_col_map.get("name")
    title_col = code_col_map.get("title") or code_col_map.get("job title") or code_col_map.get("position")
    dept_col = code_col_map.get("department") or code_col_map.get("dept")
    phone_col = code_col_map.get("phone") or code_col_map.get("mobile")
    email_col = code_col_map.get("email")
    if not emp_code_col or not emp_name_col:
        st.error("Employee Code or Name column not found.")
        return
    df[emp_code_col] = df[emp_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
    search_term = st.text_input("Search by name or code...")
    if search_term:
        mask = (
            df[emp_name_col].str.contains(search_term, case=False, na=False) |
            df[emp_code_col].str.contains(search_term, case=False, na=False)
        )
        display_df = df[mask].copy()
    else:
        display_df = df.copy()
    display_cols = [emp_name_col, emp_code_col]
    if title_col and title_col in display_df.columns:
        display_cols.append(title_col)
    if dept_col and dept_col in display_df.columns:
        display_cols.append(dept_col)
    if phone_col and phone_col in display_df.columns:
        display_cols.append(phone_col)
    if email_col and email_col in display_df.columns:
        display_cols.append(email_col)
    display_df = display_df[display_cols]
    display_df.columns = [col.replace('_', ' ').title() for col in display_df.columns]
    st.dataframe(display_df, use_container_width=True)

def page_hr_view(user):
    st.subheader("📊 HR Dashboard")
    if user.get("Title", "").upper() != "HR":
        st.error("Access denied. HR only.")
        return
    df = load_employees()
    if df.empty:
        st.error("No employee data.")
        return
    code_col_map = {c.lower().strip(): c for c in df.columns}
    emp_code_col = code_col_map.get("employee_code") or code_col_map.get("employee code") or code_col_map.get("code")
    emp_name_col = code_col_map.get("employee_name") or code_col_map.get("employee name") or code_col_map.get("name")
    title_col = code_col_map.get("title") or code_col_map.get("job title") or code_col_map.get("position")
    dept_col = code_col_map.get("department") or code_col_map.get("dept")
    if emp_code_col:
        df[emp_code_col] = df[emp_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
    total_employees = len(df)
    total_departments = df[dept_col].nunique() if dept_col and dept_col in df.columns else 0
    thirty_days_ago = datetime.now() - timedelta(days=30)
    if "Hire Date" in df.columns:
        df["Hire Date"] = pd.to_datetime(df["Hire Date"], errors="coerce")
        new_hires = len(df[df["Hire Date"] >= thirty_days_ago])
    else:
        new_hires = 0
    c1, c2, c3 = st.columns(3)
    c1.metric("Total Employees", total_employees)
    c2.metric("Departments", total_departments)
    c3.metric("New Hires (30 days)", new_hires)
    st.markdown("---")
    st.markdown("### Employees per Department")
    if dept_col and dept_col in df.columns:
        dept_counts = df[dept_col].fillna("Unknown").value_counts().reset_index()
        dept_counts.columns = ["Department", "Employee Count"]
        st.table(dept_counts.sort_values("Employee Count", ascending=False).reset_index(drop=True))
    else:
        st.info("Department column not found.")
    st.markdown("---")
    buf = BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as writer:
        df.to_excel(writer, index=False)
    buf.seek(0)
    st.download_button(
        "📥 Download All Employees",
        data=buf,
        file_name="All_Employees.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

def page_hr_queries(user):
    st.subheader("❓ HR Queries")
    if user.get("Title", "").upper() != "HR":
        st.error("Access denied. HR only.")
        return
    queries = load_hr_queries()
    if queries.empty:
        st.info("No queries received.")
        return
    queries = queries.sort_values(by="Date Sent", ascending=False).reset_index(drop=True)
    for idx, row in queries.iterrows():
        emp_code = row.get('Employee Code', '')
        emp_name = row.get('Employee Name', '') if pd.notna(row.get('Employee Name', '')) else ''
        subj = row.get('Subject', '') if pd.notna(row.get('Subject', '')) else ''
        msg = row.get("Message", '') if pd.notna(row.get("Message", '')) else ''
        status = row.get('Status', '') if pd.notna(row.get('Status', '')) else ''
        date_sent = row.get("Date Sent", '')
        reply_existing = row.get("Reply", '') if pd.notna(row.get("Reply", '')) else ''
        try:
            sent_time = pd.to_datetime(date_sent).strftime('%d-%m-%Y %H:%M')
        except Exception:
            sent_time = str(date_sent)
        card_html = f"""
        <div class="hr-message-card">
            <div class="hr-message-title">📌 {subj if subj else 'No Subject'}</div>
            <div class="hr-message-meta">👤 {emp_name} — {emp_code} &nbsp;|&nbsp; 🕒 {sent_time} &nbsp;|&nbsp; 🏷️ {status}</div>
            <div class="hr-message-body">{msg if msg else ''}</div>
        </div>
        """
        st.markdown(card_html, unsafe_allow_html=True)
        if reply_existing:
            st.markdown("**🟢 Existing reply:**")
            st.markdown(reply_existing)
        col1, col2 = st.columns([1, 4])
        with col1:
            new_status = st.selectbox("Status", ["Pending", "Resolved", "In Progress"], index=(["Pending", "Resolved", "In Progress"].index(status) if status in ["Pending", "Resolved", "In Progress"] else 0), key=f"status_{row['ID']}")
        with col2:
            reply_msg = st.text_area("Reply", value=reply_existing, key=f"reply_{row['ID']}")
        if st.button(f"Send Reply for Query #{row['ID']}", key=f"btn_reply_{row['ID']}"):
            queries.loc[queries["ID"] == row["ID"], "Reply"] = reply_msg
            queries.loc[queries["ID"] == row["ID"], "Status"] = new_status
            queries.loc[queries["ID"] == row["ID"], "Date Replied"] = datetime.now().strftime('%d-%m-%Y %H:%M')
            save_hr_queries(queries)
            add_notification("", "", f"HR replied to your query #{row['ID']}", recipient_code=emp_code)
            st.success(f"✅ Reply sent for Query #{row['ID']}!")
            st.rerun()

def page_hr_requests(user):
    st.subheader("📄 HR Requests")
    if user.get("Title", "").upper() != "HR":
        st.error("Access denied. HR only.")
        return
    requests_df = load_hr_requests()
    if requests_df.empty:
        st.info("No requests received.")
        return
    requests_df = requests_df.sort_values(by="Date Sent", ascending=False).reset_index(drop=True)
    for idx, row in requests_df.iterrows():
        emp_code = row.get('Employee Code', '')
        emp_name = row.get('Employee Name', '') if pd.notna(row.get('Employee Name', '')) else ''
        request_text = row.get('Request', '') if pd.notna(row.get('Request', '')) else ''
        status = row.get('Status', '') if pd.notna(row.get('Status', '')) else ''
        date_sent = row.get("Date Sent", '')
        response_existing = row.get("Response", '') if pd.notna(row.get("Response", '')) else ''
        file_attached = row.get("File Attached", '')
        try:
            sent_time = pd.to_datetime(date_sent).strftime('%d-%m-%Y %H:%M')
        except Exception:
            sent_time = str(date_sent)
        card_html = f"""
        <div class="hr-message-card">
            <div class="hr-message-title">📋 Request #{row['ID']}</div>
            <div class="hr-message-meta">👤 {emp_name} — {emp_code} &nbsp;|&nbsp; 🕒 {sent_time} &nbsp;|&nbsp; 🏷️ {status}</div>
            <div class="hr-message-body">📄 <strong>Request:</strong> {request_text}</div>
            {f'<div class="hr-message-attachment">📎 <a href="/download/{file_attached}" target="_blank">Download Attachment</a></div>' if file_attached else ''}
        </div>
        """
        st.markdown(card_html, unsafe_allow_html=True)
        if response_existing:
            st.markdown("**🟢 Existing response:**")
            st.markdown(response_existing)
        col1, col2 = st.columns([1, 4])
        with col1:
            new_status = st.selectbox("Status", ["Pending", "Approved", "Rejected"], index=(["Pending", "Approved", "Rejected"].index(status) if status in ["Pending", "Approved", "Rejected"] else 0), key=f"req_status_{row['ID']}")
        with col2:
            response_msg = st.text_area("Response", value=response_existing, key=f"req_response_{row['ID']}")
        uploaded_resp_file = st.file_uploader(f"Attach Response File for Request #{row['ID']}", type=["pdf", "docx", "xlsx"], key=f"upload_resp_{row['ID']}")
        def save_response_file(uploaded_file, emp_code, req_id):
            filename = f"resp_{emp_code}_{req_id}_{uploaded_file.name}"
            filepath = os.path.join("hr_responses", filename)
            os.makedirs("hr_responses", exist_ok=True)
            with open(filepath, "wb") as f:
                f.write(uploaded_file.getbuffer())
            return filename
        if st.button(f"Send Response for Request #{row['ID']}", key=f"btn_req_reply_{row['ID']}"):
            resp_filename = ""
            if uploaded_resp_file:
                resp_filename = save_response_file(uploaded_resp_file, emp_code, row["ID"])
            requests_df.loc[requests_df["ID"] == row["ID"], "Response"] = response_msg
            requests_df.loc[requests_df["ID"] == row["ID"], "Response File"] = resp_filename
            requests_df.loc[requests_df["ID"] == row["ID"], "Status"] = new_status
            requests_df.loc[requests_df["ID"] == row["ID"], "Date Responded"] = datetime.now().strftime('%d-%m-%Y %H:%M')
            save_hr_requests(requests_df)
            add_notification("", "", f"HR responded to your request #{row['ID']}", recipient_code=emp_code)
            st.success(f"✅ Response sent for Request #{row['ID']}!")
            st.rerun()

def page_hr_development(user):
    st.subheader("🎓 Employee Development (HR View)")
    if user.get("Title", "").upper() != "HR":
        st.error("Access denied. HR only.")
        return
    tab_idb, tab_certs = st.tabs(["📋 IDB Reports", "📜 Certifications"])
    with tab_idb:
        idb_df = load_idb_reports()
        if not idb_df.empty:
            if "Employee Name" not in idb_df.columns:
                df = st.session_state.get("df", pd.DataFrame())
                if not df.empty:
                    col_map = {c.lower().strip(): c for c in df.columns}
                    emp_code_col = col_map.get("employee_code") or col_map.get("employee code")
                    emp_name_col = col_map.get("employee_name") or col_map.get("employee name") or col_map.get("name")
                    if emp_code_col and emp_name_col:
                        df[emp_code_col] = df[emp_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
                        idb_df["Employee Code"] = idb_df["Employee Code"].astype(str).str.strip()
                        idb_df = idb_df.merge(
                            df[[emp_code_col, emp_name_col]].rename(columns={emp_code_col: "Employee Code", emp_name_col: "Employee Name"}),
                            on="Employee Code",
                            how="left"
                        )
            idb_df["Selected Departments"] = idb_df["Selected Departments"].apply(
                lambda x: ", ".join(eval(x)) if isinstance(x, str) else ", ".join(x) if isinstance(x) else ""
            )
            idb_df["Strengths"] = idb_df["Strengths"].apply(
                lambda x: "; ".join(eval(x)) if isinstance(x, str) else "; ".join(x) if isinstance(x) else ""
            )
            idb_df["Development Areas"] = idb_df["Development Areas"].apply(
                lambda x: "; ".join(eval(x)) if isinstance(x, str) else "; ".join(x) if isinstance(x) else ""
            )
            display_cols = ["Employee Code", "Employee Name", "Selected Departments", "Strengths", "Development Areas", "Action Plan", "Updated At"]
            st.dataframe(idb_df[display_cols], use_container_width=True)
            buf = BytesIO()
            with pd.ExcelWriter(buf, engine="openpyxl") as writer:
                idb_df[display_cols].to_excel(writer, index=False)
            buf.seek(0)
            st.download_button(
                "📥 Download IDB Reports (Excel)",
                data=buf,
                file_name="HR_IDB_Reports.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )
        else:
            st.info("No IDB reports submitted yet.")
    with tab_certs:
        certs_df = load_certificates()
        if not certs_df.empty:
            st.dataframe(certs_df, use_container_width=True)
            buf = BytesIO()
            with pd.ExcelWriter(buf, engine="openpyxl") as writer:
                certs_df.to_excel(writer, index=False)
            buf.seek(0)
            st.download_button(
                "📥 Download Certificates (Excel)",
                data=buf,
                file_name="HR_Certificates.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )
        else:
            st.info("No certificates uploaded yet.")

def page_employee_photos(user):
    st.subheader("📸 Employee Photos (HR Only)")
    if user.get("Title", "").upper() != "HR":
        st.error("Access denied. HR only.")
        return
    os.makedirs("employee_photos", exist_ok=True)
    photo_files = os.listdir("employee_photos")
    if not photo_files:
        st.info("No employee photos uploaded yet.")
        return
    cols = st.columns(3)
    for i, filename in enumerate(photo_files):
        with cols[i % 3]:
            img_path = os.path.join("employee_photos", filename)
            try:
                image = Image.open(img_path)
                st.image(image, caption=filename, use_column_width=True)
            except Exception:
                st.error(f"Could not load image: {filename}")

def page_salary_monthly(user):
    st.subheader("💰 Salary Information")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.error("No employee data available.")
        return
    code_col_map = {c.lower().strip(): c for c in df.columns}
    emp_code_col = code_col_map.get("employee_code") or code_col_map.get("employee code") or code_col_map.get("code")
    emp_name_col = code_col_map.get("employee_name") or code_col_map.get("employee name") or code_col_map.get("name")
    salary_col = code_col_map.get("salary") or code_col_map.get("basic salary")
    if not all([emp_code_col, emp_name_col, salary_col]):
        st.error("Required columns (Employee Code, Employee Name, Salary) not found.")
        return
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    user_row = df[df[emp_code_col] == user_code]
    if user_row.empty:
        st.error("Your record not found.")
        return
    user_record = user_row.iloc[0]
    user_name = user_record.get(emp_name_col, user_code)
    raw_salary = user_record.get(salary_col, "N/A")
    try:
        decrypted_salary = decrypt_salary_value(raw_salary)
        formatted_salary = format_currency(float(decrypted_salary), 'EGP', locale='en_US')
    except:
        formatted_salary = str(raw_salary)
    st.markdown(f"**Employee Name:** {user_name}")
    st.markdown(f"**Employee Code:** {user_code}")
    st.markdown(f"**Gross Salary:** {formatted_salary}")
    st.markdown("---")
    months = ["January", "February", "March", "April", "May", "June",
              "July", "August", "September", "October", "November", "December"]
    current_month = datetime.now().month
    current_year = datetime.now().year
    month_name = months[current_month - 1]
    year_str = str(current_year)
    st.markdown(f"### Salary Slip for {month_name} {year_str}")
    # Example slip details - customize based on actual data
    basic = formatted_salary
    allowance = "N/A"
    deduction = "N/A"
    net = formatted_salary
    slip_data = {
        "Component": ["Basic Salary", "Allowance", "Deduction", "Net Pay"],
        "Amount": [basic, allowance, deduction, net]
    }
    slip_df = pd.DataFrame(slip_data)
    st.table(slip_df)

def page_salary_report(user):
    st.subheader("📊 Salary Report (HR)")
    if user.get("Title", "").upper() != "HR":
        st.error("Access denied. HR only.")
        return
    df = load_employees()
    if df.empty:
        st.error("No employee data.")
        return
    code_col_map = {c.lower().strip(): c for c in df.columns}
    emp_code_col = code_col_map.get("employee_code") or code_col_map.get("employee code") or code_col_map.get("code")
    emp_name_col = code_col_map.get("employee_name") or code_col_map.get("employee name") or code_col_map.get("name")
    salary_col = code_col_map.get("salary") or code_col_map.get("basic salary")
    if not all([emp_code_col, emp_name_col, salary_col]):
        st.error("Required columns not found.")
        return
    df[emp_code_col] = df[emp_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
    df_display = df[[emp_code_col, emp_name_col, salary_col]].copy()
    df_display.rename(columns={emp_code_col: "Employee Code", emp_name_col: "Employee Name", salary_col: "Encrypted Salary"}, inplace=True)
    st.dataframe(df_display, use_container_width=True)
    buf = BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as writer:
        df_display.to_excel(writer, index=False)
    buf.seek(0)
    st.download_button(
        "📥 Download Salary Report",
        data=buf,
        file_name="Salary_Report.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

def page_idb_mr(user):
    st.subheader("🚀 IDB – Individual Development Blueprint")
    st.markdown("""<div style="background-color:#f0fdf4; padding:12px; border-radius:8px; border-left:4px solid #059669;"><p style="color:#05445E; font-weight:bold;">We want you to always aim higher — your success matters to us.</p></div>""", unsafe_allow_html=True)
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    user_name = user.get("Employee Name", user_code)
    departments = ["Sales", "Marketing", "HR", "SFE", "Distribution", "Market Access"]
    reports = load_idb_reports()
    existing = reports[reports["Employee Code"] == user_code]
    if not existing.empty:
        row = existing.iloc[0]
        selected_deps = eval(row["Selected Departments"]) if isinstance(row["Selected Departments"], str) else row["Selected Departments"]
        strengths = eval(row["Strengths"]) if isinstance(row["Strengths"], str) else row["Strengths"]
        development = eval(row["Development Areas"]) if isinstance(row["Development Areas"], str) else row["Development Areas"]
        action = row["Action Plan"]
    else:
        selected_deps = []
        strengths = ["", "", ""]
        development = ["", "", ""]
        action = ""
    with st.form("idb_form"):
        st.markdown("### 🔍 Select Target Departments (Max 2)")
        selected = st.multiselect("Choose up to 2 departments you're interested in:", options=departments, default=selected_deps)
        if len(selected) > 2:
            st.warning("⚠️ You can select a maximum of 2 departments.")
        st.markdown("### 💪 Area of Strength (3 points)")
        strength_inputs = []
        for i in range(3):
            val = strengths[i] if i < len(strengths) else ""
            strength_inputs.append(st.text_input(f"Strength {i+1}", value=val, key=f"str_{i}"))
        st.markdown("### 📈 Area of Development (3 points)")
        dev_inputs = []
        for i in range(3):
            val = development[i] if i < len(development) else ""
            dev_inputs.append(st.text_input(f"Development {i+1}", value=val, key=f"dev_{i}"))
        st.markdown("### 🤝 Action Plan (Agreed with your manager)")
        action_input = st.text_area("Action", value=action, height=100)
        submitted = st.form_submit_button("💾 Save IDB Report")
        if submitted:
            if len(selected) > 2:
                st.error("You cannot select more than 2 departments.")
            else:
                success = save_idb_report(
                    user_code,
                    user_name,  # ✅ FIXED: Added Employee Name
                    selected,
                    [s.strip() for s in strength_inputs if s.strip()],
                    [d.strip() for d in dev_inputs if d.strip()],
                    action_input.strip()
                )
                if success:
                    st.success("✅ IDB Report saved successfully!")
                    # ✅ FIXED: Send notification to HR + ALL managers (DM, AM, BUM)
                    add_notification("", "HR", f"MR {user_name} ({user_code}) updated their IDB report.")
                    add_notification("", "DM", f"MR {user_name} ({user_code}) updated their IDB report.")
                    add_notification("", "AM", f"MR {user_name} ({user_code}) updated their IDB report.")
                    add_notification("", "BUM", f"MR {user_name} ({user_code}) updated their IDB report.")
                    st.rerun()
                else:
                    st.error("❌ Failed to save report.")
    if not existing.empty:
        st.markdown("### 📊 Your Current IDB Report")
        display_data = {
            "Field": [
                "Selected Departments",
                "Strength 1", "Strength 2", "Strength 3",
                "Development 1", "Development 2", "Development 3",
                "Action Plan",
                "Updated At"
            ],
            "Value": [
                ", ".join(selected_deps),
                *(strengths + [""] * (3 - len(strengths))),
                *(development + [""] * (3 - len(development))),
                action,
                existing.iloc[0]["Updated At"]
            ]
        }
        display_df = pd.DataFrame(display_data)
        st.dataframe(display_df, use_container_width=True)

def page_leave_application(user):
    st.subheader("🏖️ Apply for Leave")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.error("No employee data available.")
        return
    code_col_map = {c.lower().strip(): c for c in df.columns}
    emp_code_col = code_col_map.get("employee_code") or code_col_map.get("employee code") or code_col_map.get("code")
    mgr_code_col = code_col_map.get("manager_code") or code_col_map.get("manager code") or code_col_map.get("reporting_to")
    if not emp_code_col or not mgr_code_col:
        st.error("Employee Code or Manager Code column not found.")
        return
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    user_row = df[df[emp_code_col] == user_code]
    if user_row.empty:
        st.error("Your record not found.")
        return
    manager_code = user_row.iloc[0][mgr_code_col]
    with st.form("leave_form"):
        start_date = st.date_input("Start Date")
        end_date = st.date_input("End Date")
        leave_type = st.selectbox("Leave Type", ["Annual", "Sick", "Emergency", "Unpaid"])
        reason = st.text_area("Reason")
        submitted = st.form_submit_button("Submit Leave Request")
        if submitted:
            if end_date < start_date:
                st.error("End date cannot be before start date.")
            else:
                new_row = pd.DataFrame([{
                    "Employee Code": user_code,
                    "Manager Code": manager_code,
                    "Start Date": pd.Timestamp(start_date),
                    "End Date": pd.Timestamp(end_date),
                    "Leave Type": leave_type,
                    "Reason": reason,
                    "Status": "Pending",
                    "Decision Date": None,
                    "Comment": ""
                }])
                leaves_df = load_leaves()
                leaves_df = pd.concat([leaves_df, new_row], ignore_index=True)
                save_leaves(leaves_df)
                add_notification("", manager_code, f"Leave request from {user.get('Employee Name', user_code)} ({user_code}).")
                st.success("✅ Leave request submitted successfully!")

def page_my_leaves(user):
    st.subheader("🗓️ My Leaves")
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    leaves_df = load_leaves()
    my_leaves = leaves_df[leaves_df["Employee Code"] == user_code].copy()
    my_leaves["Start Date"] = pd.to_datetime(my_leaves["Start Date"], errors="coerce").dt.strftime("%d-%m-%Y")
    my_leaves["End Date"] = pd.to_datetime(my_leaves["End Date"], errors="coerce").dt.strftime("%d-%m-%Y")
    my_leaves["Decision Date"] = pd.to_datetime(my_leaves["Decision Date"], errors="coerce").dt.strftime("%d-%m-%Y")
    display_cols = ["Start Date", "End Date", "Leave Type", "Reason", "Status", "Decision Date", "Comment"]
    if not my_leaves.empty:
        st.dataframe(my_leaves[display_cols], use_container_width=True)
    else:
        st.info("No leave records found.")

def page_manage_leaves(user):
    st.subheader("审批 Leaves")
    user_title = str(user.get("Title", "")).strip().upper()
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.error("No employee data available.")
        return
    code_col_map = {c.lower().strip(): c for c in df.columns}
    emp_code_col = code_col_map.get("employee_code") or code_col_map.get("employee code") or code_col_map.get("code")
    mgr_code_col = code_col_map.get("manager_code") or code_col_map.get("manager code") or code_col_map.get("reporting_to")
    emp_name_col = code_col_map.get("employee_name") or code_col_map.get("employee name") or code_col_map.get("name")
    if not all([emp_code_col, mgr_code_col, emp_name_col]):
        st.error("Required columns not found.")
        return
    df[emp_code_col] = df[emp_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
    if user_title in ["DM", "AM", "BUM"]:
        team_leaves = load_leaves()
        team_leaves["Employee Code"] = team_leaves["Employee Code"].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
        team_leaves = team_leaves.merge(
            df[[emp_code_col, emp_name_col]],
            left_on="Employee Code",
            right_on=emp_code_col,
            how="left"
        )
        name_col_to_use = emp_name_col
        if user_title == "DM":
            team_leaves_filtered = team_leaves[team_leaves[mgr_code_col] == user_code]
        elif user_title == "AM":
            # AM manages DMs and their teams
            dm_codes = df[(df[mgr_code_col] == user_code) & (df[code_col_map.get("title") or code_col_map.get("job title") or code_col_map.get("position")] == "DM")][emp_code_col].tolist()
            all_managed_codes = dm_codes[:]
            for dm_code in dm_codes:
                subordinates = df[df[mgr_code_col] == dm_code][emp_code_col].tolist()
                all_managed_codes.extend(subordinates)
            team_leaves_filtered = team_leaves[team_leaves["Employee Code"].isin(all_managed_codes)]
        elif user_title == "BUM":
            # BUM manages AMs, DMs and their teams
            am_dm_codes = df[(df[mgr_code_col] == user_code) | (df[mgr_code_col].isin(df[df[mgr_code_col] == user_code][emp_code_col]))][emp_code_col].tolist()
            all_managed_codes = am_dm_codes[:]
            for code in am_dm_codes:
                subordinates = df[df[mgr_code_col] == code][emp_code_col].tolist()
                all_managed_codes.extend(subordinates)
            team_leaves_filtered = team_leaves[team_leaves["Employee Code"].isin(all_managed_codes)]
        else:
            team_leaves_filtered = pd.DataFrame()
        pending_leaves = team_leaves_filtered[team_leaves_filtered["Status"] == "Pending"].reset_index(drop=True)
        st.markdown("### 🟡 Pending Requests")
        if not pending_leaves.empty:
            for idx, row in pending_leaves.iterrows():
                emp_name = row.get(name_col_to_use, "") if name_col_to_use in row else ""
                emp_display = f"{emp_name} ({row['Employee Code']})" if emp_name else row['Employee Code']
                with st.expander(f"Leave Request: {emp_display} - {row['Leave Type']} ({row['Start Date'].strftime('%d-%m-%Y')} to {row['End Date'].strftime('%d-%m-%Y')})"):
                    st.write(f"**Reason:** {row['Reason']}")
                    decision = st.radio("Decision", ("Approve", "Reject"), key=f"decision_{row.name}")
                    comment = st.text_input("Comment (optional)", key=f"comment_{row.name}")
                    if st.button(f"Submit Decision for {emp_display}", key=f"submit_decision_{row.name}"):
                        team_leaves.loc[team_leaves["Employee Code"] == row["Employee Code"], "Status"] = decision
                        team_leaves.loc[team_leaves["Employee Code"] == row["Employee Code"], "Comment"] = comment
                        team_leaves.loc[team_leaves["Employee Code"] == row["Employee Code"], "Decision Date"] = datetime.now()
                        save_leaves(team_leaves)
                        add_notification("", row["Employee Code"], f"Your leave request has been {decision.lower()}. Comment: {comment}")
                        st.success(f"✅ Decision '{decision}' submitted for {emp_display}!")
                        st.rerun()
        else:
            st.info("No pending leave requests.")
        st.markdown("---")
        st.markdown("### ✅ Approved / ❌ Rejected Requests")
        processed_leaves = team_leaves_filtered[team_leaves_filtered["Status"] != "Pending"].reset_index(drop=True)
        if not processed_leaves.empty:
            processed_leaves["Start Date"] = pd.to_datetime(processed_leaves["Start Date"]).dt.strftime("%d-%m-%Y")
            processed_leaves["End Date"] = pd.to_datetime(processed_leaves["End Date"]).dt.strftime("%d-%m-%Y")
            processed_leaves["Decision Date"] = pd.to_datetime(processed_leaves["Decision Date"]).dt.strftime("%d-%m-%Y")
            display_cols = [name_col_to_use, "Employee Code", "Start Date", "End Date", "Leave Type", "Reason", "Status", "Decision Date", "Comment"]
            st.dataframe(processed_leaves[display_cols], use_container_width=True)
        else:
            st.info("No processed requests.")
    else:
        st.error("Access denied. Only DM, AM, BUM can manage leaves.")

def page_recruitment(user):
    st.subheader("👥 Recruitment Management")
    if user.get("Title", "").upper() != "HR":
        st.error("Access denied. HR only.")
        return
    st.markdown(f"""<div style="background-color:white; padding:12px; border-radius:8px; border:1px solid #05445E; margin-bottom:20px;">
        <p style="color:#05445E; font-weight:bold;">Recruitment Database Management</p>
    </div>""", unsafe_allow_html=True)
    st.markdown("### Upload Recruitment Data from Google Forms")
    uploaded_db = st.file_uploader("Upload Excel from Google Forms", type=["xlsx"])
    if uploaded_db:
        try:
            new_db_df = pd.read_excel(uploaded_db)
            st.session_state["recruitment_preview"] = new_db_df.copy()
            st.success("File loaded successfully.")
            st.dataframe(new_db_df.head(10), use_container_width=True)
            if st.button("✅ Replace Recruitment Database"):
                save_recruitment_data(new_db_df)
                st.success("Recruitment database updated!")
                st.rerun()
        except Exception as e:
            st.error(f"Error reading file: {e}")
    st.markdown("---")
    st.markdown("### Current Recruitment Database")
    db_df = load_recruitment_data()
    if not db_df.empty:
        st.dataframe(db_df, use_container_width=True)
        buf = BytesIO()
        with pd.ExcelWriter(buf, engine="openpyxl") as writer:
            db_df.to_excel(writer, index=False)
        buf.seek(0)
        st.download_button(
            "📥 Download Recruitment Database",
            data=buf,
            file_name="Recruitment_Data.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
    else:
        st.info("No recruitment data uploaded yet.")

def page_certificates(user):
    st.subheader("📜 My Certificates")
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    user_name = user.get("Employee Name", user_code)
    certs_df = load_certificates()
    user_certs = certs_df[certs_df["Employee Code"] == user_code].copy()
    st.markdown("### Upload New Certificate")
    uploaded_cert = st.file_uploader("Choose a certificate file", type=["pdf", "png", "jpg", "jpeg", "docx"])
    cert_name = st.text_input("Certificate Name")
    exp_date = st.date_input("Expiration Date (optional)")
    if st.button("Upload Certificate"):
        if not uploaded_cert or not cert_name:
            st.error("Please provide a file and a name.")
            return
        filename = f"cert_{user_code}_{cert_name.replace(' ', '_')}_{uploaded_cert.name}"
        filepath = os.path.join("certificates", filename)
        os.makedirs("certificates", exist_ok=True)
        with open(filepath, "wb") as f:
            f.write(uploaded_cert.getbuffer())
        new_cert = {
            "Employee Code": user_code,
            "Employee Name": user_name,
            "Certificate Name": cert_name,
            "File": filename,
            "Upload Date": datetime.now().strftime('%d-%m-%Y'),
            "Expiration Date": exp_date.strftime('%d-%m-%Y') if exp_date else "",
            "Status": "Active"
        }
        new_df = pd.DataFrame([new_cert])
        certs_df = pd.concat([certs_df, new_df], ignore_index=True)
        save_certificates(certs_df)
        st.success("✅ Certificate uploaded successfully!")
        st.rerun()
    st.markdown("### My Uploaded Certificates")
    if not user_certs.empty:
        for idx, row in user_certs.iterrows():
            with st.container():
                st.markdown(f"**Name:** {row['Certificate Name']}")
                st.markdown(f"**Uploaded:** {row['Upload Date']}")
                st.markdown(f"**Expires:** {row['Expiration Date'] if row['Expiration Date'] else 'N/A'}")
                st.markdown(f"**Status:** {row['Status']}")
                file_path = os.path.join("certificates", row["File"])
                if os.path.exists(file_path):
                    with open(file_path, "rb") as f:
                        st.download_button(
                            label=f"📥 Download {row['File']}",
                            data=f,
                            file_name=row["File"], # Same original filename
                            mime="application/octet-stream", # Generic format preserving file type
                            key=f"dl_cert_{idx}"
                        )
                else:
                    st.warning("File not found.")
                st.markdown("---")
    else:
        st.info("📭 No certificates uploaded.")

def render_logo_and_title():
    pass # Do nothing

# CSS Styles
hide_streamlit_style = """
<style>
#MainMenu { visibility: hidden; }
footer { visibility: hidden; }
header { visibility: hidden; }
div[data-testid="stToolbar"] { display: none; }
div[data-testid="stDeployButton"] { display: none; }
</style>
"""
st.markdown(hide_streamlit_style, unsafe_allow_html=True)

# Updated CSS with white button text
updated_css = """
<style>
/* ========== COLORS SYSTEM ========== */
:root {
  --primary: #05445E;
  --secondary: #0A5C73;
  --text-main: #2E2E2E;
  --text-muted: #6B7280;
  --card-bg: #FFFFFF;
  --soft-bg: #F2F6F8;
  --border-soft: #E5E7EB;
}

/* ========== GENERAL TEXT ========== */
html, body, p, span, label {
  color: var(--text-main) !important;
}

/* ========== HEADERS ========== */
h1, h2, h3, h4, h5 {
  color: var(--primary) !important;
}

/* ========== BUTTONS ========== */
.stButton > button {
  background-color: var(--primary) !important;
  color: white !important; /* White text for contrast */
  border: 1px solid var(--primary) !important;
  width: 100% !important;
  padding: 12px 0 !important;
  margin: 5px 0 !important;
  border-radius: 8px !important;
  font-weight: 500 !important;
  transition: all 0.3s ease !important;
}
.stButton > button:hover {
  background-color: #FF0000 !important; /* Red on hover */
  color: white !important; /* Keep text white on hover */
  border-color: #FF0000 !important;
  transform: translateY(-2px) !important;
  box-shadow: 0 4px 8px rgba(0,0,0,0.2) !important;
}
.stButton > button:focus {
  outline: none !important;
  box-shadow: 0 0 0 2px rgba(5, 68, 94, 0.5) !important;
}

/* ========== LINKS ========== */
a {
  color: var(--secondary) !important;
  text-decoration: none !important;
}
a:hover {
  color: var(--primary) !important;
  text-decoration: underline !important;
}

/* ========== INPUT FIELDS ========== */
input, textarea, select, .stSelectbox, .stMultiSelect {
  background-color: var(--card-bg) !important;
  border: 1px solid var(--border-soft) !important;
  border-radius: 8px !important;
  padding: 8px 12px !important;
  color: var(--text-main) !important;
}
input:focus, textarea:focus, select:focus {
  border-color: var(--primary) !important;
  box-shadow: 0 0 0 2px rgba(5, 68, 94, 0.2) !important;
  outline: none !important;
}

/* ========== DATAFRAME STYLING ========== */
table {
  border-collapse: collapse !important;
  width: 100% !important;
}
th {
  background-color: var(--soft-bg) !important;
  color: var(--primary) !important;
  font-weight: bold !important;
  padding: 10px !important;
  border: 1px solid var(--border-soft) !important;
  text-align: left !important;
}
td {
  padding: 8px 10px !important;
  border: 1px solid var(--border-soft) !important;
  color: var(--text-main) !important;
}

/* ========== CARDS & CONTAINERS ========== */
[data-testid="stForm"] {
  background-color: var(--card-bg) !important;
  padding: 20px !important;
  border-radius: 12px !important;
  border: 1px solid var(--border-soft) !important;
  box-shadow: 0 4px 6px rgba(0,0,0,0.05) !important;
}

/* ========== INFO TEXT (No data, help text) ========== */
.info-text {
  color: var(--text-muted) !important;
  font-size: 14px;
}

/* ========== SECTION HEADER BOX ========== */
.section-box {
  background-color: var(--soft-bg);
  padding: 14px 20px;
  border-radius: 14px;
  margin: 25px 0 15px 0;
}

/* ========== ADDITIONAL ESSENTIAL STYLES ========== */
.sidebar-title {
  font-size: 1.4rem;
  font-weight: bold;
  color: var(--primary);
  text-align: center;
  margin-bottom: 10px;
}

.hr-message-card {
  background-color: #FFFFFF;
  border-left: 4px solid var(--primary);
  padding: 12px;
  margin: 10px 0;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.05);
}
.hr-message-title {
  font-weight: bold;
  color: var(--primary);
  margin-bottom: 5px;
}
.hr-message-meta {
  font-size: 0.9em;
  color: var(--text-muted);
  margin-bottom: 5px;
}
.hr-message-body {
  color: var(--text-main);
}

.team-node {
  margin: 5px 0;
}
.team-node-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 5px 0;
}
.team-node-summary {
  font-size: 0.9em;
  color: var(--text-muted);
}

.leave-balance-container {
  display: flex;
  justify-content: space-around;
  margin: 15px 0;
}
.leave-balance-item {
  text-align: center;
}
.leave-balance-label {
  font-size: 0.9em;
  color: var(--text-muted);
}
.leave-balance-value {
  font-size: 1.4rem;
  font-weight: bold;
  margin-top: 4px;
}
.leave-balance-value.used { color: #dc2626; }
.leave-balance-value.remaining { color: #059669; }

.team-structure-value.am { color: var(--primary); }
.team-structure-value.dm { color: var(--secondary); }
.team-structure-value.mr { color: #dc2626; }

.notification-bell {
  position: absolute;
  top: 20px;
  right: 20px;
  background-color: #ef4444;
  color: white;
  width: 24px;
  height: 24px;
  border-radius: 50%;
  display: flex;
  justify-content: center;
  align-items: center;
  font-weight: bold;
  font-size: 0.8rem;
  z-index: 100;
}
</style>
"""

st.markdown(updated_css, unsafe_allow_html=True)

# Main App Logic
if st.session_state["external_password_page"]:
    page_forgot_password()
else:
    if st.session_state["logged_in_user"]:
        user = st.session_state["logged_in_user"]
        title_val = str(user.get("Title") or "").strip().upper()
        is_hr = "HR" in title_val
        is_bum = title_val == "BUM"
        is_am = title_val == "AM"
        is_dm = title_val == "DM"
        is_mr = title_val == "MR"

        # Define navigation pages based on role
        pages = ["My Profile", "Notifications"]
        if is_hr:
            pages.extend([
                "HR View", "HR Queries", "HR Requests",
                "Employee Development", "Employee Photos",
                "Salary Report", "Recruitment Management"
            ])
        elif is_bum or is_am or is_dm:
            pages.extend([
                "Employee Development",  # New page added
                "Manage Leaves",
                "Directory",
                "Ask HR",
                "Request HR"
            ])
        elif is_mr:
            pages.extend([
                "IDB – Individual Development Blueprint",
                "Apply for Leave",
                "My Leaves",
                "My Certificates",
                "Directory",
                "Ask HR",
                "Request HR"
            ])

        # Add common pages
        pages.extend(["Salary Monthly"])

        # Sidebar Navigation
        with st.sidebar:
            st.markdown('<div class="sidebar-title">Employee Portal</div>', unsafe_allow_html=True)
            unread_count = get_unread_count(user)
            for p in pages:
                if p == "Notifications":
                    if unread_count > 0:
                        button_label = f"Notifications ({unread_count})"
                    else:
                        button_label = "Notifications"
                    if st.button(button_label, key=f"nav_{p}", use_container_width=True):
                        st.session_state["current_page"] = p
                        st.rerun()
                else:
                    if st.button(p, key=f"nav_{p}", use_container_width=True):
                        st.session_state["current_page"] = p
                        st.rerun()
            st.markdown("---")
            if st.button("🚪 Logout", use_container_width=True):
                st.session_state["logged_in_user"] = None
                st.session_state["current_page"] = "Login"
                st.success("You have been logged out.")
                st.rerun()

        # Page Routing
        current_page = st.session_state["current_page"]

        if current_page == "Login":
            page_login()
        elif current_page == "My Profile":
            page_my_profile(user)
        elif current_page == "Notifications":
            page_notifications(user)
        elif current_page == "HR View":
            if is_hr:
                page_hr_view(user)
            else:
                st.error("Access denied. HR only.")
        elif current_page == "HR Queries":
            if is_hr:
                page_hr_queries(user)
            else:
                st.error("Access denied. HR only.")
        elif current_page == "HR Requests":
            if is_hr:
                page_hr_requests(user)
            else:
                st.error("Access denied. HR only.")
        elif current_page == "Employee Development":
            # Available for BUM, AM, DM
            if is_bum or is_am or is_dm:
                page_employee_development(user)
            else:
                st.error("Access denied. Only BUM, AM, DM can access this page.")
        elif current_page == "Employee Photos":
            if is_hr:
                page_employee_photos(user)
            else:
                st.error("Access denied. HR only.")
        elif current_page == "Ask HR":
            page_ask_hr(user)
        elif current_page == "Ask Employees":
            if is_hr:
                page_ask_employees(user)
            else:
                st.error("Access denied. HR only.")
        elif current_page == "Request HR":
            page_request_hr(user)
        elif current_page == "Directory":
            page_directory(user)
        elif current_page == "Salary Monthly":
            page_salary_monthly(user)
        elif current_page == "Salary Report":
            if is_hr:
                page_salary_report(user)
            else:
                st.error("Access denied. HR only.")
        elif current_page == "IDB – Individual Development Blueprint":
            if is_mr:
                page_idb_mr(user)
            else:
                st.error("Access denied. MR only.")
        elif current_page == "Apply for Leave":
            if is_mr:
                page_leave_application(user)
            else:
                st.error("Access denied. MR only.")
        elif current_page == "My Leaves":
            page_my_leaves(user)
        elif current_page == "Manage Leaves":
            if is_dm or is_am or is_bum:
                page_manage_leaves(user)
            else:
                st.error("Access denied. DM/AM/BUM only.")
        elif current_page == "Recruitment Management":
            if is_hr:
                page_recruitment(user)
            else:
                st.error("Access denied. HR only.")
        elif current_page == "My Certificates":
            if is_mr:
                page_certificates(user)
            else:
                st.error("Access denied. MR only.")
        else:
            st.error(f"Page '{current_page}' not found.")
    else:
        page_login()

def get_unread_count(user):
    notifications = load_notifications()
    if notifications.empty:
        return 0
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    user_title = str(user.get("Title", "")).strip().upper()
    mask = (
        (notifications["Recipient Code"].astype(str) == user_code) &
        (notifications["Is Read"] == False)
    ) | (
        (notifications["Recipient Title"].astype(str).str.upper() == user_title) &
        (notifications["Is Read"] == False)
    )
    return int(notifications[mask].shape[0])

# --- New Functions for Confirmation Messages ---
def show_confirmation_message(message: str):
    """Displays a success message indicating an action was completed."""
    st.success(message)

# --- Modified Button Functions to Include Confirmation ---

def page_ask_hr(user):
    st.subheader("❓ Ask HR")
    subject = st.text_input("Subject")
    message = st.text_area("Message")
    if st.button("Send to HR"):
        employee_code = user.get("Employee Code", "")
        employee_name = user.get("Employee Name", employee_code)
        queries = load_hr_queries()
        new_id = int(queries["ID"].max()) + 1 if not queries.empty and "ID" in queries.columns else 1
        new_row = {
            "ID": new_id,
            "Employee Code": employee_code,
            "Employee Name": employee_name,
            "Subject": subject,
            "Message": message,
            "Status": "Pending",
            "Date Sent": datetime.now().strftime('%d-%m-%Y %H:%M'),
            "Reply": "",
            "Date Replied": ""
        }
        new_df = pd.DataFrame([new_row])
        queries = pd.concat([queries, new_df], ignore_index=True)
        save_hr_queries(queries)
        add_notification("", "HR", f"New query from {employee_name} ({employee_code}).")
        # Confirmation message added
        show_confirmation_message("✅ Message sent to HR successfully!")

def page_request_hr(user):
    st.subheader("📄 Request HR")
    request_text = st.text_area("Request Details")
    uploaded_file = st.file_uploader("Attach File (optional)", type=["pdf", "docx", "xlsx", "png", "jpg"])
    def save_request_file(uploaded_file, emp_code, req_id):
        filename = f"req_{emp_code}_{req_id}_{uploaded_file.name}"
        filepath = os.path.join("hr_attachments", filename)
        os.makedirs("hr_attachments", exist_ok=True)
        with open(filepath, "wb") as f:
            f.write(uploaded_file.getbuffer())
        return filename
    if st.button("Submit Request"):
        if not request_text.strip():
            st.error("Request details cannot be empty.")
            return
        employee_code = user.get("Employee Code", "")
        employee_name = user.get("Employee Name", employee_code)
        requests_df = load_hr_requests()
        new_id = int(requests_df["ID"].max()) + 1 if not requests_df.empty and "ID" in requests_df.columns else 1
        file_name = ""
        if uploaded_file:
            file_name = save_request_file(uploaded_file, employee_code, new_id)
        new_row = {
            "ID": new_id,
            "HR Code": "",
            "Employee Code": employee_code,
            "Employee Name": employee_name,
            "Request": request_text,
            "File Attached": file_name,
            "Status": "Pending",
            "Response": "",
            "Response File": "",
            "Date Sent": datetime.now().strftime('%d-%m-%Y %H:%M'),
            "Date Responded": ""
        }
        new_df = pd.DataFrame([new_row])
        requests_df = pd.concat([requests_df, new_df], ignore_index=True)
        save_hr_requests(requests_df)
        add_notification("", "HR", f"New request from {employee_name} ({employee_code}).")
        # Confirmation message added
        show_confirmation_message("✅ Request sent to HR successfully!")

def page_ask_employees(user):
    st.subheader("📢 Ask Employees (HR)")
    if user.get("Title", "").upper() != "HR":
        st.error("Access denied. HR only.")
        return
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.error("No employee data available.")
        return
    code_col_map = {c.lower().strip(): c for c in df.columns}
    emp_code_col = code_col_map.get("employee_code") or code_col_map.get("employee code") or code_col_map.get("code")
    emp_name_col = code_col_map.get("employee_name") or code_col_map.get("employee name") or code_col_map.get("name")
    if not emp_code_col or not emp_name_col:
        st.error("Employee Code or Name column not found.")
        return
    df[emp_code_col] = df[emp_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
    all_codes = df[emp_code_col].tolist()
    selected_codes = st.multiselect("Select Employee Codes", options=all_codes)
    subject = st.text_input("Subject")
    message = st.text_area("Message")
    if st.button("Send to Selected Employees"):
        if not selected_codes:
            st.error("Please select at least one employee.")
            return
        if not subject.strip() or not message.strip():
            st.error("Subject and message cannot be empty.")
            return
        for code in selected_codes:
            add_notification("", "", f"Broadcast from HR: {subject} - {message}", recipient_code=code)
        # Confirmation message added
        show_confirmation_message("✅ Message sent to selected employees.")

def page_hr_queries(user):
    st.subheader("❓ HR Queries")
    if user.get("Title", "").upper() != "HR":
        st.error("Access denied. HR only.")
        return
    queries = load_hr_queries()
    if queries.empty:
        st.info("No queries received.")
        return
    queries = queries.sort_values(by="Date Sent", ascending=False).reset_index(drop=True)
    for idx, row in queries.iterrows():
        emp_code = row.get('Employee Code', '')
        emp_name = row.get('Employee Name', '') if pd.notna(row.get('Employee Name', '')) else ''
        subj = row.get('Subject', '') if pd.notna(row.get('Subject', '')) else ''
        msg = row.get("Message", '') if pd.notna(row.get("Message", '')) else ''
        status = row.get('Status', '') if pd.notna(row.get('Status', '')) else ''
        date_sent = row.get("Date Sent", '')
        reply_existing = row.get("Reply", '') if pd.notna(row.get("Reply", '')) else ''
        try:
            sent_time = pd.to_datetime(date_sent).strftime('%d-%m-%Y %H:%M')
        except Exception:
            sent_time = str(date_sent)
        card_html = f"""
        <div class="hr-message-card">
            <div class="hr-message-title">📌 {subj if subj else 'No Subject'}</div>
            <div class="hr-message-meta">👤 {emp_name} — {emp_code} &nbsp;|&nbsp; 🕒 {sent_time} &nbsp;|&nbsp; 🏷️ {status}</div>
            <div class="hr-message-body">{msg if msg else ''}</div>
        </div>
        """
        st.markdown(card_html, unsafe_allow_html=True)
        if reply_existing:
            st.markdown("**🟢 Existing reply:**")
            st.markdown(reply_existing)
        col1, col2 = st.columns([1, 4])
        with col1:
            new_status = st.selectbox("Status", ["Pending", "Resolved", "In Progress"], index=(["Pending", "Resolved", "In Progress"].index(status) if status in ["Pending", "Resolved", "In Progress"] else 0), key=f"status_{row['ID']}")
        with col2:
            reply_msg = st.text_area("Reply", value=reply_existing, key=f"reply_{row['ID']}")
        if st.button(f"Send Reply for Query #{row['ID']}", key=f"btn_reply_{row['ID']}"):
            queries.loc[queries["ID"] == row["ID"], "Reply"] = reply_msg
            queries.loc[queries["ID"] == row["ID"], "Status"] = new_status
            queries.loc[queries["ID"] == row["ID"], "Date Replied"] = datetime.now().strftime('%d-%m-%Y %H:%M')
            save_hr_queries(queries)
            add_notification("", "", f"HR replied to your query #{row['ID']}", recipient_code=emp_code)
            # Confirmation message added
            show_confirmation_message(f"✅ Reply sent for Query #{row['ID']}!")
            st.rerun()

def page_hr_requests(user):
    st.subheader("📄 HR Requests")
    if user.get("Title", "").upper() != "HR":
        st.error("Access denied. HR only.")
        return
    requests_df = load_hr_requests()
    if requests_df.empty:
        st.info("No requests received.")
        return
    requests_df = requests_df.sort_values(by="Date Sent", ascending=False).reset_index(drop=True)
    for idx, row in requests_df.iterrows():
        emp_code = row.get('Employee Code', '')
        emp_name = row.get('Employee Name', '') if pd.notna(row.get('Employee Name', '')) else ''
        request_text = row.get('Request', '') if pd.notna(row.get('Request', '')) else ''
        status = row.get('Status', '') if pd.notna(row.get('Status', '')) else ''
        date_sent = row.get("Date Sent", '')
        response_existing = row.get("Response", '') if pd.notna(row.get("Response", '')) else ''
        file_attached = row.get("File Attached", '')
        try:
            sent_time = pd.to_datetime(date_sent).strftime('%d-%m-%Y %H:%M')
        except Exception:
            sent_time = str(date_sent)
        card_html = f"""
        <div class="hr-message-card">
            <div class="hr-message-title">📋 Request #{row['ID']}</div>
            <div class="hr-message-meta">👤 {emp_name} — {emp_code} &nbsp;|&nbsp; 🕒 {sent_time} &nbsp;|&nbsp; 🏷️ {status}</div>
            <div class="hr-message-body">📄 <strong>Request:</strong> {request_text}</div>
            {f'<div class="hr-message-attachment">📎 <a href="/download/{file_attached}" target="_blank">Download Attachment</a></div>' if file_attached else ''}
        </div>
        """
        st.markdown(card_html, unsafe_allow_html=True)
        if response_existing:
            st.markdown("**🟢 Existing response:**")
            st.markdown(response_existing)
        col1, col2 = st.columns([1, 4])
        with col1:
            new_status = st.selectbox("Status", ["Pending", "Approved", "Rejected"], index=(["Pending", "Approved", "Rejected"].index(status) if status in ["Pending", "Approved", "Rejected"] else 0), key=f"req_status_{row['ID']}")
        with col2:
            response_msg = st.text_area("Response", value=response_existing, key=f"req_response_{row['ID']}")
        uploaded_resp_file = st.file_uploader(f"Attach Response File for Request #{row['ID']}", type=["pdf", "docx", "xlsx"], key=f"upload_resp_{row['ID']}")
        def save_response_file(uploaded_file, emp_code, req_id):
            filename = f"resp_{emp_code}_{req_id}_{uploaded_file.name}"
            filepath = os.path.join("hr_responses", filename)
            os.makedirs("hr_responses", exist_ok=True)
            with open(filepath, "wb") as f:
                f.write(uploaded_file.getbuffer())
            return filename
        if st.button(f"Send Response for Request #{row['ID']}", key=f"btn_req_reply_{row['ID']}"):
            resp_filename = ""
            if uploaded_resp_file:
                resp_filename = save_response_file(uploaded_resp_file, emp_code, row["ID"])
            requests_df.loc[requests_df["ID"] == row["ID"], "Response"] = response_msg
            requests_df.loc[requests_df["ID"] == row["ID"], "Response File"] = resp_filename
            requests_df.loc[requests_df["ID"] == row["ID"], "Status"] = new_status
            requests_df.loc[requests_df["ID"] == row["ID"], "Date Responded"] = datetime.now().strftime('%d-%m-%Y %H:%M')
            save_hr_requests(requests_df)
            add_notification("", "", f"HR responded to your request #{row['ID']}", recipient_code=emp_code)
            # Confirmation message added
            show_confirmation_message(f"✅ Response sent for Request #{row['ID']}!")
            st.rerun()

def page_idb_mr(user):
    st.subheader("🚀 IDB – Individual Development Blueprint")
    st.markdown("""<div style="background-color:#f0fdf4; padding:12px; border-radius:8px; border-left:4px solid #059669;"><p style="color:#05445E; font-weight:bold;">We want you to always aim higher — your success matters to us.</p></div>""", unsafe_allow_html=True)
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    user_name = user.get("Employee Name", user_code)
    departments = ["Sales", "Marketing", "HR", "SFE", "Distribution", "Market Access"]
    reports = load_idb_reports()
    existing = reports[reports["Employee Code"] == user_code]
    if not existing.empty:
        row = existing.iloc[0]
        selected_deps = eval(row["Selected Departments"]) if isinstance(row["Selected Departments"], str) else row["Selected Departments"]
        strengths = eval(row["Strengths"]) if isinstance(row["Strengths"], str) else row["Strengths"]
        development = eval(row["Development Areas"]) if isinstance(row["Development Areas"], str) else row["Development Areas"]
        action = row["Action Plan"]
    else:
        selected_deps = []
        strengths = ["", "", ""]
        development = ["", "", ""]
        action = ""
    with st.form("idb_form"):
        st.markdown("### 🔍 Select Target Departments (Max 2)")
        selected = st.multiselect("Choose up to 2 departments you're interested in:", options=departments, default=selected_deps)
        if len(selected) > 2:
            st.warning("⚠️ You can select a maximum of 2 departments.")
        st.markdown("### 💪 Area of Strength (3 points)")
        strength_inputs = []
        for i in range(3):
            val = strengths[i] if i < len(strengths) else ""
            strength_inputs.append(st.text_input(f"Strength {i+1}", value=val, key=f"str_{i}"))
        st.markdown("### 📈 Area of Development (3 points)")
        dev_inputs = []
        for i in range(3):
            val = development[i] if i < len(development) else ""
            dev_inputs.append(st.text_input(f"Development {i+1}", value=val, key=f"dev_{i}"))
        st.markdown("### 🤝 Action Plan (Agreed with your manager)")
        action_input = st.text_area("Action", value=action, height=100)
        submitted = st.form_submit_button("💾 Save IDB Report")
        if submitted:
            if len(selected) > 2:
                st.error("You cannot select more than 2 departments.")
            else:
                success = save_idb_report(
                    user_code,
                    user_name,  # ✅ FIXED: Added Employee Name
                    selected,
                    [s.strip() for s in strength_inputs if s.strip()],
                    [d.strip() for d in dev_inputs if d.strip()],
                    action_input.strip()
                )
                if success:
                    # Confirmation message added
                    show_confirmation_message("✅ IDB Report saved successfully!")
                    # ✅ FIXED: Send notification to HR + ALL managers (DM, AM, BUM)
                    add_notification("", "HR", f"MR {user_name} ({user_code}) updated their IDB report.")
                    add_notification("", "DM", f"MR {user_name} ({user_code}) updated their IDB report.")
                    add_notification("", "AM", f"MR {user_name} ({user_code}) updated their IDB report.")
                    add_notification("", "BUM", f"MR {user_name} ({user_code}) updated their IDB report.")
                    st.rerun()
                else:
                    st.error("❌ Failed to save report.")
    if not existing.empty:
        st.markdown("### 📊 Your Current IDB Report")
        display_data = {
            "Field": [
                "Selected Departments",
                "Strength 1", "Strength 2", "Strength 3",
                "Development 1", "Development 2", "Development 3",
                "Action Plan",
                "Updated At"
            ],
            "Value": [
                ", ".join(selected_deps),
                *(strengths + [""] * (3 - len(strengths))),
                *(development + [""] * (3 - len(development))),
                action,
                existing.iloc[0]["Updated At"]
            ]
        }
        display_df = pd.DataFrame(display_data)
        st.dataframe(display_df, use_container_width=True)

def page_leave_application(user):
    st.subheader("🏖️ Apply for Leave")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.error("No employee data available.")
        return
    code_col_map = {c.lower().strip(): c for c in df.columns}
    emp_code_col = code_col_map.get("employee_code") or code_col_map.get("employee code") or code_col_map.get("code")
    mgr_code_col = code_col_map.get("manager_code") or code_col_map.get("manager code") or code_col_map.get("reporting_to")
    if not emp_code_col or not mgr_code_col:
        st.error("Employee Code or Manager Code column not found.")
        return
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    user_row = df[df[emp_code_col] == user_code]
    if user_row.empty:
        st.error("Your record not found.")
        return
    manager_code = user_row.iloc[0][mgr_code_col]
    with st.form("leave_form"):
        start_date = st.date_input("Start Date")
        end_date = st.date_input("End Date")
        leave_type = st.selectbox("Leave Type", ["Annual", "Sick", "Emergency", "Unpaid"])
        reason = st.text_area("Reason")
        submitted = st.form_submit_button("Submit Leave Request")
        if submitted:
            if end_date < start_date:
                st.error("End date cannot be before start date.")
            else:
                new_row = pd.DataFrame([{
                    "Employee Code": user_code,
                    "Manager Code": manager_code,
                    "Start Date": pd.Timestamp(start_date),
                    "End Date": pd.Timestamp(end_date),
                    "Leave Type": leave_type,
                    "Reason": reason,
                    "Status": "Pending",
                    "Decision Date": None,
                    "Comment": ""
                }])
                leaves_df = load_leaves()
                leaves_df = pd.concat([leaves_df, new_row], ignore_index=True)
                save_leaves(leaves_df)
                add_notification("", manager_code, f"Leave request from {user.get('Employee Name', user_code)} ({user_code}).")
                # Confirmation message added
                show_confirmation_message("✅ Leave request submitted successfully!")

def page_manage_leaves(user):
    st.subheader("审批 Leaves")
    user_title = str(user.get("Title", "")).strip().upper()
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.error("No employee data available.")
        return
    code_col_map = {c.lower().strip(): c for c in df.columns}
    emp_code_col = code_col_map.get("employee_code") or code_col_map.get("employee code") or code_col_map.get("code")
    mgr_code_col = code_col_map.get("manager_code") or code_col_map.get("manager code") or code_col_map.get("reporting_to")
    emp_name_col = code_col_map.get("employee_name") or code_col_map.get("employee name") or code_col_map.get("name")
    if not all([emp_code_col, mgr_code_col, emp_name_col]):
        st.error("Required columns not found.")
        return
    df[emp_code_col] = df[emp_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
    if user_title in ["DM", "AM", "BUM"]:
        team_leaves = load_leaves()
        team_leaves["Employee Code"] = team_leaves["Employee Code"].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
        team_leaves = team_leaves.merge(
            df[[emp_code_col, emp_name_col]],
            left_on="Employee Code",
            right_on=emp_code_col,
            how="left"
        )
        name_col_to_use = emp_name_col
        if user_title == "DM":
            team_leaves_filtered = team_leaves[team_leaves[mgr_code_col] == user_code]
        elif user_title == "AM":
            # AM manages DMs and their teams
            dm_codes = df[(df[mgr_code_col] == user_code) & (df[code_col_map.get("title") or code_col_map.get("job title") or code_col_map.get("position")] == "DM")][emp_code_col].tolist()
            all_managed_codes = dm_codes[:]
            for dm_code in dm_codes:
                subordinates = df[df[mgr_code_col] == dm_code][emp_code_col].tolist()
                all_managed_codes.extend(subordinates)
            team_leaves_filtered = team_leaves[team_leaves["Employee Code"].isin(all_managed_codes)]
        elif user_title == "BUM":
            # BUM manages AMs, DMs and their teams
            am_dm_codes = df[(df[mgr_code_col] == user_code) | (df[mgr_code_col].isin(df[df[mgr_code_col] == user_code][emp_code_col]))][emp_code_col].tolist()
            all_managed_codes = am_dm_codes[:]
            for code in am_dm_codes:
                subordinates = df[df[mgr_code_col] == code][emp_code_col].tolist()
                all_managed_codes.extend(subordinates)
            team_leaves_filtered = team_leaves[team_leaves["Employee Code"].isin(all_managed_codes)]
        else:
            team_leaves_filtered = pd.DataFrame()
        pending_leaves = team_leaves_filtered[team_leaves_filtered["Status"] == "Pending"].reset_index(drop=True)
        st.markdown("### 🟡 Pending Requests")
        if not pending_leaves.empty:
            for idx, row in pending_leaves.iterrows():
                emp_name = row.get(name_col_to_use, "") if name_col_to_use in row else ""
                emp_display = f"{emp_name} ({row['Employee Code']})" if emp_name else row['Employee Code']
                with st.expander(f"Leave Request: {emp_display} - {row['Leave Type']} ({row['Start Date'].strftime('%d-%m-%Y')} to {row['End Date'].strftime('%d-%m-%Y')})"):
                    st.write(f"**Reason:** {row['Reason']}")
                    decision = st.radio("Decision", ("Approve", "Reject"), key=f"decision_{row.name}")
                    comment = st.text_input("Comment (optional)", key=f"comment_{row.name}")
                    if st.button(f"Submit Decision for {emp_display}", key=f"submit_decision_{row.name}"):
                        team_leaves.loc[team_leaves["Employee Code"] == row["Employee Code"], "Status"] = decision
                        team_leaves.loc[team_leaves["Employee Code"] == row["Employee Code"], "Comment"] = comment
                        team_leaves.loc[team_leaves["Employee Code"] == row["Employee Code"], "Decision Date"] = datetime.now()
                        save_leaves(team_leaves)
                        add_notification("", row["Employee Code"], f"Your leave request has been {decision.lower()}. Comment: {comment}")
                        # Confirmation message added
                        show_confirmation_message(f"✅ Decision '{decision}' submitted for {emp_display}!")
                        st.rerun()
        else:
            st.info("No pending leave requests.")
        st.markdown("---")
        st.markdown("### ✅ Approved / ❌ Rejected Requests")
        processed_leaves = team_leaves_filtered[team_leaves_filtered["Status"] != "Pending"].reset_index(drop=True)
        if not processed_leaves.empty:
            processed_leaves["Start Date"] = pd.to_datetime(processed_leaves["Start Date"]).dt.strftime("%d-%m-%Y")
            processed_leaves["End Date"] = pd.to_datetime(processed_leaves["End Date"]).dt.strftime("%d-%m-%Y")
            processed_leaves["Decision Date"] = pd.to_datetime(processed_leaves["Decision Date"]).dt.strftime("%d-%m-%Y")
            display_cols = [name_col_to_use, "Employee Code", "Start Date", "End Date", "Leave Type", "Reason", "Status", "Decision Date", "Comment"]
            st.dataframe(processed_leaves[display_cols], use_container_width=True)
        else:
            st.info("No processed requests.")
    else:
        st.error("Access denied. Only DM, AM, BUM can manage leaves.")

def page_recruitment(user):
    st.subheader("👥 Recruitment Management")
    if user.get("Title", "").upper() != "HR":
        st.error("Access denied. HR only.")
        return
    st.markdown(f"""<div style="background-color:white; padding:12px; border-radius:8px; border:1px solid #05445E; margin-bottom:20px;">
        <p style="color:#05445E; font-weight:bold;">Recruitment Database Management</p>
    </div>""", unsafe_allow_html=True)
    st.markdown("### Upload Recruitment Data from Google Forms")
    uploaded_db = st.file_uploader("Upload Excel from Google Forms", type=["xlsx"])
    if uploaded_db:
        try:
            new_db_df = pd.read_excel(uploaded_db)
            st.session_state["recruitment_preview"] = new_db_df.copy()
            st.success("File loaded successfully.")
            st.dataframe(new_db_df.head(10), use_container_width=True)
            if st.button("✅ Replace Recruitment Database"):
                save_recruitment_data(new_db_df)
                # Confirmation message added
                show_confirmation_message("Recruitment database updated!")
                st.rerun()
        except Exception as e:
            st.error(f"Error reading file: {e}")
    st.markdown("---")
    st.markdown("### Current Recruitment Database")
    db_df = load_recruitment_data()
    if not db_df.empty:
        st.dataframe(db_df, use_container_width=True)
        buf = BytesIO()
        with pd.ExcelWriter(buf, engine="openpyxl") as writer:
            db_df.to_excel(writer, index=False)
        buf.seek(0)
        st.download_button(
            "📥 Download Recruitment Database",
            data=buf,
            file_name="Recruitment_Data.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
    else:
        st.info("No recruitment data uploaded yet.")

def page_certificates(user):
    st.subheader("📜 My Certificates")
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    user_name = user.get("Employee Name", user_code)
    certs_df = load_certificates()
    user_certs = certs_df[certs_df["Employee Code"] == user_code].copy()
    st.markdown("### Upload New Certificate")
    uploaded_cert = st.file_uploader("Choose a certificate file", type=["pdf", "png", "jpg", "jpeg", "docx"])
    cert_name = st.text_input("Certificate Name")
    exp_date = st.date_input("Expiration Date (optional)")
    if st.button("Upload Certificate"):
        if not uploaded_cert or not cert_name:
            st.error("Please provide a file and a name.")
            return
        filename = f"cert_{user_code}_{cert_name.replace(' ', '_')}_{uploaded_cert.name}"
        filepath = os.path.join("certificates", filename)
        os.makedirs("certificates", exist_ok=True)
        with open(filepath, "wb") as f:
            f.write(uploaded_cert.getbuffer())
        new_cert = {
            "Employee Code": user_code,
            "Employee Name": user_name,
            "Certificate Name": cert_name,
            "File": filename,
            "Upload Date": datetime.now().strftime('%d-%m-%Y'),
            "Expiration Date": exp_date.strftime('%d-%m-%Y') if exp_date else "",
            "Status": "Active"
        }
        new_df = pd.DataFrame([new_cert])
        certs_df = pd.concat([certs_df, new_df], ignore_index=True)
        save_certificates(certs_df)
        # Confirmation message added
        show_confirmation_message("✅ Certificate uploaded successfully!")
        st.rerun()
    st.markdown("### My Uploaded Certificates")
    if not user_certs.empty:
        for idx, row in user_certs.iterrows():
            with st.container():
                st.markdown(f"**Name:** {row['Certificate Name']}")
                st.markdown(f"**Uploaded:** {row['Upload Date']}")
                st.markdown(f"**Expires:** {row['Expiration Date'] if row['Expiration Date'] else 'N/A'}")
                st.markdown(f"**Status:** {row['Status']}")
                file_path = os.path.join("certificates", row["File"])
                if os.path.exists(file_path):
                    with open(file_path, "rb") as f:
                        st.download_button(
                            label=f"📥 Download {row['File']}",
                            data=f,
                            file_name=row["File"], # Same original filename
                            mime="application/octet-stream", # Generic format preserving file type
                            key=f"dl_cert_{idx}"
                        )
                else:
                    st.warning("File not found.")
                st.markdown("---")
    else:
        st.info("📭 No certificates uploaded.")

