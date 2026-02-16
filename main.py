# ============================
# PAGE: My Team
# ============================
def build_team_hierarchy_recursive(df, manager_code, manager_title="AM"):
    emp_code_col = "Employee Code"
    emp_name_col = "Employee Name"
    mgr_code_col = "Manager Code"
    title_col = "Title"
    required_cols = [emp_code_col, emp_name_col, mgr_code_col, title_col]
    if not all(col in df.columns for col in required_cols):
        missing = [col for col in required_cols if col not in df.columns]
        st.warning(f"Missing required columns: {missing}")
        return {}
    df = df.copy()
    df[emp_code_col] = df[emp_code_col].astype(str).str.strip().str.replace('.0', '', regex=False)
    df[mgr_code_col] = df[mgr_code_col].astype(str).str.strip().str.replace('.0', '', regex=False)
    df[title_col] = df[title_col].astype(str).str.strip().str.upper()
    mgr_row = df[df[emp_code_col] == str(manager_code)]
    if mgr_row.empty:
        st.warning(f"Manager with code {manager_code} not found in data.")
        return {}
    mgr_name = mgr_row.iloc[0][emp_name_col]
    current_title = mgr_row.iloc[0][title_col]
    if current_title == "BUM":
        subordinate_types = ["AM", "DM"]
    elif current_title == "AM":
        subordinate_types = ["DM"]
    elif current_title == "DM":
        subordinate_types = ["MR"]
    else:
        subordinate_types = []
    direct_subs = df[df[mgr_code_col] == str(manager_code)]
    if subordinate_types:
        direct_subs = direct_subs[direct_subs[title_col].isin(subordinate_types)]
    node = {
        "Manager": f"{mgr_name} ({current_title})",
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
        node["Summary"]["Total"] = node["Summary"]["AM"] + node["Summary"]["DM"] + node["Summary"]["MR"]
    else:
        node["Summary"] = {"AM":0, "DM":0, "MR":0, "Total":0}
    return node

def page_my_team(user, role="AM"):
    st.subheader("My Team Structure")
    user_code = None
    for key, val in user.items():
        if key == "Employee Code":
            user_code = str(val).strip().replace(".0", "")
            break
    if not user_code:
        st.error("Your Employee Code not found.")
        return
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.error("Employee data not loaded.")
        return
    hierarchy = build_team_hierarchy_recursive(df, user_code, role.upper())
    if not hierarchy:
        st.info(f"Could not build team structure for your code: {user_code}. Check your manager assignment or title.")
        return
    ROLE_ICONS = {
        "BUM": "🏢",
        "AM": "👨‍💼",
        "DM": "👩‍💼",
        "MR": "🧑‍⚕️"
    }
    ROLE_COLORS = {
        "BUM": "#05445E",
        "AM": "#05445E",
        "DM": "#0A5C73",
        "MR": "#dc2626"
    }
    st.markdown("""
    <style>
    .team-node {
        background-color: #FFFFFF;
        border-left: 4px solid #05445E;
        padding: 12px;
        margin: 8px 0;
        border-radius: 6px;
        box-shadow: 0 2px 6px rgba(0,0,0,0.05);
    }
    .team-node-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        font-weight: 600;
        color: #05445E;
        margin-bottom: 8px;
    }
    .team-node-summary {
        font-size: 0.9rem;
        color: #666666;
        margin-top: 4px;
    }
    .team-node-children {
        margin-left: 20px;
        margin-top: 8px;
    }
    .team-member {
        display: flex;
        align-items: center;
        padding: 6px 12px;
        background-color: #f8fafc;
        border-radius: 4px;
        margin: 4px 0;
        font-size: 0.95rem;
    }
    .team-member-icon {
        margin-right: 8px;
        font-size: 1.1rem;
    }
    </style>
    """, unsafe_allow_html=True)
    user_title = role.upper()
    if user_title == "BUM":
        st.markdown("### Team Structure Summary")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown(f"""
            <div class="team-structure-card">
            <div class="team-structure-title">AM Count</div>
            <div class="team-structure-value am">{hierarchy['Summary']['AM']}</div>
            </div>
            """, unsafe_allow_html=True)
        with col2:
            st.markdown(f"""
            <div class="team-structure-card">
            <div class="team-structure-title">DM Count</div>
            <div class="team-structure-value dm">{hierarchy['Summary']['DM']}</div>
            </div>
            """, unsafe_allow_html=True)
        with col3:
            st.markdown(f"""
            <div class="team-structure-card">
            <div class="team-structure-title">MR Count</div>
            <div class="team-structure-value mr">{hierarchy['Summary']['MR']}</div>
            </div>
            """, unsafe_allow_html=True)
    elif user_title == "AM":
        st.markdown("### Team Structure Summary")
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"""
            <div class="team-structure-card">
            <div class="team-structure-title">DM Count</div>
            <div class="team-structure-value dm">{hierarchy['Summary']['DM']}</div>
            </div>
            """, unsafe_allow_html=True)
        with col2:
            st.markdown(f"""
            <div class="team-structure-card">
            <div class="team-structure-title">MR Count</div>
            <div class="team-structure-value mr">{hierarchy['Summary']['MR']}</div>
            </div>
            """, unsafe_allow_html=True)
    def render_tree(node, level=0, is_last_child=False):
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
        summary_str = " | ".join(summary_parts) if summary_parts else "No direct reports"
        manager_info = node.get("Manager", "Unknown")
        manager_code = node.get("Manager Code", "N/A")
        role = "MR"
        if "(" in manager_info and ")" in manager_info:
            role_part = manager_info.split("(")[-1].split(")")[0].strip()
            if role_part in ROLE_ICONS:
                role = role_part
        icon = ROLE_ICONS.get(role, "👤")
        color = ROLE_COLORS.get(role, "#2E2E2E")
        prefix = ""
        if level > 0:
            for i in range(level - 1):
                prefix += "│   "
            if is_last_child:
                prefix += "└── "
            else:
                prefix += "├── "
        st.markdown(f"""
        <div class="team-node">
        <div class="team-node-header">
        <span style="color: {color};">{prefix}{icon} <strong>{manager_info}</strong> (Code: {manager_code})</span>
        <span class="team-node-summary">{summary_str}</span>
        </div>
        """, unsafe_allow_html=True)
        if node.get("Team"):
            st.markdown('<div class="team-node-children">', unsafe_allow_html=True)
            team_count = len(node.get("Team", []))
            for i, team_member in enumerate(node.get("Team", [])):
                is_last = (i == team_count - 1)
                render_tree(team_member, level + 1, is_last)
            st.markdown('</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
    render_tree(hierarchy, 0, True)
    if not hierarchy.get("Team"):
        root_manager_info = hierarchy.get("Manager", "Unknown")
        root_manager_code = hierarchy.get("Manager Code", "N/A")
        role = "MR"
        if "(" in root_manager_info and ")" in root_manager_info:
            role_part = root_manager_info.split("(")[-1].split(")")[0].strip()
            if role_part in ROLE_ICONS:
                role = role_part
        icon = ROLE_ICONS.get(role, "👤")
        color = ROLE_COLORS.get(role, "#2E2E2E")
        st.markdown(f'<span style="color: {color};">{icon} <strong>{root_manager_info}</strong> (Code: {root_manager_code})</span>', unsafe_allow_html=True)
        st.info("No direct subordinates found under your supervision.")

# ============================
# PAGE: Directory
# ============================
def page_directory(user):
    st.subheader("Company Structure")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.info("Employee data not loaded.")
        return
    st.info("Search and filter employees below.")
    COLUMNS_TO_SHOW = [
        "Employee Code",
        "Employee Name",
        "Manager Name",
        "Title",
        "Mobile",
        "Department",
        "E-Mail",
        "Address as 702 bricks"
    ]
    col_map = {c.lower().strip(): c for c in df.columns}
    final_columns = []
    for col_name in COLUMNS_TO_SHOW:
        variations = [
            col_name.lower().replace(' ', '_'),
            col_name.lower().replace(' ', ''),
            col_name.lower(),
            col_name
        ]
        found_col = None
        for var in variations:
            if var in col_map:
                found_col = col_map[var]
                break
        if found_col:
            final_columns.append(found_col)
    col1, col2 = st.columns(2)
    with col1:
        search_name = st.text_input("Search by Employee Name")
    with col2:
        search_code = st.text_input("Search by Employee Code")
    filtered_df = df.copy()
    if search_name:
        emp_name_col = None
        for col in df.columns:
            if col.lower().replace(" ", "_").replace("-", "_") in ["employee_name", "name", "employee name", "full name", "first name"]:
                emp_name_col = col
                break
        if emp_name_col:
            filtered_df = filtered_df[filtered_df[emp_name_col].astype(str).str.contains(search_name, case=False, na=False)]
    if search_code:
        emp_code_col = None
        for col in df.columns:
            if col.lower().replace(" ", "_").replace("-", "_") in ["employee_code", "code", "employee code", "emp_code"]:
                emp_code_col = col
                break
        if emp_code_col:
            filtered_df = filtered_df[filtered_df[emp_code_col].astype(str).str.contains(search_code, case=False, na=False)]
    if final_columns:
        display_df = filtered_df[final_columns].copy()
        st.dataframe(display_df, use_container_width=True)
        st.info(f"Showing {len(display_df)} of {len(df)} employees.")
    else:
        st.error("No columns could be mapped for display. Please check your Excel sheet headers.")

# ============================
# PAGE: Ask HR
# ============================
def page_ask_hr(user):
    st.subheader("💬 Ask HR")
    if user is None:
        st.error("User session not found. Please login.")
        return
    user_code = None
    user_name = None
    for key, val in user.items():
        if key.lower().replace(" ", "").replace("_", "") in ["employeecode", "employee_code"]:
            user_code = str(val).strip().replace(".0", "")
        if key.lower().replace(" ", "").replace("_", "") in ["employeename", "employee_name", "name"]:
            user_name = str(val).strip()
    if not user_code:
        st.error("Your Employee Code not found in session.")
        return
    if not user_name:
        user_name = user_code
    hr_df = load_hr_queries()
    with st.form("ask_hr_form"):
        subj = st.text_input("Subject")
        msg = st.text_area("Message", height=160)
        submitted = st.form_submit_button("Send to HR")
        if submitted:
            if not subj.strip() or not msg.strip():
                st.warning("Please fill both Subject and Message.")
            else:
                new_row = pd.DataFrame([{
                    "Employee Code": user_code,
                    "Employee Name": user_name,
                    "Subject": subj.strip(),
                    "Message": msg.strip(),
                    "Reply": "",
                    "Status": "Pending",
                    "Date Sent": pd.Timestamp.now(),
                    "Date Replied": pd.NaT
                }])
                if hr_df is None or hr_df.empty:
                    hr_df = new_row
                else:
                    hr_df = pd.concat([hr_df, new_row], ignore_index=True)
                if save_hr_queries(hr_df):
                    st.success("✅ Your message was sent to HR.")
                    add_notification("", "HR", f"New Ask HR from {user_name} ({user_code})")
                    st.rerun()
                else:
                    st.error("❌ Failed to save message. Check server permissions.")
    st.markdown("### 📜 Your previous messages")
    if hr_df is None or hr_df.empty:
        st.info("No messages found.")
        return
    try:
        hr_df["Date Sent_dt"] = pd.to_datetime(hr_df["Date Sent"], errors="coerce")
        my_msgs = hr_df[hr_df["Employee Code"].astype(str).str.strip() == str(user_code)].sort_values("Date Sent_dt", ascending=False).reset_index(drop=True)
    except Exception:
        my_msgs = hr_df[hr_df["Employee Code"].astype(str).str.strip() == str(user_code)].reset_index(drop=True)
    if my_msgs.empty:
        st.info("You have not sent any messages yet.")
        return
    for idx, row in my_msgs.iterrows():
        subj = row.get("Subject", "")
        msg = row.get("Message", "")
        reply = row.get("Reply", "")
        status = row.get("Status", "")
        date_sent = row.get("Date Sent", "")
        try:
            sent_time = pd.to_datetime(date_sent).strftime('%d-%m-%Y %H:%M')
        except Exception:
            sent_time = str(date_sent)
        message_html = f"""
        <div class='hr-message-card'>
        <div class='hr-message-title'>{subj}</div>
        <div class='hr-message-meta'>Sent: {sent_time} — Status: {status}</div>
        <div class='hr-message-body'>{msg}</div>
        </div>
        """
        st.markdown(message_html, unsafe_allow_html=True)
        if pd.notna(reply) and str(reply).strip() != "":
            st.markdown("**🟢 HR Reply:**")
            st.markdown(reply)
        else:
            st.markdown("**🕒 HR Reply:** Pending")
        st.markdown("---")

# ============================
# PAGE: HR Inbox
# ============================
def page_hr_inbox(user):
    st.subheader("📬 HR Inbox")
    st.markdown("View employee queries and reply to them here.")
    hr_df = load_hr_queries()
    if hr_df is None or hr_df.empty:
        st.info("No Ask HR messages.")
        return
    try:
        hr_df["Date Sent_dt"] = pd.to_datetime(hr_df["Date Sent"], errors="coerce")
        hr_df = hr_df.sort_values("Date Sent_dt", ascending=False).reset_index(drop=True)
    except Exception:
        hr_df = hr_df.reset_index(drop=True)
    for idx, row in hr_df.iterrows():
        emp_code = str(row.get('Employee Code', ''))
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
        reply_text = st.text_area("✍️ Write reply here:", value="", key=f"reply_{idx}", height=120)
        col1, col2, col3 = st.columns([2, 2, 1])
        with col1:
            if st.button("✅ Send Reply", key=f"send_reply_{idx}"):
                try:
                    hr_df.at[idx, "Reply"] = reply_text
                    hr_df.at[idx, "Status"] = "Replied"
                    hr_df.at[idx, "Date Replied"] = pd.Timestamp.now()
                    save_hr_queries(hr_df)
                    add_notification(emp_code, "", f"HR replied to your message: {subj}")
                    st.success("✅ Reply sent and employee notified.")
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ Failed to send reply: {e}")
        with col2:
            if st.button("🗂️ Mark as Closed", key=f"close_bottom_{idx}"):
                try:
                    hr_df.at[idx, "Status"] = "Closed"
                    hr_df.at[idx, "Date Replied"] = pd.Timestamp.now()
                    save_hr_queries(hr_df)
                    st.success("✅ Message marked as closed.")
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ Failed to close message: {e}")
        with col3:
            if st.button("🗑️ Delete", key=f"del_inbox_{idx}"):
                hr_df = hr_df.drop(idx).reset_index(drop=True)
                save_hr_queries(hr_df)
                st.success("Message deleted!")
                st.rerun()
        st.markdown("---")

# ============================
# PAGE: Ask Employees
# ============================
def save_request_file(uploaded_file, employee_code, request_id):
    os.makedirs("hr_request_files", exist_ok=True)
    ext = uploaded_file.name.split(".")[-1].lower()
    filename = f"req_{request_id}_emp_{employee_code}.{ext}"
    filepath = os.path.join("hr_request_files", filename)
    with open(filepath, "wb") as f:
        f.write(uploaded_file.getbuffer())
    return filename

def page_ask_employees(user):
    st.subheader("📤 Ask Employees")
    st.info("🔍 Type employee name or code to search. HR can send requests with file attachments.")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.error("Employee data not loaded.")
        return
    col_map = {c.lower().strip(): c for c in df.columns}
    code_col_options = ["employee_code", "employee code", "emp code", "code", "employeeid", "emp_id"]
    code_col = None
    for opt in code_col_options:
        if opt in col_map:
            code_col = col_map[opt]
            break
    if not code_col:
        st.error("Could not find any column for Employee Code. Please check your Excel sheet headers.")
        return
    name_col_options = ["employee_name", "employee name", "name", "emp name", "full name", "first name"]
    name_col = None
    for opt in name_col_options:
        if opt in col_map:
            name_col = col_map[opt]
            break
    if not name_col:
        st.error("Could not find any column for Employee Name. Please check your Excel sheet headers.")
        return
    df[code_col] = df[code_col].astype(str).str.strip()
    df[name_col] = df[name_col].astype(str).str.strip()
    emp_options = df[[code_col, name_col]].copy()
    emp_options["Display"] = emp_options[name_col] + " (Code: " + emp_options[code_col] + ")"
    st.markdown("### 🔍 Search Employee by Name or Code")
    search_term = st.text_input("Type employee name or code to search...")
    filtered_options = emp_options.copy()
    if search_term:
        try:
            mask = (
                emp_options[name_col].str.contains(search_term, case=False, na=False) |
                emp_options[code_col].str.contains(search_term, case=False, na=False)
            )
            filtered_options = emp_options[mask].copy()
            if filtered_options.empty:
                st.warning("No employee found matching your search.")
                return
        except Exception as e:
            st.warning(f"Search error: {e}. Showing all employees.")
            filtered_options = emp_options.copy()
    if len(filtered_options) == 1:
        selected_row = filtered_options.iloc[0]
    elif len(filtered_options) > 1:
        selected_display = st.selectbox("Select Employee", filtered_options["Display"].tolist())
        selected_row = filtered_options[filtered_options["Display"] == selected_display].iloc[0]
    else:
        return
    selected_code = selected_row[code_col]
    selected_name = selected_row[name_col]
    st.success(f"✅ Selected: {selected_name} (Code: {selected_code})")
    request_text = st.text_area("Request Details", height=100)
    uploaded_file = st.file_uploader("Attach File (Optional)", type=["pdf", "docx", "xlsx", "jpg", "png"])
    if st.button("Send Request"):
        if not request_text.strip():
            st.warning("Please enter a request message.")
            return
        hr_code = str(user.get("Employee Code", "N/A")).strip().replace(".0", "")
        requests_df = load_hr_requests()
        new_id = int(requests_df["ID"].max()) + 1 if "ID" in requests_df.columns and not requests_df.empty else 1
        file_attached = ""
        if uploaded_file:
            file_attached = save_request_file(uploaded_file, selected_code, new_id)
        new_row = pd.DataFrame([{
            "ID": new_id,
            "HR Code": hr_code,
            "Employee Code": selected_code,
            "Employee Name": selected_name,
            "Request": request_text.strip(),
            "File Attached": file_attached,
            "Status": "Pending",
            "Response": "",
            "Response File": "",
            "Date Sent": pd.Timestamp.now(),
            "Date Responded": pd.NaT
        }])
        requests_df = pd.concat([requests_df, new_row], ignore_index=True)
        save_hr_requests(requests_df)
        add_notification(selected_code, "", f"HR has sent you a new request (ID: {new_id}). Check 'Request HR' page.")
        st.success(f"Request sent to {selected_name} (Code: {selected_code}) successfully.")
        st.rerun()

# ============================
# PAGE: Request HR
# ============================
def save_response_file(uploaded_file, employee_code, request_id):
    os.makedirs("hr_response_files", exist_ok=True)
    ext = uploaded_file.name.split(".")[-1].lower()
    filename = f"resp_{request_id}_emp_{employee_code}.{ext}"
    filepath = os.path.join("hr_response_files", filename)
    with open(filepath, "wb") as f:
        f.write(uploaded_file.getbuffer())
    return filename

def page_request_hr(user):
    st.subheader("📥 Request HR")
    st.info("Here you can respond to requests sent by HR. You can upload files as response.")
    user_code = str(user.get("Employee Code", "N/A")).strip().replace(".0", "")
    requests_df = load_hr_requests()
    if requests_df.empty:
        st.info("No requests from HR.")
        return
    user_requests = requests_df[requests_df["Employee Code"].astype(str) == user_code].copy()
    if user_requests.empty:
        st.info("No requests from HR for you.")
        return
    user_requests = user_requests.sort_values("Date Sent", ascending=False).reset_index(drop=True)
    for idx, row in user_requests.iterrows():
        st.markdown(f"### 📄 Request ID: {row['ID']}")
        st.write(f"**From HR:** {row['Request']}")
        date_sent_val = row.get("Date Sent")
        if pd.notna(date_sent_val) and date_sent_val != pd.NaT:
            try:
                formatted_date = pd.to_datetime(date_sent_val).strftime('%d-%m-%Y %H:%M')
                st.write(f"**Date Sent:** {formatted_date}")
            except Exception:
                st.write("**Date Sent:** Not available")
        else:
            st.write("**Date Sent:** Not available")
        file_attached = row.get("File Attached", "")
        if pd.notna(file_attached) and isinstance(file_attached, str) and file_attached.strip() != "":
            filepath = os.path.join("hr_request_files", file_attached)
            if os.path.exists(filepath):
                with open(filepath, "rb") as f:
                    st.download_button("📥 Download Attached File", f, file_name=file_attached, key=f"dl_req_{idx}")
            else:
                st.warning("The attached file does not exist on the server.")
        else:
            st.info("No file was attached to this request.")
        if row["Status"] == "Completed":
            st.success("✅ This request has been responded to.")
            response_file = row.get("Response File", "")
            if pd.notna(response_file) and isinstance(response_file, str) and response_file.strip() != "":
                resp_path = os.path.join("hr_response_files", response_file)
                if os.path.exists(resp_path):
                    with open(resp_path, "rb") as f:
                        st.download_button("📥 Download Your Response", f, file_name=response_file, key=f"dl_resp_{idx}")
                else:
                    st.warning("Your response file does not exist on the server.")
            continue
        st.markdown("---")
        response_text = st.text_area("Your Response", key=f"resp_text_{idx}")
        uploaded_resp_file = st.file_uploader("Attach Response File (Optional)", type=["pdf", "docx", "xlsx", "jpg", "png"], key=f"resp_file_{idx}")
        if st.button("Submit Response", key=f"submit_resp_{idx}"):
            if not response_text.strip() and not uploaded_resp_file:
                st.warning("Please provide a response or attach a file.")
                continue
            requests_df.loc[requests_df["ID"] == row["ID"], "Response"] = response_text.strip()
            requests_df.loc[requests_df["ID"] == row["ID"], "Status"] = "Completed"
            requests_df.loc[requests_df["ID"] == row["ID"], "Date Responded"] = pd.Timestamp.now()
            response_file_name = ""
            if uploaded_resp_file:
                resp_filename = save_response_file(uploaded_resp_file, user_code, row["ID"])
                response_file_name = resp_filename
            save_hr_requests(requests_df)
            add_notification("", "HR", f"Employee {user_code} responded to request ID {row['ID']}.")
            st.success("Response submitted successfully.")
            st.rerun()

# ============================
# PAGE: Dashboard
# ============================
def page_dashboard(user):
    st.subheader("Dashboard")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.info("No employee data available.")
        return
    col_map = {c.lower(): c for c in df.columns}
    dept_col = col_map.get("department")
    hire_col = col_map.get("hire date") or col_map.get("hire_date") or col_map.get("hiring date")
    total_employees = df.shape[0]
    total_departments = df[dept_col].nunique() if dept_col else 0
    new_hires = 0
    if hire_col:
        try:
            df[hire_col] = pd.to_datetime(df[hire_col], errors="coerce")
            new_hires = df[df[hire_col] >= (pd.Timestamp.now() - pd.Timedelta(days=30))].shape[0]
        except Exception:
            new_hires = 0
    c1, c2, c3 = st.columns(3)
    c1.metric("Total Employees", total_employees)
    c2.metric("Departments", total_departments)
    c3.metric("New Hires (30 days)", new_hires)
    st.markdown("---")
    st.markdown("### Employees per Department (table)")
    if dept_col:
        dept_counts = df[dept_col].fillna("Unknown").value_counts().reset_index()
        dept_counts.columns = ["Department", "Employee Count"]
        st.table(dept_counts.sort_values("Employee Count", ascending=False).reset_index(drop=True))
    else:
        st.info("Department column not found.")
    st.markdown("---")
    buf = BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Employees")
    buf.seek(0)
    st.download_button("Download Full Employees Excel", data=buf, file_name="employees_export.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    if st.button("Save & Push current dataset to GitHub"):
        saved, pushed = save_and_maybe_push(df, actor=user.get("Employee Name","HR"))
        if saved:
            if pushed:
                st.success("Saved locally and pushed to GitHub.")
            else:
                if GITHUB_TOKEN:
                    st.warning("Saved locally but GitHub push failed.")
                else:
                    st.info("Saved locally. GitHub not configured.")
        else:
            st.error("Failed to save dataset locally.")

# ============================
# PAGE: Reports
# ============================
def page_reports(user):
    st.subheader("Reports (Placeholder)")
    st.info("Reports section - ready to be expanded.")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.info("No data to report.")
        return
    st.markdown("Basic preview of dataset:")
    st.dataframe(df.head(200), use_container_width=True)
    buf = BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Employees")
    buf.seek(0)
    st.download_button("Export Report Data (Excel)", data=buf, file_name="report_employees.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

# ============================
# PAGE: HR Manager
# ============================
def page_hr_manager(user):
    st.subheader("HR Manager")
    st.info("Upload new employee sheet, manage employees, and perform administrative actions.")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.error("Employee data not loaded.")
        return
    st.markdown("### 🔑 Reset Employee Password")
    st.warning("This will invalidate the current password. The employee must use 'Change Password (No Login)' to set a new one.")
    with st.form("reset_password_form"):
        emp_code_reset = st.text_input("Enter Employee Code to Reset Password")
        reset_submitted = st.form_submit_button("🔐 Reset Password")
        if reset_submitted:
            if not emp_code_reset.strip():
                st.error("Please enter a valid Employee Code.")
            else:
                emp_code_clean = emp_code_reset.strip().replace(".0", "")
                hashes = load_password_hashes()
                if emp_code_clean in hashes:
                    del hashes[emp_code_clean]
                    save_password_hashes(hashes)
                    
                    # Also remove from MySQL
                    try:
                        query = "UPDATE employees SET password_hash = NULL WHERE employee_code = %s"
                        execute_query(query, (emp_code_clean,), commit=True)
                    except:
                        pass
                        
                    st.success(f"✅ Password for Employee {emp_code_clean} has been reset. Employee must set a new password using the external link.")
                    add_notification(emp_code_clean, "", "Your password was reset by HR. Please set a new password using the 'Change Password (No Login)' link on the login page.")
                else:
                    col_map = {c.lower().strip(): c for c in df.columns}
                    code_col = col_map.get("employee_code") or col_map.get("employee code")
                    if code_col:
                        df[code_col] = df[code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
                        if emp_code_clean in df[code_col].values:
                            st.success(f"✅ Employee {emp_code_clean} marked for password reset. They can now set a new password.")
                            add_notification(emp_code_clean, "", "Your account is ready for a new password. Use the 'Change Password (No Login)' link.")
                        else:
                            st.error("Employee code not found in company database.")
                    else:
                        st.error("Employee code column not found.")
    st.markdown("---")
    st.markdown("### 📊 HR: Detailed Leave Report for All Employees")
    leaves_df_all = load_leaves_data()
    df_emp_global = st.session_state.get("df", pd.DataFrame())
    if not df_emp_global.empty and not leaves_df_all.empty:
        col_map = {c.lower().strip(): c for c in df_emp_global.columns}
        emp_code_col = col_map.get("employee_code") or col_map.get("employee code")
        emp_name_col = col_map.get("employee_name") or col_map.get("employee name") or col_map.get("name")
        mgr_code_col = col_map.get("manager_code") or col_map.get("manager code")
        if emp_code_col and emp_name_col and mgr_code_col:
            leaves_df_all["Employee Code"] = leaves_df_all["Employee Code"].astype(str).str.strip()
            leaves_df_all["Manager Code"] = leaves_df_all["Manager Code"].astype(str).str.strip()
            df_emp_global[emp_code_col] = df_emp_global[emp_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
            df_emp_global[mgr_code_col] = df_emp_global[mgr_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
            leaves_with_names = leaves_df_all.merge(
                df_emp_global[[emp_code_col, emp_name_col]].rename(columns={emp_code_col: "Employee Code", emp_name_col: "Employee Name"}),
                on="Employee Code", how="left"
            )
            leaves_with_names = leaves_with_names.merge(
                df_emp_global[[emp_code_col, emp_name_col]].rename(columns={emp_code_col: "Manager Code", emp_name_col: "Manager Name"}),
                on="Manager Code", how="left"
            )
            leaves_with_names["Start Date"] = pd.to_datetime(leaves_with_names["Start Date"]).dt.strftime("%d-%m-%Y")
            leaves_with_names["End Date"] = pd.to_datetime(leaves_with_names["End Date"]).dt.strftime("%d-%m-%Y")
            leaves_with_names["Annual Balance"] = 21
            leaves_with_names["Used Days"] = 0
            leaves_with_names["Remaining Days"] = 21
            unique_employees = leaves_with_names["Employee Code"].unique()
            for emp_code in unique_employees:
                _, used, remaining = calculate_leave_balance(emp_code, leaves_df_all)
                mask = leaves_with_names["Employee Code"] == emp_code
                leaves_with_names.loc[mask, "Used Days"] = used
                leaves_with_names.loc[mask, "Remaining Days"] = remaining
            st.dataframe(leaves_with_names[[
                "Employee Name", "Employee Code", "Start Date", "End Date", "Leave Type", "Status", "Comment", "Manager Name", "Manager Code", "Annual Balance", "Used Days", "Remaining Days"
            ]], use_container_width=True)
        else:
            st.warning("Required columns (Employee Code, Employee Name, Manager Code) not found in employee data for detailed report.")
    else:
        st.info("No employee or leave data available for the detailed report.")
    st.markdown("---")
    st.markdown("### Upload Employees Excel (will replace current dataset)")
    uploaded_file = st.file_uploader("Upload Excel file (.xlsx) to replace the current employees dataset", type=["xlsx"])
    if uploaded_file:
        try:
            new_df = pd.read_excel(uploaded_file)
            new_df = sanitize_employee_data(new_df)
            st.session_state["uploaded_df_preview"] = new_df.copy()
            st.success("File loaded and sanitized. Preview below.")
            st.dataframe(new_df.head(50), use_container_width=True)
            st.markdown("**Note:** Uploading will replace the current dataset in-memory.")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Replace In-Memory Dataset with Uploaded File"):
                    st.session_state["df"] = new_df.copy()
                    initialize_passwords_from_data(new_df.to_dict(orient='records'))
                    
                    # Also save to MySQL
                    save_all_employees_to_mysql(new_df)
                    
                    st.success("In-memory dataset replaced and password hashes updated.")
            with col2:
                if st.button("Preview only (do not replace)"):
                    st.info("Preview shown above.")
        except Exception as e:
            st.error(f"Failed to read uploaded file: {e}")
    st.markdown("---")
    st.markdown("### Manage Employees (Edit / Delete)")
    if df.empty:
        st.info("Dataset empty. Upload or load data first.")
        return
    st.dataframe(df.head(100), use_container_width=True)
    col_map = {c.lower(): c for c in df.columns}
    code_col = col_map.get("employee_code") or list(df.columns)[0]
    selected_code = st.text_input("Enter employee code to edit/delete (exact match)", value="")
    if selected_code:
        matched_rows = df[df[code_col].astype(str) == str(selected_code).strip()]
        if matched_rows.empty:
            st.warning("No employee found with that code.")
        else:
            row = matched_rows.iloc[0]
            st.markdown("#### Edit Employee")
            with st.form("edit_employee_form"):
                updated = {}
                for col in df.columns:
                    val = row[col]
                    if pd.isna(val):
                        val = ""
                    if isinstance(val, (int, float)) and not isinstance(val, bool):
                        try:
                            updated[col] = st.number_input(label=str(col), value=float(val) if pd.notna(val) else 0.0, key=f"edit_{col}")
                        except Exception:
                            updated[col] = st.text_input(label=str(col), value=str(val), key=f"edit_{col}")
                    elif "date" in str(col).lower():
                        try:
                            date_val = pd.to_datetime(val, errors="coerce")
                        except Exception:
                            date_val = None
                        try:
                            updated[col] = st.date_input(label=str(col), value=date_val.date() if date_val is not None and pd.notna(date_val) else datetime.date.today(), key=f"edit_{col}_date")
                        except Exception:
                            updated[col] = st.text_input(label=str(col), value=str(val), key=f"edit_{col}")
                    else:
                        updated[col] = st.text_input(label=str(col), value=str(val), key=f"edit_{col}")
                submitted_edit = st.form_submit_button("Save Changes")
                if submitted_edit:
                    for k, v in updated.items():
                        if isinstance(v, datetime.date):
                            v = pd.Timestamp(v)
                        df.loc[df[code_col].astype(str) == str(selected_code).strip(), k] = v
                    st.session_state["df"] = df
                    
                    # Save to MySQL
                    save_employee_to_mysql(row.to_dict())
                    
                    saved, pushed = save_and_maybe_push(df, actor=user.get("Employee Name","HR"))
                    if saved:
                        st.success("Employee updated and saved locally.")
                        if pushed:
                            st.success("Changes pushed to GitHub.")
                        else:
                            if GITHUB_TOKEN:
                                st.warning("Saved locally but GitHub push failed.")
                            else:
                                st.info("Saved locally. GitHub not configured.")
                    else:
                        st.error("Failed to save changes locally.")
            st.markdown("#### Delete Employee")
            if st.button("Initiate Delete"):
                st.session_state["delete_target"] = str(selected_code).strip()
            if st.session_state.get("delete_target") == str(selected_code).strip():
                st.warning(f"You are about to delete employee with code: {selected_code}.")
                col_del1, col_del2 = st.columns(2)
                with col_del1:
                    if st.button("Confirm Delete"):
                        st.session_state["df"] = df[df[code_col].astype(str) != str(selected_code).strip()].reset_index(drop=True)
                        
                        # Delete from MySQL
                        delete_employee_from_mysql(str(selected_code).strip())
                        
                        saved, pushed = save_and_maybe_push(st.session_state["df"], actor=user.get("Employee Name","HR"))
                        st.session_state["delete_target"] = None
                        if saved:
                            st.success("Employee deleted and dataset saved locally.")
                            if pushed:
                                st.success("Deletion pushed to GitHub.")
                            else:
                                if GITHUB_TOKEN:
                                    st.warning("Saved locally but GitHub push failed.")
                                else:
                                    st.info("Saved locally. GitHub not configured.")
                        else:
                            st.error("Failed to save after deletion.")
                with col_del2:
                    if st.button("Cancel Delete"):
                        st.session_state["delete_target"] = None
                        st.info("Deletion cancelled.")
    st.markdown("---")
    st.markdown("### Save / Push Dataset")
    if st.button("Save current in-memory dataset locally and optionally push to GitHub"):
        df_current = st.session_state.get("df", pd.DataFrame())
        
        # Save to MySQL
        save_all_employees_to_mysql(df_current)
        
        saved, pushed = save_and_maybe_push(df_current, actor=user.get("Employee Name","HR"))
        if saved:
            if pushed:
                st.success("Saved locally and pushed to GitHub.")
            else:
                if GITHUB_TOKEN:
                    st.warning("Saved locally but GitHub push failed.")
                else:
                    st.info("Saved locally. GitHub not configured.")
        else:
            st.error("Failed to save dataset locally.")
    st.markdown("---")
    st.warning("🛠️ **Clear All Test Data** (Use BEFORE going live!)")
    if st.button("🗑️ Clear Leaves, HR Messages, Notifications & Photos"):
        try:
            test_files = [LEAVES_FILE_PATH, HR_QUERIES_FILE_PATH, NOTIFICATIONS_FILE_PATH, HR_REQUESTS_FILE_PATH, SALARIES_FILE_PATH]
            cleared = []
            for f in test_files:
                if os.path.exists(f):
                    os.remove(f)
                    cleared.append(f)
            if os.path.exists("employee_photos"):
                shutil.rmtree("employee_photos")
                cleared.append("employee_photos/")
            if os.path.exists("hr_request_files"):
                shutil.rmtree("hr_request_files")
                cleared.append("hr_request_files/")
            if os.path.exists("hr_response_files"):
                shutil.rmtree("hr_response_files")
                cleared.append("hr_response_files/")
            
            # Also clear MySQL tables
            try:
                execute_query("DELETE FROM leaves", commit=True)
                execute_query("DELETE FROM hr_queries", commit=True)
                execute_query("DELETE FROM notifications", commit=True)
                execute_query("DELETE FROM hr_requests", commit=True)
                execute_query("DELETE FROM salaries", commit=True)
                cleared.append("MySQL tables")
            except:
                pass
                
            if cleared:
                st.success(f"✅ Cleared: {', '.join(cleared)}")
            else:
                st.info("Nothing to clear.")
            st.rerun()
        except Exception as e:
            st.error(f"❌ Failed to clear: {e}")

# ============================
# PAGE: Employee Photos
# ============================
def save_employee_photo(employee_code, uploaded_file):
    os.makedirs("employee_photos", exist_ok=True)
    emp_code_clean = str(employee_code).strip().replace(".0", "")
    ext = uploaded_file.name.split(".")[-1].lower()
    if ext not in ["jpg", "jpeg", "png"]:
        raise ValueError("Only JPG/PNG files allowed.")
    filename = f"{emp_code_clean}.{ext}"
    filepath = os.path.join("employee_photos", filename)
    with open(filepath, "wb") as f:
        f.write(uploaded_file.getbuffer())
    return filename

def page_employee_photos(user):
    st.subheader("📸 Employee Photos (HR Only)")
    os.makedirs("employee_photos", exist_ok=True)
    photo_files = os.listdir("employee_photos")
    if not photo_files:
        st.info("No employee photos uploaded yet.")
        return
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.warning("Employee data not loaded.")
        return
    code_to_name = {}
    col_map = {c.lower().strip(): c for c in df.columns}
    emp_code_col = col_map.get("employee_code") or col_map.get("employee code")
    emp_name_col = col_map.get("employee_name") or col_map.get("name") or col_map.get("employee name")
    if emp_code_col and emp_name_col:
        df[emp_code_col] = df[emp_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
        for _, row in df.iterrows():
            code = row[emp_code_col]
            name = row.get(emp_name_col, "N/A")
            code_to_name[code] = name
    cols_per_row = 4
    cols = st.columns(cols_per_row)
    for i, filename in enumerate(sorted(photo_files)):
        col = cols[i % cols_per_row]
        filepath = os.path.join("employee_photos", filename)
        emp_code = filename.rsplit(".", 1)[0]
        emp_name = code_to_name.get(emp_code, "Unknown")
        with col:
            st.image(filepath, use_column_width=True)
            st.caption(f"{emp_code}<br>{emp_name}", unsafe_allow_html=True)
            with open(filepath, "rb") as f:
                st.download_button("📥 Download", f, file_name=filename, key=f"dl_{filename}")
    st.markdown("---")
    if st.button("📥 Download All Employee Photos (ZIP)"):
        zip_path = "employee_photos_all.zip"
        with zipfile.ZipFile(zip_path, 'w') as zipf:
            photo_dir = "employee_photos"
            if os.path.exists(photo_dir):
                for filename in os.listdir(photo_dir):
                    file_path = os.path.join(photo_dir, filename)
                    if os.path.isfile(file_path):
                        zipf.write(file_path, filename)
        with open(zip_path, "rb") as f:
            st.download_button(
                label="Download All Photos",
                data=f,
                file_name="employee_photos_all.zip",
                mime="application/zip"
            )
        st.success("✅ ZIP file created. Click the button to download.")

# ============================
# PAGE: Recruitment
# ============================
def save_recruitment_cv(uploaded_file):
    os.makedirs(RECRUITMENT_CV_DIR, exist_ok=True)
    ext = uploaded_file.name.split(".")[-1].lower()
    if ext not in ["pdf", "doc", "docx"]:
        raise ValueError("Only PDF or DOC/DOCX files allowed for CV.")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"cv_{timestamp}.{ext}"
    filepath = os.path.join(RECRUITMENT_CV_DIR, filename)
    with open(filepath, "wb") as f:
        f.write(uploaded_file.getbuffer())
    return filename

def page_recruitment(user):
    st.subheader("👥 Recruitment Management")
    if user.get("Title", "").upper() != "HR":
        st.error("Access denied. HR only.")
        return
    st.markdown(f"""
    <div style="background-color:white; padding:12px; border-radius:8px; border:1px solid #05445E; margin-bottom:20px;">
    <h4>📝 Candidate Application Form</h4>
    <p>Share this link with job applicants:</p>
    <a href="{GOOGLE_FORM_RECRUITMENT_LINK}" target="_blank" style="color:#05445E; text-decoration:underline;">
    👉 Apply via Google Form
    </a>
    <p style="font-size:0.9rem; color:#666666; margin-top:8px;">
    After applicants submit, download the Excel responses from Google Sheets and upload them below.
    </p>
    </div>
    """, unsafe_allow_html=True)
    tab_cv, tab_db = st.tabs(["📄 CV Candidates", "📊 Recruitment Database"])
    with tab_cv:
        st.markdown("### Upload New Candidate CV")
        uploaded_cv = st.file_uploader("Upload CV (PDF or Word)", type=["pdf", "doc", "docx"])
        candidate_name = st.text_input("Candidate Name (for reference)")
        if uploaded_cv and st.button("✅ Save CV"):
            try:
                filename = save_recruitment_cv(uploaded_cv)
                st.success(f"CV saved as: `{filename}`")
                if candidate_name:
                    add_notification("", "HR", f"New CV uploaded for: {candidate_name}")
                st.rerun()
            except Exception as e:
                st.error(f"Failed to save CV: {e}")
        st.markdown("---")
        st.markdown("### All Uploaded CVs")
        cv_files = []
        if os.path.exists(RECRUITMENT_CV_DIR):
            cv_files = sorted(os.listdir(RECRUITMENT_CV_DIR), reverse=True)
        if not cv_files:
            st.info("No CVs uploaded yet.")
        else:
            for cv in cv_files:
                col1, col2 = st.columns([4, 1])
                with col1:
                    st.markdown(f"📄 `{cv}`")
                with col2:
                    with open(os.path.join(RECRUITMENT_CV_DIR, cv), "rb") as f:
                        st.download_button("📥", f, file_name=cv, key=f"dl_cv_{cv}")
            if st.button("📦 Download All CVs (ZIP)"):
                zip_path = "all_cvs.zip"
                with zipfile.ZipFile(zip_path, 'w') as zipf:
                    for cv in cv_files:
                        zipf.write(os.path.join(RECRUITMENT_CV_DIR, cv), cv)
                with open(zip_path, "rb") as f:
                    st.download_button("Download ZIP", f, file_name="Recruitment_CVs.zip", mime="application/zip")
    with tab_db:
        st.markdown("### Upload Recruitment Data from Google Forms")
        uploaded_db = st.file_uploader("Upload Excel from Google Forms", type=["xlsx"])
        if uploaded_db:
            try:
                new_db_df = pd.read_excel(uploaded_db)
                st.session_state["recruitment_preview"] = new_db_df.copy()
                st.success("File loaded successfully.")
                st.dataframe(new_db_df.head(10), use_container_width=True)
                if st.button("✅ Replace Recruitment Database"):
                    save_json_file(new_db_df, RECRUITMENT_DATA_FILE)
                    st.success("Recruitment database updated!")
                    st.rerun()
            except Exception as e:
                st.error(f"Error reading file: {e}")
        st.markdown("---")
        st.markdown("### Current Recruitment Database")
        db_df = load_json_file(RECRUITMENT_DATA_FILE)
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

# ============================
# PAGE: Settings
# ============================
def page_settings(user):
    st.subheader("⚙️ System Settings")
    if user.get("Title", "").upper() != "HR":
        st.error("You do not have permission to access System Settings.")
        return
    st.markdown("Manage system configuration, templates, design and backup options.")
    tab3, tab4 = st.tabs([
        "🧾 Templates",
        "💾 Backup"
    ])
    with tab3:
        st.markdown("### Upload Templates")
        st.markdown("**Upload Salary Template (.xlsx)**")
        uploaded_template = st.file_uploader("Upload Salary Template", type=["xlsx"])
        if uploaded_template:
            with open("salary_template.xlsx", "wb") as f:
                f.write(uploaded_template.getbuffer())
            st.success("Salary template uploaded successfully.")
        st.markdown("### Upload System Logo")
        uploaded_logo = st.file_uploader("Upload Logo (PNG / JPG)", type=["png", "jpg", "jpeg"])
        if uploaded_logo:
            with open("logo.jpg", "wb") as f:
                f.write(uploaded_logo.getbuffer())
            st.success("Logo updated successfully.")
    with tab4:
        st.markdown("### Full System Backup")
        if st.button("Create Backup Zip"):
            backup_name = f"backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
            with zipfile.ZipFile(backup_name, "w") as zipf:
                for file in [
                    DEFAULT_FILE_PATH, LEAVES_FILE_PATH, NOTIFICATIONS_FILE_PATH,
                    HR_QUERIES_FILE_PATH, HR_REQUESTS_FILE_PATH, SALARIES_FILE_PATH
                ]:
                    if os.path.exists(file):
                        zipf.write(file)
                if os.path.exists("employee_photos"):
                    for photo in os.listdir("employee_photos"):
                        zipf.write(os.path.join("employee_photos", photo))
            with open(backup_name, "rb") as f:
                st.download_button(
                    label="📥 Download Backup ZIP",
                    data=f,
                    file_name=backup_name,
                    mime="application/zip"
                )
            st.success("Backup created successfully.")

# ============================
# PAGE: Salary Monthly
# ============================
def page_salary_monthly(user):
    st.subheader("Monthly Salaries")
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    try:
        salary_df = load_salary_data()
        if salary_df.empty:
            st.info("No salary data available.")
            return
        required_columns = ["Employee Code", "Month", "Basic Salary", "KPI Bonus", "Deductions"]
        missing_cols = [c for c in required_columns if c not in salary_df.columns]
        if missing_cols:
            st.error(f"❌ Missing columns: {missing_cols}")
            return
        salary_df["Employee Code"] = (
            salary_df["Employee Code"]
            .astype(str)
            .str.strip()
            .str.replace(".0", "", regex=False)
        )
        user_salaries = salary_df[salary_df["Employee Code"] == user_code].copy()
        if user_salaries.empty:
            st.info(f"🚫 No salary records found for you (Code: {user_code}).")
            return
        for col in ["Basic Salary", "KPI Bonus", "Deductions"]:
            user_salaries[col] = user_salaries[col].apply(decrypt_salary_value)
        user_salaries["Net Salary"] = (
            user_salaries["Basic Salary"]
            + user_salaries["KPI Bonus"]
            - user_salaries["Deductions"]
        )
        user_salaries = user_salaries.reset_index(drop=True)
        if st.button("📊 Show All Details"):
            st.session_state["show_all_details"] = not st.session_state.get("show_all_details", False)
        if st.session_state.get("show_all_details", False):
            st.markdown("### All Salary Records")
            st.dataframe(
                user_salaries[["Month", "Basic Salary", "KPI Bonus", "Deductions", "Net Salary"]],
                use_container_width=True
            )
        for idx, row in user_salaries.iterrows():
            month = row["Month"]
            btn_key = f"show_details_{month}_{idx}"
            if st.button(f"Show Details for {month}", key=btn_key):
                st.session_state[f"salary_details_{month}"] = row.to_dict()
        for idx, row in user_salaries.iterrows():
            month = row["Month"]
            details_key = f"salary_details_{month}"
            if st.session_state.get(details_key):
                details = st.session_state[details_key]
                card = f"""
                <div style="background-color:#f0fdf4; padding:14px; border-radius:10px;
                margin-bottom:10px; box-shadow:0 4px 8px rgba(0,0,0,0.05);">
                <h4 style="color:#05445E;">Salary Details – {details['Month']}</h4>
                <p style="color:#666666;">💰 Basic Salary:
                <b style="color:#05445E;">{details['Basic Salary']:.2f}</b></p>
                <p style="color:#666666;">🎯 KPI Bonus:
                <b style="color:#05445E;">{details['KPI Bonus']:.2f}</b></p>
                <p style="color:#666666;">📉 Deductions:
                <b style="color:#dc2626;">{details['Deductions']:.2f}</b></p>
                <hr style="border-color:#cbd5e1;">
                <p style="color:#666666;">🧮 Net Salary:
                <b style="color:#059669;">{details['Net Salary']:.2f}</b></p>
                </div>
                """
                st.markdown(card, unsafe_allow_html=True)
                output = BytesIO()
                with pd.ExcelWriter(output, engine="openpyxl") as writer:
                    pd.DataFrame([details]).to_excel(
                        writer, index=False, sheet_name=f"Salary_{month}"
                    )
                output.seek(0)
                st.download_button(
                    f"📥 Download Salary Slip for {month}",
                    data=output,
                    file_name=f"Salary_{user_code}_{month}.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )
                if st.button(f"Hide Details for {month}", key=f"hide_{month}"):
                    del st.session_state[details_key]
                    st.rerun()
    except Exception as e:
        st.error(f"❌ Error loading salary data: {e}")

# ============================
# PAGE: Salary Report
# ============================
def page_salary_report(user):
    st.subheader("Salary Report")
    st.info("Upload the monthly salary sheet. HR can save it to update the system for all employees.")
    uploaded_file = st.file_uploader("Upload Salary Excel File (.xlsx)", type=["xlsx"])
    if uploaded_file:
        try:
            new_salary_df = pd.read_excel(uploaded_file)
            required_cols = ["Employee Code", "Month", "Basic Salary", "KPI Bonus", "Deductions"]
            if not all(col in new_salary_df.columns for col in required_cols):
                st.error("Missing required columns. Must include: Employee Code, Month, Basic Salary, KPI Bonus, Deductions.")
                return
            cols_to_encrypt = ["Basic Salary", "KPI Bonus", "Deductions"]
            for col in cols_to_encrypt:
                new_salary_df[col] = new_salary_df[col].apply(encrypt_salary_value)
            if "Net Salary" in new_salary_df.columns:
                new_salary_df["Net Salary"] = new_salary_df["Net Salary"].apply(encrypt_salary_value)
            st.session_state["uploaded_salary_df_preview"] = new_salary_df.copy()
            st.success("File loaded and encrypted. Preview below (values appear as encrypted strings).")
            st.dataframe(new_salary_df.head(50), use_container_width=True)
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Replace In-Memory Salary Dataset with Uploaded File"):
                    save_json_file(new_salary_df, SALARIES_FILE_PATH)
                    save_all_salaries_to_mysql(new_salary_df)
                    st.session_state["salary_df"] = new_salary_df.copy()
                    st.success("✅ Salary data encrypted and saved locally and to MySQL.")
            with col2:
                if st.button("Preview only (do not replace)"):
                    st.info("Preview shown above.")
        except Exception as e:
            st.error(f"Failed to process uploaded file: {e}")
    st.markdown("---")
    st.markdown("### Save & Push Salary Report to GitHub")
    if st.button("Save current salary dataset locally and push to GitHub"):
        current_salary_df = st.session_state.get("salary_df")
        if current_salary_df is None:
            current_salary_df = load_salary_data()
        if current_salary_df is None or current_salary_df.empty:
            st.error(f"Could not load salary data from {SALARIES_FILE_PATH}. Upload a file first.")
            return
        saved = save_json_file(current_salary_df, SALARIES_FILE_PATH)
        save_all_salaries_to_mysql(current_salary_df)
        pushed_to_github = False
        if saved and GITHUB_TOKEN:
            data_list = current_salary_df.where(pd.notnull(current_salary_df), None).to_dict(orient='records')
            pushed_to_github = upload_json_to_github(SALARIES_FILE_PATH, data_list, f"Update salary report via HR by {user.get('Employee Name', 'HR')}")
        if saved:
            if pushed_to_github:
                st.success("✅ Salary data saved and pushed to GitHub.")
            else:
                if GITHUB_TOKEN:
                    st.warning("✅ Saved locally, but GitHub push failed.")
                else:
                    st.info("✅ Saved locally. GitHub token not configured.")
        else:
            st.error("❌ Failed to save locally.")
    st.markdown("---")
    st.markdown("### Current Salary Data (Encrypted View)")
    current_salary_df = st.session_state.get("salary_df")
    if current_salary_df is None:
        current_salary_df = load_salary_data()
    if current_salary_df is not None and not current_salary_df.empty:
        st.session_state["salary_df"] = current_salary_df
        st.dataframe(current_salary_df.head(100), use_container_width=True)
        buf = BytesIO()
        with pd.ExcelWriter(buf, engine="openpyxl") as writer:
            current_salary_df.to_excel(writer, index=False, sheet_name="Salaries")
        buf.seek(0)
        st.download_button(
            "Download Current Encrypted Salary Data",
            data=buf,
            file_name="Salaries.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
    else:
        st.info("No salary data available.")

# ============================
# PAGE: Notify Compliance
# ============================
def page_notify_compliance(user):
    st.subheader("📨 Notify Compliance Team")
    st.info("Use this form to notify the Compliance team about delays, absences, or other operational issues.")
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.error("Employee data not loaded.")
        return
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    emp_code_col = "Employee Code"
    mgr_code_col = "Manager Code"
    emp_name_col = "Employee Name"
    if not all(col in df.columns for col in [emp_code_col, mgr_code_col, emp_name_col]):
        st.error(f"❌ Required columns missing: {emp_code_col}, {mgr_code_col}, {emp_name_col}")
        return
    df[emp_code_col] = df[emp_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
    df[mgr_code_col] = df[mgr_code_col].astype(str).str.strip().str.replace(r'\.0$', '', regex=True)
    user_row = df[df[emp_code_col] == user_code]
    if user_row.empty:
        st.error("Your record not found.")
        return
    manager_code = user_row.iloc[0].get(mgr_code_col, "N/A")
    manager_name = "N/A"
    if manager_code != "N/A":
        mgr_row = df[df[emp_code_col] == str(manager_code).strip()]
        if not mgr_row.empty:
            manager_name = mgr_row.iloc[0].get(emp_name_col, "N/A")
    st.markdown(f"**Your Manager**: {manager_name} (Code: {manager_code})")
    compliance_titles = {
        "ASSOCIATE COMPLIANCE",
        "FIELD COMPLIANCE SPECIALIST",
        "COMPLIANCE MANAGER"
    }
    df["Title_upper"] = df["Title"].astype(str).str.upper()
    compliance_df = df[df["Title_upper"].isin(compliance_titles)].copy()
    df.drop(columns=["Title_upper"], inplace=True, errors="ignore")
    if compliance_df.empty:
        st.warning("No Compliance officers found in the system.")
        return
    compliance_options = {}
    for _, row in compliance_df.iterrows():
        name = row.get(emp_name_col, "Unknown")
        code = row.get(emp_code_col, "N/A")
        compliance_options[f"{name} (Code: {code})"] = {"name": name, "code": code}
    selected_option = st.selectbox("Select Compliance Officer", list(compliance_options.keys()))
    recipient_data = compliance_options[selected_option]
    recipient_name = recipient_data["name"]
    recipient_code = recipient_data["code"]
    message = st.text_area("Your Message", height=120, placeholder="Example: I was delayed today due to traffic...")
    if st.button("📤 Send to Compliance"):
        if not message.strip():
            st.warning("Please write a message.")
        else:
            messages_df = load_compliance_messages()
            new_id = int(messages_df["ID"].max()) + 1 if not messages_df.empty else 1
            new_row = pd.DataFrame([{
                "ID": new_id,
                "MR Code": user_code,
                "MR Name": user.get("Employee Name", user_code),
                "Compliance Recipient": recipient_name,
                "Compliance Code": recipient_code,
                "Manager Code": manager_code,
                "Manager Name": manager_name,
                "Message": message.strip(),
                "Timestamp": pd.Timestamp.now(),
                "Status": "Pending"
            }])
            messages_df = pd.concat([messages_df, new_row], ignore_index=True)
            if save_compliance_messages(messages_df):
                for title in compliance_titles:
                    add_notification("", title, f"New message from MR {user_code}")
                if manager_code != "N/A" and manager_code != user_code:
                    add_notification(manager_code, "", f"New compliance message from your team member {user_code}")
                st.success("✅ Your message has been sent to Compliance and your manager.")
            else:
                st.error("❌ Failed to send message.")

# ============================
# PAGE: Report Compliance
# ============================
def page_report_compliance(user):
    st.subheader("📋 Report Compliance")
    st.info("Messages sent by MRs regarding delays, absences, or compliance issues.")
    messages_df = load_compliance_messages()
    if messages_df.empty:
        st.info("No compliance messages yet.")
        return
    df = st.session_state.get("df", pd.DataFrame())
    if df.empty:
        st.error("Employee data not loaded.")
        return
    title_val = str(user.get("Title", "")).strip().upper()
    is_compliance = title_val in {"ASSOCIATE COMPLIANCE", "FIELD COMPLIANCE SPECIALIST", "COMPLIANCE MANAGER"}
    is_manager = title_val in {"AM", "DM"}
    if not is_compliance and is_manager:
        user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
        hierarchy = build_team_hierarchy_recursive(df, user_code, title_val)
        if hierarchy:
            def collect_all_team_codes(node, codes_set):
                if node:
                    codes_set.add(node.get("Manager Code", ""))
                    for child in node.get("Team", []):
                        collect_all_team_codes(child, codes_set)
                return codes_set
            team_codes = set()
            collect_all_team_codes(hierarchy, team_codes)
            team_codes.add(user_code)
            messages_df = messages_df[
                messages_df["MR Code"].astype(str).isin(team_codes)
            ].copy()
    messages_df = messages_df.sort_values("Timestamp", ascending=False).reset_index(drop=True)
    messages_df["Date"] = pd.to_datetime(messages_df["Timestamp"]).dt.strftime("%d-%m-%Y %H:%M")
    display_df = messages_df[[
        "Date", "MR Name", "MR Code", "Message", "Compliance Recipient", "Manager Name"
    ]].rename(columns={
        "Date": "Date & Time",
        "MR Name": "Employee Name",
        "MR Code": "Employee Code",
        "Message": "Reason",
        "Compliance Recipient": "Sent To Compliance",
        "Manager Name": "Team Manager"
    })
    st.dataframe(display_df, use_container_width=True)
    buf = BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as writer:
        display_df.to_excel(writer, index=False)
    buf.seek(0)
    st.download_button(
        "📥 Download Report (Excel)",
        data=buf,
        file_name="Compliance_Report.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

# ============================
# PAGE: IDB MR
# ============================
def page_idb_mr(user):
    st.subheader("🚀 IDB – Individual Development Blueprint")
    st.markdown("""
    <div style="background-color:#f0fdf4; padding:12px; border-radius:8px; border-left:4px solid #059669;">
    <p style="color:#05445E; font-weight:bold;">We want you to always aim higher — your success matters to us.</p>
    </div>
    """, unsafe_allow_html=True)
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
        selected = st.multiselect(
            "Choose up to 2 departments you're interested in:",
            options=departments,
            default=selected_deps
        )
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
                    user_name,
                    selected,
                    [s.strip() for s in strength_inputs if s.strip()],
                    [d.strip() for d in dev_inputs if d.strip()],
                    action_input.strip()
                )
                if success:
                    st.success("✅ IDB Report saved successfully!")
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
        st.table(display_df)
        buf = BytesIO()
        with pd.ExcelWriter(buf, engine="openpyxl") as writer:
            display_df.to_excel(writer, index=False, sheet_name="IDB_Report")
        buf.seek(0)
        st.download_button(
            "📥 Download IDB Report (Excel)",
            data=buf,
            file_name=f"IDB_{user_code}.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )

# ============================
# PAGE: Self Development
# ============================
def page_self_development(user):
    st.subheader("🌱 Self Development")
    st.markdown("""
    <div style="background-color:#e0f2fe; padding:16px; border-radius:10px; text-align:center; margin-bottom:20px;">
    <h3 style="color:#05445E;">We always want you at your best — your success matters to us.<br>
    Share your journey to success with us.</h3>
    </div>
    """, unsafe_allow_html=True)
    user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
    uploaded_cert = st.file_uploader("Upload your certification (PDF, JPG, PNG)", type=["pdf", "jpg", "jpeg", "png"])
    cert_desc = st.text_input("Brief description (optional)", placeholder="e.g., Leadership Course, Excel Advanced...")
    if uploaded_cert and st.button("📤 Submit Certification"):
        os.makedirs("certifications", exist_ok=True)
        ext = uploaded_cert.name.split(".")[-1].lower()
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"cert_{user_code}_{timestamp}.{ext}"
        filepath = os.path.join("certifications", filename)
        with open(filepath, "wb") as f:
            f.write(uploaded_cert.getbuffer())
        cert_log = load_json_file("certifications_log.json", default_columns=["Employee Code", "File", "Description", "Uploaded At"])
        new_log = pd.DataFrame([{
            "Employee Code": user_code,
            "File": filename,
            "Description": cert_desc,
            "Uploaded At": pd.Timestamp.now().isoformat()
        }])
        cert_log = pd.concat([cert_log, new_log], ignore_index=True)
        save_json_file(cert_log, "certifications_log.json")
        add_notification("", "HR", f"MR {user_code} uploaded a new certification.")
        st.success("✅ Certification submitted to HR!")
        st.rerun()

# ============================
# PAGE: HR Development
# ============================
def page_hr_development(user):
    st.subheader("🎓 Employee Development (HR View)")
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
                lambda x: ", ".join(eval(x)) if isinstance(x, str) else ", ".join(x)
            )
            idb_df["Strengths"] = idb_df["Strengths"].apply(
                lambda x: "; ".join(eval(x)) if isinstance(x, str) else "; ".join(x)
            )
            idb_df["Development Areas"] = idb_df["Development Areas"].apply(
                lambda x: "; ".join(eval(x)) if isinstance(x, str) else "; ".join(x)
            )
            display_cols = ["Employee Code", "Employee Name", "Selected Departments", "Strengths", "Development Areas", "Action Plan", "Updated At"]
            st.dataframe(idb_df[display_cols], use_container_width=True)
            buf = BytesIO()
            with pd.ExcelWriter(buf, engine="openpyxl") as writer:
                idb_df.to_excel(writer, index=False)
            buf.seek(0)
            st.download_button("📥 Download IDB Reports", data=buf, file_name="HR_IDB_Reports.xlsx")
        else:
            st.info("📭 No IDB reports yet.")
    with tab_certs:
        cert_log = load_json_file("certifications_log.json")
        if not cert_log.empty:
            st.dataframe(cert_log, use_container_width=True)
            for idx, row in cert_log.iterrows():
                filepath = os.path.join("certifications", row["File"])
                if os.path.exists(filepath):
                    with open(filepath, "rb") as f:
                        file_bytes = f.read()
                        st.download_button(
                            label=f"📥 Download {row['File']}",
                            data=file_bytes,
                            file_name=row["File"],
                            mime="application/octet-stream",
                            key=f"dl_cert_{idx}"
                        )
        else:
            st.info("📭 No certifications uploaded.")

# ============================
# PAGE: IDB DM AM Combined
# ============================
def page_idb_dm_am_combined(user):
    st.subheader("🚀 IDB & Certificate Development")
    tab1, tab2 = st.tabs(["📋 IDB Report", "📜 Certifications"])
    with tab1:
        st.markdown("""
        <div style="background-color:#f0fdf4; padding:12px; border-radius:8px; border-left:4px solid #059669;">
        <p style="color:#05445E; font-weight:bold;">We want you to always aim higher — your success matters to us.</p>
        </div>
        """, unsafe_allow_html=True)
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
        with st.form("idb_form_dm_am"):
            st.markdown("### 🔍 Select Target Departments (Max 2)")
            selected = st.multiselect(
                "Choose up to 2 departments you're interested in:",
                options=departments,
                default=selected_deps
            )
            if len(selected) > 2:
                st.warning("⚠️ You can select a maximum of 2 departments.")
            st.markdown("### 💪 Area of Strength (3 points)")
            strength_inputs = []
            for i in range(3):
                val = strengths[i] if i < len(strengths) else ""
                strength_inputs.append(st.text_input(f"Strength {i+1}", value=val, key=f"str_dm_am_{i}"))
            st.markdown("### 📈 Area of Development (3 points)")
            dev_inputs = []
            for i in range(3):
                val = development[i] if i < len(development) else ""
                dev_inputs.append(st.text_input(f"Development {i+1}", value=val, key=f"dev_dm_am_{i}"))
            st.markdown("### 🤝 Action Plan (Agreed with your manager)")
            action_input = st.text_area("Action", value=action, height=100)
            submitted = st.form_submit_button("💾 Save IDB Report")
            if submitted:
                if len(selected) > 2:
                    st.error("You cannot select more than 2 departments.")
                else:
                    success = save_idb_report(
                        user_code,
                        user_name,
                        selected,
                        [s.strip() for s in strength_inputs if s.strip()],
                        [d.strip() for d in dev_inputs if d.strip()],
                        action_input.strip()
                    )
                    if success:
                        st.success("✅ IDB Report saved successfully!")
                        add_notification("", "HR", f"{user.get('Title', '')} {user_name} ({user_code}) updated their IDB report.")
                        add_notification("", "BUM", f"{user.get('Title', '')} {user_name} ({user_code}) updated their IDB report.")
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
            st.table(display_df)
            buf = BytesIO()
            with pd.ExcelWriter(buf, engine="openpyxl") as writer:
                display_df.to_excel(writer, index=False, sheet_name="IDB_Report")
            buf.seek(0)
            st.download_button(
                "📥 Download IDB Report (Excel)",
                data=buf,
                file_name=f"IDB_{user_code}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )
    with tab2:
        st.markdown("""
        <div style="background-color:#e0f2fe; padding:16px; border-radius:10px; text-align:center; margin-bottom:20px;">
        <h3 style="color:#05445E;">Share your journey to success with us.</h3>
        </div>
        """, unsafe_allow_html=True)
        user_code = str(user.get("Employee Code", "")).strip().replace(".0", "")
        uploaded_cert = st.file_uploader("Upload your certification (PDF, JPG, PNG)", type=["pdf", "jpg", "jpeg", "png"])
        cert_desc = st.text_input("Brief description (optional)", placeholder="e.g., Leadership Course, Excel Advanced...")
        if uploaded_cert and st.button("📤 Submit Certification"):
            os.makedirs("certifications", exist_ok=True)
            ext = uploaded_cert.name.split(".")[-1].lower()
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"cert_{user_code}_{timestamp}.{ext}"
            filepath = os.path.join("certifications", filename)
            with open(filepath, "wb") as f:
                f.write(uploaded_cert.getbuffer())
            cert_log = load_json_file("certifications_log.json", default_columns=["Employee Code", "File", "Description", "Uploaded At"])
            new_log = pd.DataFrame([{
                "Employee Code": user_code,
                "File": filename,
                "Description": cert_desc,
                "Uploaded At": pd.Timestamp.now().isoformat()
            }])
            cert_log = pd.concat([cert_log, new_log], ignore_index=True)
            save_json_file(cert_log, "certifications_log.json")
            add_notification("", "HR", f"{user.get('Title', '')} {user_code} uploaded a new certification.")
            st.success("✅ Certification submitted to HR!")
            st.rerun()

# ============================
# PAGE: Notifications
# ============================
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
    if not user_code and not user_title:
        return
    user_notifs = notifications[
        (notifications["Recipient Code"].astype(str) == user_code) |
        (notifications["Recipient Title"].astype(str).str.upper() == user_title)
    ].copy()
    if user_notifs.empty:
        st.info("No notifications for you.")
        return
    user_notifs = user_notifs.sort_values("Timestamp", ascending=False).reset_index(drop=True)
    filter_option = st.radio(
        "Filter notifications:",
        ["All", "Unread", "Read"],
        index=1,
        horizontal=True,
        key="notif_filter"
    )
    if filter_option == "Unread":
        filtered_notifs = user_notifs[~user_notifs["Is Read"]]
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
        st.markdown(f"""
        <div style="
            background-color: {bg_color};
            border-left: 4px solid {color};
            padding: 12px;
            margin: 10px 0;
            border-radius: 8px;
            box-shadow: 0 2px 6px rgba(0,0,0,0.05);
        ">
            <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                <div style="display: flex; align-items: center; gap: 10px; flex: 1;">
                    <span style="font-size: 1.3rem; color: {color};">{icon}</span>
                    <div>
                        <div style="color: {color}; font-weight: bold; font-size: 1.05rem;">
                            {status_badge} {row['Message']}
                        </div>
                        <div style="color: #666666; font-size: 0.9rem; margin-top: 4px;">
                            • {time_formatted}
                        </div>
                    </div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("---")

# ============================
# PAGE: Migration Tool
# ============================
def page_migration_tool(user):
    st.subheader("🔄 Data Migration Tool")
    
    if user.get("Title", "").upper() != "HR":
        st.error("Access denied. HR only.")
        return
    
    st.warning("⚠️ This tool will migrate all data from JSON files to MySQL database.")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 📁 JSON Files Status")
        json_files = {
            "employees.json": os.path.exists(FILE_PATH),
            "leaves.json": os.path.exists(LEAVES_FILE_PATH),
            "salaries.json": os.path.exists(SALARIES_FILE_PATH),
            "hr_queries.json": os.path.exists(HR_QUERIES_FILE_PATH),
            "notifications.json": os.path.exists(NOTIFICATIONS_FILE_PATH),
            "idb_reports.json": os.path.exists(IDB_REPORTS_FILE),
            "compliance_messages.json": os.path.exists(COMPLIANCE_MESSAGES_FILE),
            "hr_requests.json": os.path.exists(HR_REQUESTS_FILE_PATH)
        }
        
        for file, exists in json_files.items():
            status = "✅" if exists else "❌"
            st.write(f"{status} {file}")
    
    with col2:
        st.markdown("### 🗄️ MySQL Tables Status")
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT 
                    table_name, 
                    table_rows 
                FROM information_schema.tables 
                WHERE table_schema = 'hr_system'
            """)
            tables = cursor.fetchall()
            cursor.close()
            conn.close()
            
            for table_name, row_count in tables:
                st.write(f"✅ {table_name}: {row_count} rows")
    
    st.markdown("---")
    st.markdown("### 🚀 Start Migration")
    
    if st.button("🔄 Migrate All Data to MySQL", type="primary"):
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        # 1. Migrate employees
        status_text.text("Migrating employees...")
        df_emp = load_json_file(FILE_PATH)
        if not df_emp.empty:
            save_all_employees_to_mysql(df_emp)
        progress_bar.progress(20)
        
        # 2. Migrate leaves
        status_text.text("Migrating leaves...")
        df_leaves = load_json_file(LEAVES_FILE_PATH)
        if not df_leaves.empty:
            for _, row in df_leaves.iterrows():
                save_leave_to_mysql(row.to_dict())
        progress_bar.progress(35)
        
        # 3. Migrate salaries
        status_text.text("Migrating salaries...")
        df_salaries = load_json_file(SALARIES_FILE_PATH)
        if not df_salaries.empty:
            save_all_salaries_to_mysql(df_salaries)
        progress_bar.progress(50)
        
        # 4. Migrate HR queries
        status_text.text("Migrating HR queries...")
        df_queries = load_json_file(HR_QUERIES_FILE_PATH)
        if not df_queries.empty:
            for _, row in df_queries.iterrows():
                save_hr_query_to_mysql(row.to_dict())
        progress_bar.progress(65)
        
        # 5. Migrate notifications
        status_text.text("Migrating notifications...")
        df_notifications = load_json_file(NOTIFICATIONS_FILE_PATH)
        if not df_notifications.empty:
            for _, row in df_notifications.iterrows():
                add_notification_to_mysql(
                    row.get('Recipient Code'),
                    row.get('Recipient Title'),
                    row.get('Message')
                )
        progress_bar.progress(75)
        
        # 6. Migrate IDB reports
        status_text.text("Migrating IDB reports...")
        df_idb = load_json_file(IDB_REPORTS_FILE)
        if not df_idb.empty:
            for _, row in df_idb.iterrows():
                save_idb_report_to_mysql(
                    row.get('Employee Code'),
                    row.get('Employee Name'),
                    row.get('Selected Departments'),
                    row.get('Strengths'),
                    row.get('Development Areas'),
                    row.get('Action Plan')
                )
        progress_bar.progress(85)
        
        # 7. Migrate compliance messages
        status_text.text("Migrating compliance messages...")
        df_compliance = load_json_file(COMPLIANCE_MESSAGES_FILE)
        if not df_compliance.empty:
            for _, row in df_compliance.iterrows():
                save_compliance_message_to_mysql(row.to_dict())
        progress_bar.progress(95)
        
        # 8. Migrate HR requests
        status_text.text("Migrating HR requests...")
        df_hr_requests = load_json_file(HR_REQUESTS_FILE_PATH)
        if not df_hr_requests.empty:
            for _, row in df_hr_requests.iterrows():
                save_hr_request_to_mysql(row.to_dict())
        
        progress_bar.progress(100)
        status_text.text("✅ Migration completed!")
        st.success("All data has been migrated to MySQL successfully!")
        st.balloons()

# ============================
# MAIN APP FLOW
# ============================
def save_and_maybe_push(df, actor="HR"):
    saved = save_json_file(df, FILE_PATH)
    pushed = False
    if GITHUB_TOKEN:
        data_list = df.where(pd.notnull(df), None).to_dict(orient='records')
        pushed = upload_json_to_github(FILE_PATH, data_list, f"Update {FILE_PATH} via Streamlit by {actor}")
        if pushed:
            saved = True
    return saved, pushed

ensure_session_df()

if not os.path.exists(SECURE_PASSWORDS_FILE):
    df_init = st.session_state.get("df", pd.DataFrame())
    if not df_init.empty:
        initialize_passwords_from_data(df_init.to_dict(orient='records'))

if "logged_in_user" not in st.session_state:
    st.session_state["logged_in_user"] = None
if "current_page" not in st.session_state:
    st.session_state["current_page"] = "My Profile"
if "external_password_page" not in st.session_state:
    st.session_state["external_password_page"] = False

with st.sidebar:
    st.markdown('<div class="sidebar-title">HRAS — Averroes Admin</div>', unsafe_allow_html=True)
    st.markdown("<hr style='border: 1px solid #05445E; margin: 10px 0;'>", unsafe_allow_html=True)
    
    if not st.session_state["logged_in_user"] and not st.session_state["external_password_page"]:
        with st.container():
            st.markdown("<div style='background-color:white; padding: 10px; border-radius: 8px; border: 1px solid #cbd5e1;'>", unsafe_allow_html=True)
            st.markdown("### 🔐 Login Required")
            with st.form("login_form"):
                uid = st.text_input("Employee Code")
                pwd = st.text_input("Password", type="password")
                submitted = st.form_submit_button("Sign in")
                if submitted:
                    df = st.session_state.get("df", pd.DataFrame())
                    if df.empty:
                        st.error("Employee data not loaded. Please check your file.")
                    else:
                        user = login(df, uid, pwd)
                        if user is None:
                            st.error("Invalid credentials or required columns missing.")
                        else:
                            if "Title" not in user:
                                user["Title"] = "Unknown"
                            st.session_state["logged_in_user"] = user
                            st.session_state["current_page"] = "My Profile"
                            st.success("Login successful!")
                            st.rerun()
            st.markdown("</div>", unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("🔐 Change Password (No Login)", use_container_width=True):
            st.session_state["external_password_page"] = True
            st.rerun()
    else:
        if st.session_state["external_password_page"]:
            if st.button("← Back to Login", use_container_width=True):
                st.session_state["external_password_page"] = False
                st.rerun()
        else:
            user = st.session_state["logged_in_user"]
            title_val = str(user.get("Title") or user.get("title") or "").strip().upper()
            is_hr = "HR" in title_val
            is_bum = title_val == "BUM"
            is_am = title_val == "AM"
            is_dm = title_val == "DM"
            is_mr = title_val == "MR"
            
            SPECIAL_TITLES = {
                "KEY ACCOUNT SPECIALIST",
                "SFE SPECIALIST",
                "TRAINING SPECIALIST",
                "SENIOR TALENT ACQUISITION",
                "HR SPECIALIST",
                "ASSOCIATE COMPLIANCE",
                "FIELD COMPLIANCE SPECIALIST",
                "OPERATION SUPERVISOR",
                "OPERATION ADMIN",
                "STORE SPECIALIST",
                "DIRECT SALES",
                "OPERATION SPECIALIST",
                "OPERATION AND ANALYTICS SPECIALIST",
                "OFFICE BOY"
            }
            is_special = title_val in SPECIAL_TITLES
            
            st.write(f"👋 **Welcome, {user.get('Employee Name') or 'User'}**")
            st.markdown("---")
            
            if is_hr:
                pages = ["Dashboard", "Reports", "HR Manager", "HR Inbox", "Employee Photos", 
                        "Ask Employees", "Recruitment", "🎓 Employee Development (HR View)", 
                        "Notifications", "Structure", "Salary Monthly", "Salary Report", 
                        "Settings", "🔄 Migration Tool"]
            elif is_bum:
                pages = ["My Profile", "Team Leaves", "Ask HR", "Request HR", "Notifications", 
                        "Structure", "Salary Monthly"]
            elif is_am or is_dm:
                pages = ["My Profile", "📋 Report Compliance", "🚀 IDB & Certificate Development", 
                        "Ask HR", "Request HR", "Notifications", "Structure", "Salary Monthly"]
            elif is_mr:
                pages = ["My Profile", "🚀 IDB – Individual Development Blueprint", "🌱 Self Development", 
                        "Notify Compliance", "Ask HR", "Request HR", "Notifications", "Structure", 
                        "Salary Monthly"]
            elif is_special:
                pages = ["My Profile", "Request Leave", "Team Leaves", "Ask HR", "Request HR", 
                        "Notifications", "Structure", "Salary Monthly"]
            else:
                pages = ["My Profile", "Request Leave", "Ask HR", "Request HR", "Notifications", 
                        "Structure", "Salary Monthly"]
            
            for page in pages:
                if st.button(page, use_container_width=True, key=f"nav_{page}"):
                    st.session_state["current_page"] = page
                    st.rerun()
            
            st.markdown("---")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🚪 Logout", use_container_width=True):
                    st.session_state["logged_in_user"] = None
                    st.session_state["current_page"] = "My Profile"
                    st.rerun()
            with col2:
                if st.button("🔄 Refresh", use_container_width=True):
                    st.rerun()
            
            st.markdown("<br>", unsafe_allow_html=True)
            unread = get_unread_count(user)
            if unread > 0:
                st.markdown(f'<div class="notification-bell">{unread}</div>', unsafe_allow_html=True)
                st.markdown(f"🔔 You have **{unread}** unread notifications", unsafe_allow_html=True)

# ============================
# MAIN PAGE ROUTING
# ============================
if st.session_state["external_password_page"]:
    page_forgot_password()
elif st.session_state["logged_in_user"]:
    user = st.session_state["logged_in_user"]
    current_page = st.session_state["current_page"]
    
    if current_page == "My Profile":
        page_my_profile(user)
    elif current_page == "Request Leave":
        page_leave_request(user)
    elif current_page == "Team Leaves":
        page_manager_leaves(user)
    elif current_page == "My Team":
        title_val = str(user.get("Title", "")).strip().upper()
        page_my_team(user, role=title_val)
    elif current_page == "Structure":
        page_directory(user)
    elif current_page == "Ask HR":
        page_ask_hr(user)
    elif current_page == "HR Inbox":
        page_hr_inbox(user)
    elif current_page == "Ask Employees":
        page_ask_employees(user)
    elif current_page == "Request HR":
        page_request_hr(user)
    elif current_page == "Dashboard":
        page_dashboard(user)
    elif current_page == "Reports":
        page_reports(user)
    elif current_page == "HR Manager":
        page_hr_manager(user)
    elif current_page == "Employee Photos":
        page_employee_photos(user)
    elif current_page == "Recruitment":
        page_recruitment(user)
    elif current_page == "Settings":
        page_settings(user)
    elif current_page == "Salary Monthly":
        page_salary_monthly(user)
    elif current_page == "Salary Report":
        page_salary_report(user)
    elif current_page == "Notify Compliance":
        page_notify_compliance(user)
    elif current_page == "📋 Report Compliance":
        page_report_compliance(user)
    elif current_page == "🚀 IDB – Individual Development Blueprint":
        page_idb_mr(user)
    elif current_page == "🌱 Self Development":
        page_self_development(user)
    elif current_page == "🎓 Employee Development (HR View)":
        page_hr_development(user)
    elif current_page == "🚀 IDB & Certificate Development":
        page_idb_dm_am_combined(user)
    elif current_page == "Notifications":
        page_notifications(user)
    elif current_page == "🔄 Migration Tool":
        page_migration_tool(user)
    else:
        st.error(f"Page '{current_page}' not implemented yet.")
else:
    st.markdown("""
    <div style="text-align: center; padding: 40px; background-color: white; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.08);">
    <h2 style="color: #05445E; margin-bottom: 20px;">👥 HRAS — Averroes Admin System</h2>
    <p style="color: #666666; font-size: 1.1rem; max-width: 600px; margin: 0 auto;">
    Welcome to the HR Administration System. Please log in using your Employee Code and Password to access your personalized dashboard.
    </p>
    <div style="margin-top: 30px; padding: 15px; background-color: #f0fdf4; border-radius: 8px; border-left: 4px solid #059669;">
    <p style="color: #05445E; font-weight: 500; margin: 0;">
    🔐 Forgot your password? Click "Change Password (No Login)" on the sidebar to reset it.
    </p>
    </div>
    </div>
    """, unsafe_allow_html=True)

# ============================
# FOOTER
# ============================
st.markdown("""
<div style="text-align: center; padding: 20px; color: #666666; font-size: 0.9rem; margin-top: 30px; border-top: 1px solid #e5e7eb;">
<p>HRAS — Averroes Admin System &copy; 2026 | MySQL Enterprise Edition • Encrypted • Role-Based Access</p>
</div>
""", unsafe_allow_html=True)
