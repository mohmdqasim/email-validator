import streamlit as st
import pandas as pd
import smtplib
import dns.resolver
from email.utils import parseaddr
import time
import io
import random
import string

def get_mx_record(domain):
    """Get the MX record for the given domain with timeout."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2  # Set timeout to 2 seconds
        resolver.lifetime = 2
        records = resolver.resolve(domain, 'MX')
        mx_record = sorted(records, key=lambda r: r.preference)[0].exchange.to_text()
        return mx_record
    except Exception:
        return None

def validate_email_syntax(email):
    """Validates the syntax of the email address."""
    if "@" not in email or "." not in email.split("@")[1]:
        return False
    return True

def is_catch_all(domain):
    """Check if the domain has a catch-all email configuration."""
    mx_record = get_mx_record(domain)
    if not mx_record:
        return False, "No MX records found."

    test_email = f"{''.join(random.choices(string.ascii_lowercase, k=10))}@{domain}"

    try:
        server = smtplib.SMTP(mx_record, 25, timeout=3)
        server.helo()
        server.mail("test@example.com")
        code, _ = server.rcpt(test_email)
        server.quit()

        if code == 250:
            return True, "Catch-All Detected"
        else:
            return False, "No Catch-All"
    except Exception:
        return False, "SMTP Error"

def check_email_reachability(email):
    """Check if the email is reachable via SMTP."""
    if not validate_email_syntax(email):
        return False, "Invalid email syntax.", None
    
    address = parseaddr(email)[1]
    domain = address.split('@')[1]
    
    mx_record = get_mx_record(domain)
    if not mx_record:
        return False, f"Domain '{domain}' does not have valid MX records.", None
    
    try:
        server = smtplib.SMTP(mx_record, 25, timeout=3)
        server.helo()
        server.mail("test@example.com")
        code, message = server.rcpt(email)
        server.quit()
        
        if code == 250:
            is_catch_all_domain, catch_all_message = is_catch_all(domain)
            return True, "VALID", catch_all_message
        return False, "Invalid", None
    except Exception:
        return False, "SMTP error", None

st.title("Email Validity and Reachability Checker")
st.write("Validate email addresses either individually or in bulk using a CSV file.")

option = st.radio("Select Mode", ["Single Email", "Batch (CSV File)"])

if option == "Single Email":
    email = st.text_input("Enter Email Address")
    if st.button("Validate Email"):
        if email:
            start_time = time.time()
            is_valid, message, catch_all_status = check_email_reachability(email)
            elapsed_time = time.time() - start_time
            
            st.write("### Results")
            st.write(f"**Email:** {email}")
            st.write(f"**Message:** {message}")
            if catch_all_status:
                st.write(f"**Catch-All Status:** {catch_all_status}")
            st.write(f"**Time Taken:** {elapsed_time:.2f} seconds")
        else:
            st.error("Please enter a valid email address.")

elif option == "Batch (CSV File)":
    uploaded_file = st.file_uploader("Upload a CSV File", type=["csv"])
    
    if uploaded_file:
        try:
            df = pd.read_csv(uploaded_file)
            email_column = None
            for col in df.columns:
                if col.lower() == "email":
                    email_column = col
                    break
            
            if email_column:
                st.write(f"Found '{email_column}' column. Processing emails...")

                emails = df[email_column].dropna().unique()
                valid_rows = []
                results = []

                total_emails = len(emails)
                progress_bar = st.progress(0)
                status_text = st.empty()  # Placeholder for dynamic count update

                for idx, email in enumerate(emails):
                    is_valid, message, catch_all_status = check_email_reachability(email)
                    results.append([email, message, catch_all_status])
                    
                    if is_valid:
                        valid_rows.append(email)

                    progress_bar.progress((idx + 1) / total_emails)
                    status_text.write(f"Processing {idx + 1}/{total_emails} emails...")

                result_df = pd.DataFrame(results, columns=["Email", "Status", "Catch-All"])
                valid_df = df[df[email_column].isin(valid_rows)]
                
                result_filename = f"valid_{uploaded_file.name}"
                csv_buffer = io.StringIO()
                result_df.to_csv(csv_buffer, index=False)
                csv_data = csv_buffer.getvalue()
                
                st.write("### Results")
                st.dataframe(result_df)
                st.download_button(
                    label="Download Results CSV",
                    data=csv_data,
                    file_name=result_filename,
                    mime="text/csv"
                )
            else:
                st.error("The uploaded CSV does not contain a column named 'email' or 'Email'.")
        except Exception as e:
            st.error(f"Error processing the file: {e}")
