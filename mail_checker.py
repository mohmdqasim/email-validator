import streamlit as st
import pandas as pd
import smtplib
import dns.resolver
from email.utils import parseaddr
import time
import io
import random

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

def check_catch_all(domain, test_count=3):
    """Check if the domain has a catch-all mail exchanger by testing multiple emails."""
    mx_record = get_mx_record(domain)
    if not mx_record:
        return False  # No MX record found, can't verify

    try:
        server = smtplib.SMTP(mx_record, 25, timeout=3)
        server.helo()
        server.mail('test@example.com')  # A valid sender email

        responses = []
        for _ in range(test_count):
            random_email = f"{random.randint(100000, 999999)}@{domain}"
            code, _ = server.rcpt(random_email)
            responses.append(code)
            time.sleep(0.5)  # Short delay to avoid detection

        server.quit()

        return all(code == 250 for code in responses)  # If all responses are 250, it's a catch-all domain
    except:
        return False

def check_email_reachability(email):
    """Check if the email is reachable via SMTP and determine if it's a catch-all domain."""
    if not validate_email_syntax(email):
        return False, "Invalid email syntax.", False

    address = parseaddr(email)[1]
    domain = address.split('@')[1]

    mx_record = get_mx_record(domain)
    if not mx_record:
        return False, f"Domain '{domain}' has no valid MX records.", False

    try:
        server = smtplib.SMTP(mx_record, 25, timeout=3)
        server.helo()
        server.mail("test@example.com")
        code, message = server.rcpt(email)

        is_catch_all = check_catch_all(domain)

        server.quit()

        if code == 250:
            return True, "VALID", is_catch_all
        return False, "Invalid", is_catch_all
    except:
        return False, "SMTP error", False

st.title("Email Validity, Reachability, and Catch-All Checker")
st.write("Validate email addresses either individually or in bulk using a CSV file.")

option = st.radio("Select Mode", ["Single Email", "Batch (CSV File)"])

if option == "Single Email":
    email = st.text_input("Enter Email Address")
    if st.button("Validate Email"):
        if email:
            start_time = time.time()
            is_valid, message, is_catch_all = check_email_reachability(email)
            elapsed_time = time.time() - start_time

            st.write("### Results")
            st.write(f"**Email:** {email}")
            st.write(f"**Message:** {message}")
            st.write(f"**Catch-All Domain:** {'Yes' if is_catch_all else 'No'}")
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
                total_emails = len(emails)

                progress_bar = st.progress(0)
                status_text = st.empty()  # Placeholder for dynamic count update

                results = []
                for idx, email in enumerate(emails):
                    is_valid, message, is_catch_all = check_email_reachability(email)
                    results.append([email, message, "Yes" if is_catch_all else "No"])

                    progress_bar.progress((idx + 1) / total_emails)
                    status_text.write(f"Processing {idx + 1}/{total_emails} emails...")

                results_df = pd.DataFrame(results, columns=["Email", "Status", "Catch-All"])

                result_filename = f"validated_{uploaded_file.name}"
                csv_buffer = io.StringIO()
                results_df.to_csv(csv_buffer, index=False)
                csv_data = csv_buffer.getvalue()

                st.write("### Results")
                st.dataframe(results_df)
                st.download_button(
                    label="Download Validated Emails CSV",
                    data=csv_data,
                    file_name=result_filename,
                    mime="text/csv"
                )
            else:
                st.error("The uploaded CSV does not contain a column named 'email' or 'Email'.")
        except Exception as e:
            st.error(f"Error processing the file: {e}")
