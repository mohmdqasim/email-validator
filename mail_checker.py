import streamlit as st
import pandas as pd
import smtplib
import dns.resolver
from email.utils import parseaddr
import time
import io
import socket
import re

def validate_email_syntax(email):
    """Validates the syntax of the email address."""
    # More comprehensive regex for email validation
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def get_mx_record(domain):
    """Get the MX record for the given domain with improved timeout handling."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3  # Increased timeout
        resolver.lifetime = 3
        records = resolver.resolve(domain, 'MX')
        if records:
            mx_records = sorted([(r.preference, r.exchange.to_text()) for r in records], 
                               key=lambda x: x[0])
            return mx_records[0][1]
        return None
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return None
    except Exception as e:
        st.error(f"MX lookup error: {str(e)}")
        return None

def is_catch_all_domain(server, domain, sender_email):
    """
    Improved catch-all domain detection using multiple random addresses.
    This makes the check more reliable.
    """
    # Try multiple random addresses to reduce false positives
    random_addresses = [
        f"nonexistent_{int(time.time())}@{domain}",
        f"thisisnotreal_{int(time.time())}@{domain}",
        f"invalid.address.{int(time.time())}@{domain}"
    ]
    
    try:
        for fake_email in random_addresses:
            try:
                server.mail(sender_email)
                code, _ = server.rcpt(fake_email)
                if code == 250:  # If even one fake email is accepted, it's likely a catch-all
                    return True
            except:
                continue
        return False
    except Exception:
        return False

def check_email_reachability(email, sender_email):
    """Enhanced email reachability check with better error handling."""
    if not validate_email_syntax(email):
        return False, "Invalid email syntax"
    
    address = parseaddr(email)[1]
    try:
        username, domain = address.split('@')
    except ValueError:
        return False, "Invalid email format"
    
    # Check if domain has MX records
    mx_record = get_mx_record(domain)
    if not mx_record:
        return False, f"Domain '{domain}' has no valid MX records"
    
    # Check for disposable email domains
    disposable_domains = ['mailinator.com', 'tempmail.com', 'fakeinbox.com', 'tempinbox.com']
    if domain.lower() in disposable_domains:
        return False, "Disposable email address detected"
    
    # SMTP verification with better error handling
    try:
        server = smtplib.SMTP(timeout=5)
        server.set_debuglevel(0)  # Set to 1 for debugging
        
        # Connect to the MX server
        try:
            server.connect(mx_record, 25)
        except (socket.timeout, ConnectionRefusedError):
            # Try connecting to the domain directly as fallback
            try:
                server.connect(domain, 25)
            except:
                return False, "Connection to mail server failed"
        
        # Send HELO/EHLO
        try:
            server.helo()
        except:
            try:
                server.ehlo()
            except:
                return False, "HELO/EHLO command failed"
        
        # Try MAIL FROM
        try:
            server.mail(sender_email)
        except:
            return False, "MAIL FROM command failed"
        
        # Try RCPT TO
        try:
            code, message = server.rcpt(address)
            
            # Check for common catch-all domains
            if code == 250:
                if is_catch_all_domain(server, domain, sender_email):
                    return False, "Invalid (Catch-All Domain)"
                return True, "VALID"
            
            # Interpret error codes
            message_str = message.decode('utf-8', 'ignore') if hasattr(message, 'decode') else str(message)
            
            if code == 550:
                return False, "Mailbox not found"
            elif code == 552:
                return False, "Mailbox full"
            elif code == 450:
                return False, "Mailbox temporarily unavailable"
            elif code == 421:
                return False, "Service not available"
            elif "Spamhaus" in message_str:
                return False, "Your IP is blocked by Spamhaus"
            else:
                return False, f"Invalid: SMTP Error {code} - {message_str}"
                
        except Exception as e:
            return False, f"RCPT TO command failed: {str(e)}"
            
    except Exception as e:
        return False, f"SMTP verification failed: {str(e)}"
    finally:
        try:
            server.quit()
        except:
            pass

# Streamlit UI
st.set_page_config(page_title="Email Validity Checker", layout="wide")
st.title("Email Validity and Reachability Checker")
st.write("Validate email addresses with improved accuracy using SMTP verification.")

with st.expander("About This Tool"):
    st.write("""
    This tool checks email validity through multiple methods:
    1. Syntax validation using regex
    2. Domain MX record verification
    3. SMTP server connection and mailbox verification
    4. Catch-all domain detection
    
    While this tool is more accurate than basic validation, please note that some mail servers may still return false positives due to anti-spam measures.
    """)

sender_email = st.text_input("Enter Sender Email Address (for SMTP verification)", "test@example.com")

option = st.radio("Select Mode", ["Single Email", "Batch (CSV File)"])

if option == "Single Email":
    email = st.text_input("Enter Email Address to Validate")
    
    if st.button("Validate Email"):
        if email:
            with st.spinner('Validating email...'):
                start_time = time.time()
                is_valid, message = check_email_reachability(email, sender_email)
                elapsed_time = time.time() - start_time
                
                st.write("### Results")
                if is_valid:
                    st.success(f"✅ Email is valid: {email}")
                else:
                    st.error(f"❌ Email is invalid: {email}")
                st.write(f"**Message:** {message}")
                st.write(f"**Time Taken:** {elapsed_time:.2f} seconds")
        else:
            st.error("Please enter an email address.")

elif option == "Batch (CSV File)":
    uploaded_file = st.file_uploader("Upload a CSV File with emails", type=["csv"])
    
    if uploaded_file:
        try:
            df = pd.read_csv(uploaded_file)
            
            # More flexible column detection
            email_columns = [col for col in df.columns if 'email' in col.lower()]
            
            if email_columns:
                email_column = st.selectbox("Select email column", email_columns)
                
                if st.button("Start Validation"):
                    st.write(f"Processing '{email_column}' column...")

                    emails = df[email_column].dropna().astype(str).unique()
                    results = []
                    total_emails = len(emails)

                    progress_bar = st.progress(0)
                    status_text = st.empty()

                    for idx, email in enumerate(emails):
                        status_text.write(f"Processing {idx + 1}/{total_emails}: {email}")
                        is_valid, message = check_email_reachability(email, sender_email)
                        results.append({
                            "Email": email, 
                            "Status": "Valid" if is_valid else "Invalid", 
                            "Message": message
                        })
                        
                        progress_bar.progress((idx + 1) / total_emails)

                    result_df = pd.DataFrame(results)
                    
                    # Add summary statistics
                    valid_count = result_df[result_df["Status"] == "Valid"].shape[0]
                    invalid_count = result_df[result_df["Status"] == "Invalid"].shape[0]
                    
                    st.write("### Summary")
                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("Valid Emails", valid_count)
                    with col2:
                        st.metric("Invalid Emails", invalid_count)
                    
                    st.write("### Results")
                    st.dataframe(result_df)
                    
                    # Export results
                    csv_buffer = io.StringIO()
                    result_df.to_csv(csv_buffer, index=False)
                    csv_data = csv_buffer.getvalue()
                    
                    st.download_button(
                        label="Download Validation Results CSV",
                        data=csv_data,
                        file_name=f"email_validation_results_{time.strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv"
                    )
            else:
                st.error("Could not find any column with 'email' in its name. Please ensure your CSV has an email column.")
        except Exception as e:
            st.error(f"Error processing the file: {e}")