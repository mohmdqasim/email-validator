import streamlit as st
import pandas as pd
import smtplib
import dns.resolver
from email.utils import parseaddr
import time
import io
import socket
import re
import ssl
import os

def load_disposable_domains(file_path='disposed_email.conf'):
    """Load disposable email domains from a configuration file."""
    try:
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                domains = [line.strip().lower() for line in f if line.strip()]
            return set(domains)
        else:
            st.warning(f"Disposable email config file not found: {file_path}")
            return set(['mailinator.com', 'tempmail.com', 'fakeinbox.com'])
    except Exception as e:
        st.warning(f"Error loading disposable domains: {str(e)}")
        return set(['mailinator.com', 'tempmail.com', 'fakeinbox.com'])

def validate_email_syntax(email):
    """Validates the syntax of the email address."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def get_mx_record(domain):
    """Get the MX record for the given domain with improved timeout handling."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5  # Increased timeout for more reliable lookup
        resolver.lifetime = 5
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

def verify_smtp_server(mx_record, domain):
    """Verify if the SMTP server exists and is responsive."""
    ports = [25, 587, 465]  # Common SMTP ports
    
    for port in ports:
        try:
            if port == 465:  # SSL port
                context = ssl.create_default_context()
                with socket.create_connection((mx_record, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=mx_record) as ssock:
                        return True
            else:
                with socket.create_connection((mx_record, port), timeout=5):
                    return True
        except (socket.timeout, ConnectionRefusedError, socket.gaierror):
            continue
        except Exception:
            continue
    
    try:
        # Fallback: try connecting to the domain directly
        with socket.create_connection((domain, 25), timeout=5):
            return True
    except:
        pass
    
    return False

def is_catch_all_domain(server, domain, sender_email):
    """
    Improved catch-all domain detection using multiple random addresses.
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

def check_email_reachability(email, sender_email, disposable_domains):
    """Enhanced email reachability check with better error handling and server validation."""
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
    
    # Verify SMTP server existence and responsiveness
    if not verify_smtp_server(mx_record, domain):
        return False, f"SMTP server for '{domain}' is not accessible"
    
    # Check for disposable email domains
    if domain.lower() in disposable_domains:
        return False, "Disposable email address detected"
    
    # SMTP mailbox verification with better error handling
    try:
        # Try multiple ports in case one is blocked
        ports_to_try = [25, 587]
        connected = False
        server = None
        
        for port in ports_to_try:
            try:
                server = smtplib.SMTP(timeout=7)  # Increased timeout
                server.set_debuglevel(0)
                server.connect(mx_record, port)
                connected = True
                break
            except:
                continue
        
        if not connected and server:
            # Fallback: try connecting to the domain
            try:
                server.connect(domain, 25)
                connected = True
            except:
                pass
        
        if not connected:
            return False, "Failed to connect to email server"
        
        # Try EHLO and HELO commands
        try:
            server.ehlo_or_helo_if_needed()
        except:
            try:
                server.ehlo()
            except:
                try:
                    server.helo()
                except:
                    return False, "HELO/EHLO command failed"
        
        # Try MAIL FROM
        try:
            server.mail(sender_email)
        except smtplib.SMTPException:
            return False, "MAIL FROM command failed"
        except Exception as e:
            return False, f"Server rejected sender address: {str(e)}"
        
        # Try RCPT TO
        try:
            code, message = server.rcpt(address)
            
            message_str = message.decode('utf-8', 'ignore') if hasattr(message, 'decode') else str(message)
            
            # Check for common catch-all domains
            if code == 250:
                # Additional verification for likely catch-all domains
                if is_catch_all_domain(server, domain, sender_email):
                    return False, "Invalid (Catch-All Domain)"
                return True, "VALID"
            
            # Interpret error codes
            if code == 550:
                return False, "Mailbox not found"
            elif code == 551:
                return False, "User not local or invalid address"
            elif code == 552:
                return False, "Mailbox full"
            elif code == 553:
                return False, "Mailbox name invalid"
            elif code == 450:
                return False, "Mailbox temporarily unavailable"
            elif code == 451:
                return False, "Local error in processing"
            elif code == 452:
                return False, "Insufficient system storage"
            elif code == 421:
                return False, "Service not available"
            elif "spam" in message_str.lower() or "block" in message_str.lower():
                return False, "Message blocked as potential spam"
            elif "Spamhaus" in message_str:
                return False, "Your IP is blocked by Spamhaus"
            else:
                return False, f"Invalid: SMTP Error {code} - {message_str}"
                
        except smtplib.SMTPServerDisconnected:
            return False, "Server disconnected unexpectedly"
        except smtplib.SMTPResponseException as e:
            return False, f"SMTP Error: {e.smtp_code} - {e.smtp_error}"
        except Exception as e:
            return False, f"RCPT TO command failed: {str(e)}"
            
    except socket.gaierror:
        return False, "DNS lookup failed"
    except socket.timeout:
        return False, "Connection timed out"
    except smtplib.SMTPException as e:
        return False, f"SMTP Error: {str(e)}"
    except Exception as e:
        return False, f"SMTP verification failed: {str(e)}"
    finally:
        try:
            if server:
                server.quit()
        except:
            pass

# Streamlit UI
st.set_page_config(page_title="Email Validity Checker", layout="wide")
st.title("Email Validity and Reachability Checker")
st.write("Validate email addresses with enhanced SMTP server validation.")

# Load disposable domains from configuration file
disposable_domains = load_disposable_domains()
st.sidebar.write(f"Loaded {len(disposable_domains)} disposable email domains")

with st.sidebar.expander("Configuration"):
    config_file = st.text_input("Disposable Emails Config File", "disposed_email.conf")
    if st.button("Reload Config"):
        disposable_domains = load_disposable_domains(config_file)
        st.success(f"Reloaded {len(disposable_domains)} disposable domains")
    
    st.write("Sample domains (first 5):")
    for domain in list(disposable_domains)[:5]:
        st.write(f"- {domain}")

with st.expander("Advanced Settings"):
    col1, col2 = st.columns(2)
    with col1:
        sender_email = st.text_input("Sender Email Address", "test@example.com", 
                                    help="Email address to use for SMTP MAIL FROM command")
    with col2:
        verification_timeout = st.slider("Verification Timeout (seconds)", 3, 15, 7,
                                        help="Maximum time to wait for server responses")

option = st.radio("Select Mode", ["Single Email", "Batch (CSV File)"])

if option == "Single Email":
    email = st.text_input("Enter Email Address to Validate")
    
    if st.button("Validate Email"):
        if email:
            with st.spinner('Validating email...'):
                start_time = time.time()
                is_valid, message = check_email_reachability(email, sender_email, disposable_domains)
                elapsed_time = time.time() - start_time
                
                st.write("### Results")
                if is_valid:
                    st.success(f"✅ Email is valid: {email}")
                else:
                    st.error(f"❌ Email is invalid: {email}")
                st.write(f"**Message:** {message}")
                st.write(f"**Time Taken:** {elapsed_time:.2f} seconds")
                
                # Show validation steps for debugging
                domain = email.split('@')[1] if '@' in email else "invalid"
                with st.expander("Validation Steps"):
                    st.write(f"1. Syntax check: {'✓' if validate_email_syntax(email) else '✗'}")
                    
                    mx = get_mx_record(domain)
                    st.write(f"2. MX record: {'✓ ' + mx if mx else '✗ Not found'}")
                    
                    if mx:
                        smtp_valid = verify_smtp_server(mx, domain)
                        st.write(f"3. SMTP server: {'✓ Responsive' if smtp_valid else '✗ Not responsive'}")
                    
                    st.write(f"4. Disposable domain: {'✗ Yes' if domain.lower() in disposable_domains else '✓ No'}")
        else:
            st.error("Please enter an email address.")

elif option == "Batch (CSV File)":
    uploaded_file = st.file_uploader("Upload a CSV File with emails", type=["csv"])
    
    if uploaded_file:
        try:
            df = pd.read_csv(uploaded_file)
            
            # More flexible column detection
            email_columns = [col for col in df.columns if 'email' in col.lower()]
            if not email_columns:
                email_columns = df.columns.tolist()  # If no email column found, show all columns
            
            email_column = st.selectbox("Select email column", email_columns)
            
            batch_size = st.slider("Batch Size", 10, 1000, 100, 
                                 help="Number of emails to process at once")
            
            if st.button("Start Validation"):
                st.write(f"Processing '{email_column}' column...")

                emails = df[email_column].dropna().astype(str).unique()
                results = []
                total_emails = len(emails)

                progress_bar = st.progress(0)
                status_text = st.empty()
                result_area = st.empty()

                # Process emails in smaller batches
                for idx, email in enumerate(emails):
                    status_text.write(f"Processing {idx + 1}/{total_emails}: {email}")
                    is_valid, message = check_email_reachability(email, sender_email, disposable_domains)
                    results.append({
                        "Email": email, 
                        "Status": "Valid" if is_valid else "Invalid", 
                        "Message": message
                    })
                    
                    progress_bar.progress((idx + 1) / total_emails)
                    
                    # Display intermediate results
                    if (idx + 1) % 10 == 0 or idx == total_emails - 1:
                        temp_df = pd.DataFrame(results)
                        valid_count = temp_df[temp_df["Status"] == "Valid"].shape[0]
                        invalid_count = temp_df[temp_df["Status"] == "Invalid"].shape[0]
                        
                        with result_area.container():
                            st.write(f"### Intermediate Results ({idx + 1}/{total_emails})")
                            col1, col2 = st.columns(2)
                            with col1:
                                st.metric("Valid Emails", valid_count)
                            with col2:
                                st.metric("Invalid Emails", invalid_count)
                            
                            st.dataframe(temp_df.tail(10))

                result_df = pd.DataFrame(results)
                
                # Add summary statistics
                valid_count = result_df[result_df["Status"] == "Valid"].shape[0]
                invalid_count = result_df[result_df["Status"] == "Invalid"].shape[0]
                
                st.write("### Final Summary")
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Valid Emails", valid_count)
                with col2:
                    st.metric("Invalid Emails", invalid_count)
                with col3:
                    st.metric("Total Processed", total_emails)
                
                # Group by error message types
                error_counts = result_df[result_df["Status"] == "Invalid"]["Message"].value_counts()
                
                st.write("### Error Types")
                st.bar_chart(error_counts)
                
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
        except Exception as e:
            st.error(f"Error processing the file: {e}")
            st.error(f"Details: {type(e).__name__}")