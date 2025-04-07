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
        resolver.timeout = 1  # Increased timeout for more reliable lookup
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
    
    col1, col2 = st.columns(2)
    with col1:
        batch_delay = st.slider("Delay Between Emails (seconds)", 0.1, 3.0, 0.5, 
                               help="Delay between checking individual emails in batch mode")
    with col2:
        domain_delay = st.slider("Delay Between Domains (seconds)", 1.0, 10.0, 2.0,
                                help="Delay between checking different domains in batch mode")
    
    skip_smtp_verification = st.checkbox("Skip detailed SMTP verification (faster but less accurate)", False,
                                       help="Only check domain MX records and syntax, skip actual mailbox verification")
    treat_catchall_as_valid = st.checkbox("Treat catch-all domains as valid", True,
                                        help="Mark emails on catch-all domains as valid instead of invalid")

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
            original_df = df.copy()  # Keep a copy of the original data
            
            # More flexible column detection
            email_columns = [col for col in df.columns if 'email' in col.lower()]
            if not email_columns:
                email_columns = df.columns.tolist()  # If no email column found, show all columns
            
            email_column = st.selectbox("Select email column", email_columns)
            
            batch_size = st.slider("Batch Size", 10, 1000, 100, 
                                 help="Number of emails to process at once")
            
            if st.button("Start Validation"):
                st.write(f"Processing '{email_column}' column...")

                # Create a dictionary to store validation results
                validation_results = {}
                unique_emails = df[email_column].dropna().astype(str).unique()
                total_emails = len(unique_emails)

                progress_bar = st.progress(0)
                status_text = st.empty()
                result_area = st.empty()
                
                # Group emails by domain for more efficient processing
                domains_to_check = {}
                for email in unique_emails:
                    if '@' in email:
                        domain = email.split('@')[1].lower()
                        if domain not in domains_to_check:
                            domains_to_check[domain] = []
                        domains_to_check[domain].append(email)
                    else:
                        # Handle invalid emails without domain
                        validation_results[email] = {
                            "Status": "Invalid",
                            "Message": "Invalid email format"
                        }
                
                results = []
                processed_count = 0
                domain_count = 0
                total_domains = len(domains_to_check)
                
                # Process emails grouped by domain
                for domain, emails in domains_to_check.items():
                    domain_count += 1
                    status_text.write(f"Processing domain {domain_count}/{total_domains}: {domain}")
                    
                    # Check domain validity first
                    is_valid_syntax = True
                    for email in emails:
                        if not validate_email_syntax(email):
                            is_valid_syntax = False
                            validation_results[email] = {
                                "Status": "Invalid",
                                "Message": "Invalid email syntax"
                            }
                            results.append({
                                "Email": email,
                                "Status": "Invalid",
                                "Message": "Invalid email syntax"
                            })
                            processed_count += 1
                            progress_bar.progress(processed_count / total_emails)
                    
                    if not is_valid_syntax:
                        continue
                    
                    # Check MX records and server validity
                    mx_record = get_mx_record(domain)
                    smtp_valid = mx_record and verify_smtp_server(mx_record, domain)
                    is_disposable = domain.lower() in disposable_domains
                    
                    # Skip detailed SMTP check if domain is invalid or disposable
                    if not mx_record or not smtp_valid or is_disposable:
                        for email in emails:
                            message = "Disposable email address detected" if is_disposable else "Invalid domain"
                            if not mx_record:
                                message = f"Domain '{domain}' has no valid MX records"
                            elif not smtp_valid:
                                message = f"SMTP server for '{domain}' is not accessible"
                                
                            validation_results[email] = {
                                "Status": "Invalid",
                                "Message": message
                            }
                            results.append({
                                "Email": email,
                                "Status": "Invalid",
                                "Message": message
                            })
                            processed_count += 1
                            progress_bar.progress(processed_count / total_emails)
                        continue
                    
                    # If user selected to skip detailed verification, mark all emails as valid
                    if skip_smtp_verification:
                        for email in emails:
                            validation_results[email] = {
                                "Status": "Valid",
                                "Message": "Valid (Domain verified, SMTP check skipped)"
                            }
                            results.append({
                                "Email": email,
                                "Status": "Valid",
                                "Message": "Valid (Domain verified, SMTP check skipped)"
                            })
                            processed_count += 1
                            progress_bar.progress(processed_count / total_emails)
                        continue
                    
                    # For valid domains, perform SMTP verification
                    server = None
                    try:
                        # Connect once per domain
                        server = smtplib.SMTP(timeout=verification_timeout)
                        connected = False
                        
                        # Try different ports
                        for port in [25, 587]:
                            try:
                                server.connect(mx_record, port)
                                server.ehlo_or_helo_if_needed()
                                connected = True
                                break
                            except:
                                continue
                        
                        if not connected:
                            # All emails for this domain are invalid
                            for email in emails:
                                validation_results[email] = {
                                    "Status": "Invalid",
                                    "Message": "Failed to connect to email server"
                                }
                                results.append({
                                    "Email": email,
                                    "Status": "Invalid",
                                    "Message": "Failed to connect to email server"
                                })
                                processed_count += 1
                                progress_bar.progress(processed_count / total_emails)
                            continue
                        
                        # Check if it's a catch-all domain (only once per domain)
                        is_catchall = False
                        try:
                            server.mail(sender_email)
                            fake_email = f"nonexistent{int(time.time())}@{domain}"
                            code, _ = server.rcpt(fake_email)
                            is_catchall = (code == 250)
                        except:
                            pass
                        
                        # Now check each email
                        for email in emails:
                            status_text.write(f"Processing {processed_count + 1}/{total_emails}: {email}")
                            
                            if is_catchall:
                                # Handle catch-all domains based on user preference
                                if treat_catchall_as_valid:
                                    validation_results[email] = {
                                        "Status": "Valid",
                                        "Message": "Valid (Catch-all domain)"
                                    }
                                    results.append({
                                        "Email": email,
                                        "Status": "Valid",
                                        "Message": "Valid (Catch-all domain)"
                                    })
                                else:
                                    validation_results[email] = {
                                        "Status": "Invalid",
                                        "Message": "Invalid (Catch-all domain)"
                                    }
                                    results.append({
                                        "Email": email,
                                        "Status": "Invalid",
                                        "Message": "Invalid (Catch-all domain)"
                                    })
                            else:
                                try:
                                    server.mail(sender_email)
                                    code, message = server.rcpt(email)
                                    
                                    message_str = message.decode('utf-8', 'ignore') if hasattr(message, 'decode') else str(message)
                                    
                                    if code == 250:
                                        validation_results[email] = {
                                            "Status": "Valid",
                                            "Message": "VALID"
                                        }
                                        results.append({
                                            "Email": email,
                                            "Status": "Valid",
                                            "Message": "VALID"
                                        })
                                    else:
                                        # Process specific error codes
                                        if code == 550:
                                            error_msg = "Mailbox not found"
                                        elif code == 551:
                                            error_msg = "User not local or invalid address"
                                        elif code == 552:
                                            error_msg = "Mailbox full"
                                        elif code == 553:
                                            error_msg = "Mailbox name invalid"
                                        elif code == 450:
                                            error_msg = "Mailbox temporarily unavailable"
                                        elif code == 451:
                                            error_msg = "Local error in processing"
                                        elif code == 452:
                                            error_msg = "Insufficient system storage"
                                        elif code == 421:
                                            error_msg = "Service not available"
                                        else:
                                            error_msg = f"Invalid: SMTP Error {code} - {message_str}"
                                        
                                        validation_results[email] = {
                                            "Status": "Invalid",
                                            "Message": error_msg
                                        }
                                        results.append({
                                            "Email": email,
                                            "Status": "Invalid",
                                            "Message": error_msg
                                        })
                                except Exception as e:
                                    validation_results[email] = {
                                        "Status": "Invalid",
                                        "Message": f"SMTP Error: {str(e)}"
                                    }
                                    results.append({
                                        "Email": email,
                                        "Status": "Invalid",
                                        "Message": f"SMTP Error: {str(e)}"
                                    })
                            
                            processed_count += 1
                            progress_bar.progress(processed_count / total_emails)
                            
                            # Display intermediate results
                            if processed_count % 10 == 0 or processed_count == total_emails:
                                temp_df = pd.DataFrame(results)
                                valid_count = len(temp_df[temp_df["Status"] == "Valid"])
                                invalid_count = len(temp_df[temp_df["Status"] == "Invalid"])
                                
                                with result_area.container():
                                    st.write(f"### Intermediate Results ({processed_count}/{total_emails})")
                                    col1, col2 = st.columns(2)
                                    with col1:
                                        st.metric("Valid Emails", valid_count)
                                    with col2:
                                        st.metric("Invalid Emails", invalid_count)
                                    
                                    st.dataframe(temp_df.tail(10))
                            
                            # Add small delay between checks within same domain
                            time.sleep(batch_delay)
                            
                    except Exception as e:
                        # If there's an error with the domain, mark all remaining emails as invalid
                        for email in emails:
                            if email not in validation_results:
                                validation_results[email] = {
                                    "Status": "Invalid",
                                    "Message": f"Domain error: {str(e)}"
                                }
                                results.append({
                                    "Email": email,
                                    "Status": "Invalid",
                                    "Message": f"Domain error: {str(e)}"
                                })
                                processed_count += 1
                                progress_bar.progress(processed_count / total_emails)
                    finally:
                        # Ensure server is closed properly
                        try:
                            if server:
                                server.quit()
                        except:
                            pass
                    
                    # Add delay between domains to avoid rate limiting
                    time.sleep(domain_delay)
                
                # Create results dataframe for display
                result_df = pd.DataFrame(results)
                
                # Add status and message to original dataframe
                original_df["Status"] = original_df[email_column].map(
                    lambda x: validation_results.get(str(x), {}).get("Status", "Unknown") if pd.notna(x) else "Unknown"
                )
                original_df["Validation_Message"] = original_df[email_column].map(
                    lambda x: validation_results.get(str(x), {}).get("Message", "") if pd.notna(x) else ""
                )
                
                # Create separate dataframes for valid and invalid emails
                valid_df = original_df[original_df["Status"] == "Valid"]
                invalid_df = original_df[original_df["Status"] == "Invalid"]
                
                # Add summary statistics
                valid_count = len(result_df[result_df["Status"] == "Valid"])
                invalid_count = len(result_df[result_df["Status"] == "Invalid"])
                
                st.write("### Final Summary")
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Valid Emails", valid_count)
                with col2:
                    st.metric("Invalid Emails", invalid_count)
                with col3:
                    st.metric("Total Processed", total_emails)
                
                # Group by error message types
                if "Message" in result_df.columns and len(result_df[result_df["Status"] == "Invalid"]) > 0:
                    error_counts = result_df[result_df["Status"] == "Invalid"]["Message"].value_counts()
                    
                    st.write("### Error Types")
                    st.bar_chart(error_counts)
                
                st.write("### Results Overview")
                st.dataframe(result_df)
                
                timestamp = time.strftime('%Y%m%d_%H%M%S')
                
                # Export full results with original data
                full_csv_buffer = io.StringIO()
                original_df.to_csv(full_csv_buffer, index=False)
                full_csv_data = full_csv_buffer.getvalue()
                
                # Export valid emails only
                valid_csv_buffer = io.StringIO()
                valid_df.to_csv(valid_csv_buffer, index=False)
                valid_csv_data = valid_csv_buffer.getvalue()
                
                # Export invalid emails only
                invalid_csv_buffer = io.StringIO()
                invalid_df.to_csv(invalid_csv_buffer, index=False)
                invalid_csv_data = invalid_csv_buffer.getvalue()
                
                # Display download buttons
                st.write("### Download Results")
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.download_button(
                        label="Download All Results",
                        data=full_csv_data,
                        file_name=f"email_validation_all_{timestamp}.csv",
                        mime="text/csv"
                    )
                
                with col2:
                    st.download_button(
                        label="Download Valid Emails Only",
                        data=valid_csv_data,
                        file_name=f"email_validation_valid_{timestamp}.csv",
                        mime="text/csv",
                        disabled=(valid_count == 0)
                    )
                
                with col3:
                    st.download_button(
                        label="Download Invalid Emails Only",
                        data=invalid_csv_data,
                        file_name=f"email_validation_invalid_{timestamp}.csv",
                        mime="text/csv",
                        disabled=(invalid_count == 0)
                    )
                
        except Exception as e:
            st.error(f"Error processing the file: {e}")
            st.error(f"Details: {type(e).__name__}")