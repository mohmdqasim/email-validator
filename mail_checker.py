import streamlit as st
import pandas as pd
import smtplib
import dns.resolver
from email.utils import parseaddr
import time

def get_mx_record(domain):
    """Get the MX record for the given domain."""
    try:
        records = dns.resolver.resolve(domain, 'MX')
        # Get the mail server with the highest priority (lowest preference value)
        mx_record = sorted(records, key=lambda r: r.preference)[0].exchange.to_text()
        return mx_record
    except Exception as e:
        return None

def validate_email_syntax(email):
    """Validates the syntax of the email address."""
    if "@" not in email or "." not in email.split("@")[1]:
        return False
    return True

def check_email_reachability(email):
    """Check if the email is reachable via SMTP."""
    # Validate email syntax
    if not validate_email_syntax(email):
        return False, "Invalid email syntax."

    # Extract domain
    address = parseaddr(email)[1]
    domain = address.split('@')[1]

    # Get MX record for the domain
    mx_record = get_mx_record(domain)
    if not mx_record:
        return False, f"Domain '{domain}' does not have valid MX records."

    try:
        # Connect to the mail server
        server = smtplib.SMTP(mx_record, 25)
        server.set_debuglevel(0)  # Set to 1 for detailed debug output
        server.helo()  # Say hello to the server
        server.mail("test@example.com")  # Dummy sender email
        code, message = server.rcpt(email)  # Validate recipient address

        # Handle SMTP response codes
        if code == 250:
            return True, "✅"
        elif code == 550:
            return False, "❌"
        elif code in (451, 452):
            return False, "Server temporarily unavailable. Try again later."
        else:
            return False, f"Unexpected server response: {code} - {message.decode('utf-8')}"
    except smtplib.SMTPConnectError:
        return False, "Unable to connect to the mail server."
    except smtplib.SMTPServerDisconnected:
        return False, "Server disconnected unexpectedly."
    except smtplib.SMTPException as e:
        return False, f"SMTP error: {e}"
    finally:
        try:
            server.quit()
        except:
            pass  # Ignore errors when closing the connection

# Streamlit App
st.title("Email Validity and Reachability Checker")
st.write("Validate email addresses either individually or in bulk using a CSV file.")

# Option selection
option = st.radio("Select Mode", ["Single Email", "Batch (CSV File)"])

if option == "Single Email":
    # Single email validation
    email = st.text_input("Enter Email Address")
    if st.button("Validate Email"):
        if email:
            start_time = time.time()
            is_valid, message = check_email_reachability(email)
            elapsed_time = time.time() - start_time

            st.write("### Results")
            st.write(f"**Email:** {email}")
            st.write(f"**Message:** {message}")
            st.write(f"**Time Taken:** {elapsed_time:.2f} seconds")
        else:
            st.error("Please enter a valid email address.")

elif option == "Batch (CSV File)":
    # Batch email validation
    uploaded_file = st.file_uploader("Upload a CSV File", type=["csv"])
    
    if uploaded_file:
        try:
            # Read CSV file
            df = pd.read_csv(uploaded_file)
            
            # Check for 'email' or 'Email' column
            email_column = None
            for col in df.columns:
                if col.lower() == "email":
                    email_column = col
                    break
            
            if email_column:
                st.write(f"Found '{email_column}' column. Processing emails...")
                emails = df[email_column].dropna().unique()  # Remove duplicates and NaN values
                
                results = []
                start_time = time.time()
                
                for email in emails:
                    is_valid, message = check_email_reachability(email)
                    results.append({"Email": email, "Status": message})
                
                elapsed_time = time.time() - start_time
                
                # Show results as a table
                st.write("### Results")
                results_df = pd.DataFrame(results)
                st.dataframe(results_df)
                
                st.write(f"**Total Emails Processed:** {len(emails)}")
                st.write(f"**Time Taken:** {elapsed_time:.2f} seconds")
            else:
                st.error("The uploaded CSV does not contain a column named 'email' or 'Email'.")
        except Exception as e:
            st.error(f"Error processing the file: {e}")
