import streamlit as st
import pandas as pd
import aiosmtplib
import dns.asyncresolver
import asyncio
from email.utils import parseaddr
import time
import io

async def get_mx_record(domain):
    """Get the MX record for the given domain asynchronously."""
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 2  # Set timeout to 2 seconds
        resolver.lifetime = 2
        records = await resolver.resolve(domain, 'MX')
        mx_record = sorted(records, key=lambda r: r.preference)[0].exchange.to_text()
        return mx_record
    except Exception:
        return None

def validate_email_syntax(email):
    """Validates the syntax of the email address."""
    if "@" not in email or "." not in email.split("@")[1]:
        return False
    return True

async def check_email_reachability(email):
    """Check if the email is reachable via SMTP asynchronously."""
    if not validate_email_syntax(email):
        return False, "Invalid email syntax."
    
    address = parseaddr(email)[1]
    domain = address.split('@')[1]
    
    mx_record = await get_mx_record(domain)
    if not mx_record:
        return False, f"Domain '{domain}' does not have valid MX records."
    
    try:
        client = aiosmtplib.SMTP(timeout=3)
        await client.connect(mx_record, 25)
        await client.helo()
        await client.mail("test@example.com")
        code, message = await client.rcpt(email)
        await client.quit()

        if code == 250:
            return True, "VALID"
        return False, "Invalid"
    except Exception:
        return False, "SMTP error"

async def process_emails(emails, update_progress, update_status):
    """Process emails asynchronously and update UI."""
    valid_rows = []
    total_emails = len(emails)

    async def process_single_email(idx, email):
        is_valid, message = await check_email_reachability(email)
        if is_valid:
            valid_rows.append(email)
        update_progress((idx + 1) / total_emails)
        update_status(f"Processing {idx + 1}/{total_emails} emails...")

    tasks = [process_single_email(idx, email) for idx, email in enumerate(emails)]
    await asyncio.gather(*tasks)

    return valid_rows

st.title("Email Validity and Reachability Checker (Async)")
st.write("Validate email addresses either individually or in bulk using a CSV file.")

option = st.radio("Select Mode", ["Single Email", "Batch (CSV File)"])

if option == "Single Email":
    email = st.text_input("Enter Email Address")
    if st.button("Validate Email"):
        if email:
            start_time = time.time()
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            is_valid, message = loop.run_until_complete(check_email_reachability(email))
            elapsed_time = time.time() - start_time
            
            st.write("### Results")
            st.write(f"**Email:** {email}")
            st.write(f"**Message:** {message}")
            st.write(f"**Time Taken:** {elapsed_time:.2f} seconds")
        else:
            st.error("Please enter a valid email address.")

elif option == "Ba
