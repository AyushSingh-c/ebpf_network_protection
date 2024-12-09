import subprocess
import smtplib
import requests
from urllib.parse import urlencode
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def run_command(command):
    process = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    print(f"Process ID: {process.pid}")

    while True:
        output = process.stdout.readlines()
        print("Output: ", output)
        if output == '' and process.poll() is not None:
            break
        if output:
            print(output.strip())
        
        # Send input to the process
        user_input = input().strip()
        print("user_input: ", user_input)
        process.stdin.write(user_input)
        process.stdin.flush()

    # Capture any remaining output
    stderr = process.stderr.read()
    if stderr:
        print("Error:\n", stderr)

def handle_ssh():
    run_command("ssh ayush@169.254.1.2")

def handle_dns():
    run_command("nslookup -debug example.com")

def handle_ftp():
    run_command("ftp 169.254.1.2")

def handle_smtp():
    # SMTP server configuration
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_username = "your_email@gmail.com"
    smtp_password = "your_password_or_app_password"

    # Email content
    from_email = "your_email@gmail.com"
    to_email = "recipient@example.com"
    subject = "Test Email"
    body = "This is a test email sent from a Python script."

    # Create the email message
    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Connect to the SMTP server
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()  # Secure the connection
        server.login(smtp_username, smtp_password)
        
        # Send the email
        server.sendmail(from_email, to_email, msg.as_string())
        print("Email sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {e}")
    finally:
        server.quit()


def handle_http():
    # Define the search query
    query = 'example search'
    params = {'q': query}

    # Encode the parameters
    encoded_params = urlencode(params)

    # Construct the URL
    url = f'http://www.google.com/search?{encoded_params}'

    # Send the HTTP GET request
    response = requests.get(url)

    # Print the status code and part of the response content
    print(f"Status Code: {response.status_code}")
    print(f"Content: {response.text[:500]}")  # Print the first 500 characters of the response content


def handle_rdp():
    run_command("nslookup -debug google.com")
def handle_ssl():
    run_command("nslookup -debug google.com")
def handle_tls():
    run_command("nslookup -debug google.com")
def handle_https():
    run_command("nslookup -debug google.com")

# Main function
def main():
    user_input = input("Enter the protocol: ").strip().lower()

    if user_input == "ssh":
        handle_ssh()  
    if user_input == "dns":
        handle_dns()  
    if user_input == "ftp":
        handle_ftp()  
    if user_input == "rdp":
        handle_rdp()  
    if user_input == "smtp":
        handle_smtp()  
    if user_input == "ssl":
        handle_ssl()  
    if user_input == "tls":
        handle_tls()  
    if user_input == "http":
        handle_http()  
    if user_input == "https":
        handle_https()  
    else:
        print("Unknown protocol")
    


if __name__ == "__main__":
    main()
