import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import boto3
import logging

# Set up logging configuration
logging.basicConfig(filename="alerts.log", level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize the SNS client for SMS, select AWS Region
sns_client = boto3.client("sns", region_name="Global")  

# Email Alert Configuration
SENDER_EMAIL = "packet_intrusion_project@yahoo.com"
RECEIVER_EMAIL = "waltcloudcomputing@gmail.com"
EMAIL_PASSWORD = "JkZx,@!jE9Tkskd" 

def send_email_alert(subject, body):
    msg = MIMEMultipart()
    msg['From'] = SENDER_EMAIL
    msg['To'] = RECEIVER_EMAIL
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Set up SMTP server
        server = smtplib.SMTP('smtp.yahoo.com', 587)
        server.starttls()
        server.login(SENDER_EMAIL, EMAIL_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        server.quit()
        print(f"Email alert sent to {RECEIVER_EMAIL}")
    except Exception as e:
        print(f"Failed to send email alert: {e}")

def send_sms_alert(message, phone_number="+12345667890"):
    try:
        # Publish SMS using SNS
        response = sns_client.publish(
            PhoneNumber=phone_number,
            Message=message
        )
        print(f"SMS alert sent: {response['MessageId']}")
    except Exception as e:
        print(f"Failed to send SMS alert: {e}")

def log_alert(alert_message):
    logging.info(alert_message)
    print(f"Alert logged: {alert_message}")

def test_sns_sms():
    test_message = "This is a test alert from SNS."
    # Replace with recipient's number
    test_phone_number = "+1234567890"  
    send_sms_alert(test_message, test_phone_number)

test_sns_sms()
