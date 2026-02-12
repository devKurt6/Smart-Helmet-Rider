import smtplib
from email.mime.text import MIMEText

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = "kurtdecena24@gmail.com"
SMTP_PASSWORD = "nhinsqtoirjekesu"

msg = MIMEText("This is a test email from Flask project.")
msg["Subject"] = "SMTP Test"
msg["From"] = SMTP_USERNAME
msg["To"] = "kurtdecena41@gmail.com"

server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
server.starttls()
server.login(SMTP_USERNAME, SMTP_PASSWORD)
server.send_message(msg)
server.quit()

print("Email sent successfully!")
