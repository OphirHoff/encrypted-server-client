import smtplib
import ssl
import uuid
from email.message import EmailMessage
import base64

email_sender = "ophirh.emailserver@gmail.com"
# email_password = 'etfobscusyqrcmov'
# pass_enc = ''.join([e.decode()[:2] for e in [base64.b64encode(m.encode()) for m in email_password]])
pass_enc = 'ZQdAZgbwYgcwYwdQcweQcQcgYwbQbwdg'


def send_email(email_receiver, email_subject, email_body):
    em = EmailMessage()
    em['from'] = email_sender
    em['To'] = email_receiver
    em['Subject'] = email_subject
    em.set_content(email_body)
    context = ssl.create_default_context()

    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
        email_password = ''.join([base64.b64decode(e).decode() for e in [pass_enc[i:i+2]+'==' for i in range(0, len(pass_enc), 2)]])
        smtp.login(email_sender, email_password)
        smtp.sendmail(email_sender, email_receiver, em.as_string())
