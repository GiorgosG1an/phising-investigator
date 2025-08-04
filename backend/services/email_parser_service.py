import imaplib
import email
from email.header import decode_header
from typing import List, Dict

class EmailParserService:
    def __init__(self, imap_server:str, email_user:str, email_pass:str):
        self.imap_server = imap_server
        self.email_user = email_user
        self.email_pass = email_pass
        self.mail = None

    def connect(self):
        try:
            self.mail = imaplib.IMAP4_SSL(self.imap_server)
            self.mail.login(self.email_user, self.email_pass)
            print("[+] Connected to IMAP server")

        except imaplib.IMAP4.error as e:
            print(f"[-] IMAP Login Failed: {e}")
    
    def fetch_latest_emails(self, num_emails: int = 5) ->List[Dict]:
        self.mail.select("inbox")
        status, messages = self.mail.search(None, "ALL")
        email_ids = messages[0].split()
        latest_emails = email_ids[-num_emails:]

        emails = []
        for email_id in latest_emails:
            status, msg_data = self.mail.fetch(email_id, "(RFC822)")
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    emails.append(self.parse_email_metadata(msg))
        return emails
    
    def parse_email_metadata(self, msg) -> Dict:
        def decode_field(field):
            if field:
                decoded, charset = decode_header(field)[0]

                if isinstance(decoded, bytes):
                    return decoded.decode(charset or 'utf-8', errors='ignore')
                else:
                    return decoded
            return ""
        
        email_data = {
            "From" : decode_field(msg.get("From")), 
            "To" : decode_field(msg.get("To")),
            "Subject" : decode_field(msg.get("Subject")),
            "Date" : decode_field(msg.get("Date"))
        }

        return email_data