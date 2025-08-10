import imaplib
import email
from email.message import Message
from email.header import decode_header
from typing import List, Dict

class EmailParserService:
    """
    EmailParserService provides functionality to connect to an IMAP email server, fetch and parse emails.

    Attributes:
        imap_server (str): The IMAP server address.
        email_user (str): The email account username.
        email_pass (str): The email account password.
        mail: The IMAP connection object.
    """
    def __init__(self, imap_server:str, email_user:str, email_pass:str):
        """
        Initializes the email parser service with IMAP server credentials.

        Args:
            imap_server (str): The address of the IMAP server.
            email_user (str): The email username for authentication.
            email_pass (str): The email password for authentication.
        """
        self.imap_server = imap_server
        self.email_user = email_user
        self.email_pass = email_pass
        self.mail = None

    def connect(self):
        """
        Establishes a connection to the IMAP server and logs in using the provided credentials.

        Raises:
            imaplib.IMAP4.error: If authentication with the IMAP server fails.
        """
        try:
            self.mail = imaplib.IMAP4(self.imap_server)
            self.mail.login(self.email_user, self.email_pass)
            print("[+] Connected to IMAP server")

        except imaplib.IMAP4.error as e:
            print(f"[-] IMAP Login Failed: {e}")
    
    def fetch_latest_emails(self, num_emails: int = 5) ->List[Dict]:
        """
        Fetches the latest emails from the inbox.

        Args:
            num_emails (int, optional): The number of latest emails to fetch. Defaults to 5.

        Returns:
            List[Dict]: A list of dictionaries, each containing parsed metadata and body of an email.
        """
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
                    emails.append({
                        **self.parse_email_metadata(msg),
                        "Body": self.get_email_body(msg)
                    })
        return emails
    
    def parse_email_metadata(self, msg: Message) -> Dict:
        """
        Extracts and decodes metadata fields from an email message.

        Args:
            msg (Message): An email.message.Message object representing the email.

        Returns:
            Dict: A dictionary containing the decoded 'From', 'To', 'Subject', and 'Date' fields of the email.
        """
        def decode_field(field):
            """
            Decodes an email header field to a readable string.
            """
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
    
    def get_email_body(self, msg: Message):
        """
        Extracts and returns the plain text body from an email message.
        
        Args:
            msg (Message): The email message object to extract the body from.

        Returns:
            str: The plain text body of the email message.
        """
        body = ""

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))

                if content_type == "text/plain" and "attachment" not in content_disposition:
                    try:
                        body += part.get_payload(decode=True).decode()
                    except:
                        pass
        else:
            body = msg.get_payload(decode=True).decode()
        
        print("Body: ", body)
        return body