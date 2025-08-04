from services.email_parser_service import EmailParserService
import os

# Temporary: Read from ENV variables
# TODO change
IMAP_SERVER = os.getenv("IMAP_SERVER", "imap.gmail.com")
EMAIL_USER = os.getenv("EMAIL_USER", "your_email@example.com")
EMAIL_PASS = os.getenv("EMAIL_PASS", "your_password")

def main():
    parser = EmailParserService(IMAP_SERVER, EMAIL_USER, EMAIL_PASS)
    parser.connect()
    emails = parser.fetch_latest_emails(num_emails=3)
    for idx, email_data in enumerate(emails, 1):
        print(f"--- Email {idx} ---")
        for key, value in email_data.items():
            print(f"{key}: {value}")
        print("-------------------------\n")

if __name__ == "__main__":
    main()