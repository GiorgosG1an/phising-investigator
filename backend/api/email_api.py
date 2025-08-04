import os

from fastapi import APIRouter, Query

from backend.models.email_metadata import EmailMetadata
from backend.services.email_parser_service import EmailParserService

router = APIRouter()

@router.get("/emails/fetch", response_model=list[EmailMetadata])
def fetch_emails(limit: int = Query(5, gt=0, le=20)):
    # TODO change argument passing
    IMAP_SERVER = os.getenv("IMAP_SERVER", "imap.google.com")
    EMAIL_USER = os.getenv("EMAIL_USER", "your_email@example.com")
    EMAIL_PASS = os.getenv("EMAIL_PASS", "your_password")
    
    parser = EmailParserService(IMAP_SERVER, EMAIL_USER, EMAIL_PASS)
    parser.connect()
    raw_emails = parser.fetch_latest_emails(num_emails=limit)

    emails = []
    for email_data in raw_emails:
        email_data["phishing_flag"] = False # Placeholder for now, logic implementation later
        emails.append(EmailMetadata(**email_data))

    return emails
