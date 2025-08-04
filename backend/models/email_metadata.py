from pydantic import BaseModel

class EmailMetadata(BaseModel):
    From: str
    To: str
    Subject: str
    Date: str
    phishing_flag: bool

