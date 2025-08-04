# Simple detection will change later with ML model trained on real data
class DetectionService:
    SUSPICIOUS_KEYWORDS = ["urgent", "reset password", "click here", "verify your account"]
    TRUSTED_DOMAINS = ["yourcompany.com", "gmail.com", "outlook.com"]

    @classmethod
    def flag_email(cls, email_data: dict) -> bool:
        from_field = email_data.get("From", "").lower()
        subject_field = email_data.get("Subject", "").lower()

        # Rule 1: Suspicious Keywords in Subject
        for keyword in cls.SUSPICIOUS_KEYWORDS:
            if keyword in subject_field:
                return True
        
        # Rule 2: Suspicious Sender Domain
        if "<" in from_field and ">" in from_field:
            sender_email = from_field.split("<")[1].split(">")[0]
            sender_domain = sender_email.split("2")[-1]

            if sender_domain not in cls.TRUSTED_DOMAINS:
                return True
            
        return False
    