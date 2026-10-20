import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    DATABASE_URL = os.getenv("DATABASE_URL", "")
    VT_API_KEY = os.getenv("VT_API_KEY", "")
    SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY", "")
    RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
    RESEND_WEBHOOK_SECRET = os.getenv("RESEND_WEBHOOK_SECRET", "")
    # Server-side safety switch; per-report user consent is also required.
    VT_FILE_UPLOAD_ENABLED = os.getenv("VT_FILE_UPLOAD_ENABLED", "false").strip().lower() == "true"
    MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024
