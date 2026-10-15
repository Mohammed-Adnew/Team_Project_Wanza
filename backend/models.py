from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    sender_claimed = Column(String, nullable=True)
    sender_actual = Column(String, nullable=True)
    subject = Column(String, nullable=False)
    message_body = Column(Text, nullable=False)
    link = Column(String, nullable=True)
    attachment_filename = Column(String, nullable=True)
    risk_score = Column(Integer, nullable=False)
    verdict = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    reasons = Column(Text, nullable=False)
    source = Column(String, nullable=False)
    status = Column(String, nullable=False, default="new")
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)