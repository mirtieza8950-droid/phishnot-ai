from sqlalchemy import Column, String, Float, DateTime, JSON
from database import Base
from datetime import datetime

class ScanRecord(Base):
    __tablename__ = "scan_records"
    
    id = Column(String, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    input_type = Column(String)
    input_preview = Column(String)
    prediction = Column(String)
    confidence = Column(Float)
    model_breakdown = Column(JSON, nullable=True)
    feedback = Column(String, nullable=True)