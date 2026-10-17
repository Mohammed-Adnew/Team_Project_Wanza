-- 1. የሪፖርቶች ሠንጠረዥ (Reports Table)
CREATE TABLE IF NOT EXISTS reports (
    id SERIAL PRIMARY KEY,
    email_content TEXT NOT NULL,
    verdict VARCHAR(50),
    risk_score FLOAT,
    source VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. የኢሜይል ማስመሰያ ሠንጠረዥ (Simulated Inbox Table)
CREATE TABLE IF NOT EXISTS simulated_inbox (
    id SERIAL PRIMARY KEY,
    sender VARCHAR(255),
    subject VARCHAR(255),
    body TEXT,
    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 3. የግዴታዎች/ኮምፕላይያንስ ሠንጠረዥ (Obligations Table)
CREATE TABLE IF NOT EXISTS obligations (
    id SERIAL PRIMARY KEY,
    obligation_name VARCHAR(255) NOT NULL,
    status VARCHAR(50) DEFAULT 'unmet',
    last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
