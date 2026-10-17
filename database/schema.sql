-- Phish Watch database schema (PostgreSQL) - for the Docker database only.
-- Never run this against Neon: the tables already exist there.

CREATE TABLE reports (
    id SERIAL PRIMARY KEY,
    sender_claimed VARCHAR(255),
    sender_actual VARCHAR(255),
    subject VARCHAR(255),
    message_body TEXT,
    risk_score INTEGER,
    status VARCHAR(50) DEFAULT 'new',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    link TEXT,
    attachment_filename VARCHAR(255),
    verdict VARCHAR(100),
    severity VARCHAR(50),
    reasons TEXT,
    source VARCHAR(100),
    notes TEXT,
    resolved_at TIMESTAMP
);

CREATE TABLE simulated_inbox (
    id SERIAL PRIMARY KEY,
    sender VARCHAR(255),
    subject VARCHAR(255),
    body TEXT,
    is_phishing BOOLEAN
);

CREATE TABLE obligations (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255),
    description TEXT,
    status VARCHAR(50) DEFAULT 'Unmet'
);
