# Team Project Wanza - PhishWatch

A full-stack phishing detection, analysis, and compliance platform.

## Quickstart (Run with Docker)

### 1. Prerequisites
- Docker Engine & Docker Compose installed.

### 2. Setup Environment Variables
Clone the template configuration file:
\`\`\`bash
cp .env.example .env
\`\`\`

### 3. Launch Services
Start the entire stack (PostgreSQL and Flask Backend):
\`\`\`bash
docker compose up --build -d
\`\`\`

### 4. Verify Stack Status
Check the service health endpoint:
\`\`\`bash
curl http://localhost:8000/health
\`\`\`

- Backend API: \`http://localhost:8000\`
- PostgreSQL Database: \`localhost:5432\`
