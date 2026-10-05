# Contributing Guidelines & Workflow

Welcome to the team! To ensure stability and prevent conflicting changes, all contributions must follow this workflow.

## 1. Golden Rules
- **Never commit directly to main.**
- Always create a dedicated branch for your specific task.
- Keep pull requests focused on a single feature or bugfix.

## 2. Standard Branch Naming
- `feature/<name>` (e.g., `feature/link-check`)
- `fix/<name>` (e.g., `fix/docker-compose-port`)
- `docs/<name>` (e.g., `docs/api-specs`)

## 3. Daily Workflow Steps
1. Sync your local `main`:
   ```bash
   git checkout main
   git pull origin main
