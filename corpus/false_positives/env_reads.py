import os

# Safe environment variable reads that should NOT be flagged as hardcoded secrets
api_key = os.getenv("API_KEY", "")
db_pass = os.environ.get("DATABASE_PASSWORD", "default")
aws_token = os.environ["AWS_SESSION_TOKEN"]
