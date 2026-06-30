FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y nmap curl && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN playwright install chromium && playwright install-deps
COPY src/ .
CMD ["python", "router_bot.py"]
