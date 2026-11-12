# Destructive Farm server image (the upstream repo ships no Dockerfile).
# Build context is the repo's server/ directory.
FROM python:3.9-slim
WORKDIR /app/server
RUN apt-get update && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . /app/server/
EXPOSE 5000
# start_server.sh runs Flask on 0.0.0.0:5000 with threads.
CMD ["sh", "start_server.sh"]
