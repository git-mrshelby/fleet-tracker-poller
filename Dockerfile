FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN echo '#!/bin/sh' > /app/start.sh && \
    echo 'if [ -n "$AUTH_SECRETS" ]; then echo "$AUTH_SECRETS" | base64 -d > Auth/secrets.json; fi' >> /app/start.sh && \
    echo 'exec python fleet_supabase_pusher.py --interval 1' >> /app/start.sh && \
    chmod +x /app/start.sh

CMD ["/app/start.sh"]
