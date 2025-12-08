FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Cloud Run ustawia zmienną PORT
ENV PORT=8080

CMD ["gunicorn", "-b", "0.0.0.0:${PORT}", "app:app"]
