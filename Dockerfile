FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    F1_DATA_DIR=/data

COPY . /app

EXPOSE 8080

CMD ["python", "server.py"]
