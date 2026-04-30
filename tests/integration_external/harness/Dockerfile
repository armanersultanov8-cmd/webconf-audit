FROM python:3.14-alpine

RUN apk add --no-cache openssl

WORKDIR /app

COPY app.py /app/app.py

RUN mkdir -p /app/certs \
    && openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout /app/certs/key.pem \
        -out /app/certs/cert.pem \
        -days 365 \
        -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    && addgroup -S app \
    && adduser -S -G app app \
    && chown -R app:app /app

EXPOSE 8080 8443

USER app

CMD ["python", "/app/app.py"]
