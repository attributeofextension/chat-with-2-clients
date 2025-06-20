FROM python:3.9-alpine
WORKDIR /app
COPY ./client/src /app
COPY ./certs /app/certs
RUN pip install --no-cache-dir -r requirements.txt
CMD ["python", "chat_client.py", "server", "12345"]