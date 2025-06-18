FROM python:3.9-alpine
WORKDIR /app
EXPOSE 12345
COPY ./src/requirements.txt /app
RUN pip install --no-cache-dir -r requirements.txt
CMD ["python", "chat_server.py", "0.0.0.0", "12345"]