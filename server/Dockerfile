FROM python:3.9-alpine
WORKDIR /app
EXPOSE 12345
COPY ./server/src /app
COPY ./certs /app/certs
RUN pip install --no-cache-dir -r requirements.txt
# --- DEBUGGING STEP: Verify certs existence and readability inside container ---
RUN echo "--- Server Container Certs Debug ---" && \
    ls -l /app/certs/ && \
    echo "--- server.crt head ---" && \
    head -n 5 /app/certs/server.crt && \
    echo "--- server.key head ---" && \
    head -n 5 /app/certs/server.key && \
    echo "--- End Server Container Certs Debug ---"
# --- END DEBUGGING STEP ---
CMD ["python", "chat_server.py", "0.0.0.0", "12345"]