FROM python:3.9-alpine
WORKDIR /app
COPY ./src /app
RUN pip install --no-cache-dir -r requirements.txt
CMD ["python", "mongo_init.py"]