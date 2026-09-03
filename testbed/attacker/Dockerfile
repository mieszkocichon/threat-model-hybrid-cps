FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY attack_t0831.py .
CMD ["python", "attack_t0831.py"]
