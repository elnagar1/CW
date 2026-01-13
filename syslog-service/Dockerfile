FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Expose syslog ports
EXPOSE 1514/udp
EXPOSE 1515/tcp

CMD ["python", "-u", "main.py"]
