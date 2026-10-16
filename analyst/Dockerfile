FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY soc_analyst ./soc_analyst

CMD ["python", "-m", "soc_analyst"]
