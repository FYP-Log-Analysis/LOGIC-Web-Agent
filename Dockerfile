FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Expose API + Dashboard ports
EXPOSE 4000 8501

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "4000"]
