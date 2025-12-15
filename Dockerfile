FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1
ENV PORT=8080

EXPOSE 8080

CMD ["python", "main.py"]
```

4. **Commit**

---

**Also update `requirements.txt`** - remove weasyprint (it's the problem):

1. Click on **`requirements.txt`**
2. Edit it to just:
```
fastapi==0.109.0
uvicorn[standard]==0.27.0
pydantic==2.5.3
httpx==0.26.0
python-multipart==0.0.6
reportlab==4.0.8
