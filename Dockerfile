FROM mcr.microsoft.com/playwright/python:v1.51.0-noble

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY server.py auto_login.py index.html ./

ENV PYTHONUNBUFFERED=1 \
    TOOL_BIND_HOST=0.0.0.0 \
    TOOL_PORT=9876 \
    TOOL_OPEN_BROWSER=false \
    TOOL_HEADLESS_DEFAULT=true \
    AUTO_LOGIN_DEBUG=false

EXPOSE 9876
CMD ["python", "server.py"]
