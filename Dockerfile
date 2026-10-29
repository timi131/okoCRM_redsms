FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY okocrm_redsms ./okocrm_redsms
RUN useradd -r -u 10001 app && mkdir -p /data && chown app /data
USER app
ENV DB_PATH=/data/okocrm_redsms.sqlite3 LISTEN_PORT=8080
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3)"
CMD ["python", "-m", "okocrm_redsms"]
