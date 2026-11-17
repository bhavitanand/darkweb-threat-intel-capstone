FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Do not run the web server as root: a flaw in it would otherwise own the whole container.
RUN useradd --system --create-home --uid 10001 darklens && chown -R darklens:darklens /app
USER darklens
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status == 200 else 1)"
CMD ["uvicorn", "darklens.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
