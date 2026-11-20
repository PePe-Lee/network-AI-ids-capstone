FROM python:3.10-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY check_extract.py extract_host_minutes.py docker_demo.py ./
COPY sample/ ./sample/
COPY dashboard.html /app/dashboard.html
USER 65534:65534
EXPOSE 8080
CMD ["python", "docker_demo.py"]
