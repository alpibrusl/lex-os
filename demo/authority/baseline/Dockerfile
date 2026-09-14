# The sandbox for the nightly QA agent. Written once, when the job was
# created. Unchanged by v2 — because nothing about v2 requires changing
# it, and nothing about it notices v2.
FROM python:3.12-slim
RUN pip install --no-cache-dir requests
COPY . /app
WORKDIR /app
USER 65534:65534
ENTRYPOINT ["python", "-c", "import v1_report"]
