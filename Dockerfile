FROM python:3.12-slim

RUN groupadd -r verify && useradd -r -g verify -d /app verify

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY *.py .

RUN mkdir -p /home/verify/.rampart/verify && chown -R verify:verify /app /home/verify
USER verify

EXPOSE 8090

CMD ["python", "server.py"]
