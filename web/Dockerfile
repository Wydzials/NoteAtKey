FROM python:3.9-slim
RUN mkdir /app
WORKDIR /app
ADD requirements.txt /app
RUN pip3 install -r requirements.txt
ADD . /app
EXPOSE 8000
ENTRYPOINT ["gunicorn", "-w", "2", "-b", "0.0.0.0:8000", "--certfile=certs/server.crt", "--keyfile=certs/server.key", "app:app"]
