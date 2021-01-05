# NoteAtKey

### Setup
First generate SSL certificate:
```bash
$ openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 -keyout certs/key.pem -out certs/cert.pem
```
Then run the application with:
```bash
$ docker-compose up --build
```

To change the app configuration, edit `web/config.yaml`.
