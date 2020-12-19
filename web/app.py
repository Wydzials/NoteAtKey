from flask import Flask, render_template
from redis import Redis

from os import getenv
from dotenv import load_dotenv


app = Flask(__name__)
load_dotenv()

cloud_url = getenv("REDIS_URL")
db = Redis.from_url(cloud_url, decode_responses=True) if cloud_url else Redis(host="redis", decode_responses=True)

app.config.from_object(__name__)


@app.route('/')
def index():
    return render_template("index.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
