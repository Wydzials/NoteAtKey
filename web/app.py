from flask import Flask, render_template, request, flash, redirect, url_for
from redis import Redis

from os import getenv
from dotenv import load_dotenv
import utils

app = Flask(__name__)
load_dotenv()

cloud_url = getenv("REDIS_URL")
db = Redis.from_url(cloud_url, decode_responses=True) if cloud_url else Redis(
    host="redis", decode_responses=True)

app.secret_key = "only for flash"
app.config.from_object(__name__)


@app.route('/')
def index():
    return render_template("index.html")


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    # TODO
    username = request.form.get("username")
    password = request.form.get("password")

    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register(fields={}):
    if request.method == "GET":
        return render_template("register.html", fields=fields)

    username = request.form.get("username")
    email = request.form.get("email")
    password1 = request.form.get("password1")
    password2 = request.form.get("password2")

    correct = True

    if not (username and 3 <= len(username) <= 20 and username.isalpha()):
        flash("Nieprawidłowa nazwa użytkownika.", "danger")
        correct = False

    if not (email and 3 <= len(username) <= 50):
        flash("Nieprawidłowy adres email.", "danger")
        correct = False

    if not password1 or not password2:
        flash("Hasło nie może być puste.", "danger")
        correct = False

    if password1 != password2:
        flash("Hasła są różne.", "danger")
        correct = False

    if len(password1) > 50:
        flash("Hasło może mieć maksymalnie 50 znaków.", "danger")
        correct = False

    try:
        BITS_REQUIRED = 50
        bits = round(utils.password_bits(password1))
        if bits < BITS_REQUIRED:
            flash(
                f"Hasło jest zbyt słabe ({bits} bitów, wymagane minimum {BITS_REQUIRED} bitów).", "danger")
            correct = False
    except ValueError:
        correct = False
        flash("Nieprawidłowy znak w haśle. Dozwolone znaki to: \
            małe i duże litery, cyfry, znaki specjalne: \
            !\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~.", "danger")

    if correct:
        flash("Zarejestrowano pomyślnie!", "success")
        return redirect(url_for("index"))
    else:
        return render_template("register.html", fields={"username": username, "email": email})


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
