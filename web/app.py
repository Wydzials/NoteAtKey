from flask import Flask, render_template, request, \
    flash, redirect, url_for, g, make_response
from os import getenv
from dotenv import load_dotenv
import utils
import db

app = Flask(__name__)
load_dotenv()

app.secret_key = "only for flash"
app.config.from_object(__name__)


@app.before_request
def before():
    session_id = request.cookies.get('session_id')
    g.session = db.get_session(session_id)
    print(g.session, flush=True)


@app.context_processor
def inject_dict_for_all_templates():
    return dict(session=g.session)


@app.route('/')
def index():
    return render_template("index.html")


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username")
    password = request.form.get("password")

    correct = True

    if not username or len(username) < 1:
        flash("Nazwa użytkownika nie może być pusta.", "danger")
        correct = False

    if not password or len(password) < 1:
        flash("Hasło nie może być puste.", "danger")
        correct = False

    seconds_to_login = db.seconds_to_next_login(username)
    if seconds_to_login > 0:
        flash(
            f"Przed kolejną próbą logowania zaczekaj {seconds_to_login} sekund.", "danger")
        return redirect(url_for("login"))

    if correct and not db.check_password(username, password):
        flash("Nieprawidłowa nazwa użytkownika lub hasło.", "danger")
        correct = False

    if correct:
        db.save_login_attempt(username, True, ip())

        session_id = db.set_session(username)
        response = make_response(redirect(url_for("index")))
        response.set_cookie("session_id", session_id, httponly=True)

        flash("Zalogowano pomyślnie!", "success")
        return response
    else:
        if db.username_taken(username):
            db.save_login_attempt(username, False, ip())
        return redirect(url_for("login"))


@app.route('/logout')
def logout():
    db.clear_session(g.session.get("username"))
    return redirect(url_for("index"))

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
        BITS_REQUIRED = 1  # DEBUG
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

    if db.username_taken(username):
        flash("Nazwa użytkownika jest zajęta.", "danger")
        correct = False

    if correct:
        db.create_user(username, email, password1)
        flash("Zarejestrowano pomyślnie!", "success")
        return redirect(url_for("index"))
    else:
        return render_template("register.html", fields={"username": username, "email": email})


@app.route("/my-notes")
def my_notes():
    return render_template("my-notes.html")


@app.route("/settings")
def settings():
    if not g.session.get("username"):
        return redirect(url_for("index"))
    
    data = db.get_user_data(g.session.get("username"))
    return render_template("settings.html", user=data)



def ip():
    if not request.environ.get('HTTP_X_FORWARDED_FOR'):
        return request.environ['REMOTE_ADDR']
    else:
        return request.environ['HTTP_X_FORWARDED_FOR']


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
