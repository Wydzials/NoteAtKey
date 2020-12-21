from flask import Flask, render_template, request, \
    flash, redirect, url_for, g, make_response
from functools import wraps
from os import getenv
from dotenv import load_dotenv
import utils
import db


app = Flask(__name__)
load_dotenv()

app.secret_key = "only for flash"
app.config.from_object(__name__)


def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if not g.get("session").get("username"):
            flash("Sesja wygasła, zaloguj się ponownie.", "success")
            return redirect(url_for("index"))

        return function(*args, **kwargs)
    return wrapper


@app.before_request
def before():
    session_id = request.cookies.get("session_id")
    g.session = db.get_session(session_id)
    print(g.session, flush=True)


@app.context_processor
def inject_dict_for_all_templates():
    return dict(session=g.session)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("forms/login.html")

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

    if correct and not db.check_credentials(username, password):
        flash("Nieprawidłowa nazwa użytkownika lub hasło.", "danger")
        correct = False

    if correct:
        db.save_login_attempt(username, True, utils.get_ip(request))

        session_id = db.set_session(username)
        response = make_response(redirect(url_for("index")))
        response.set_cookie("session_id", session_id, httponly=True)

        flash("Zalogowano pomyślnie!", "success")
        return response
    else:
        if db.username_taken(username):
            db.save_login_attempt(username, False, utils.get_ip(request))
        return redirect(url_for("login"))


@app.route("/logout")
def logout():
    db.clear_session(g.session.get("username"))
    return redirect(url_for("index"))


@app.route("/register", methods=["GET", "POST"])
def register(fields={}):
    if request.method == "GET":
        return render_template("forms/register.html", fields=fields)

    username = request.form.get("username")
    email = request.form.get("email")
    password1 = request.form.get("password1")
    password2 = request.form.get("password2")

    errors = utils.check_password(password1, password2)

    if not (username and 3 <= len(username) <= 20 and username.isalpha()):
        errors.append("Nieprawidłowa nazwa użytkownika.")

    if not (email and 3 <= len(email) <= 50):
        errors.append("Nieprawidłowy adres email.")

    if db.username_taken(username):
        errors.append("Nazwa użytkownika jest zajęta.")

    if len(errors) == 0:
        db.create_user(username, email, password1)
        flash("Zarejestrowano pomyślnie!", "success")
        return redirect(url_for("index"))
    else:
        for error in errors:
            flash(error, "danger")
        return render_template("forms/register.html", fields={"username": username, "email": email})


@app.route("/my-notes")
@login_required
def my_notes():
    return render_template("my_notes.html")


@app.route("/settings")
@login_required
def settings():
    if not g.session.get("username"):
        return redirect(url_for("index"))

    data = db.get_user_data(g.session.get("username"))
    return render_template("settings.html", user=data)


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def password_change():
    if request.method == "GET":
        return render_template("forms/password_change.html")

    username = g.session.get("username")

    old = request.form.get("old-password")
    new1 = request.form.get("password1")
    new2 = request.form.get("password2")

    errors = utils.check_password(new1, new2)

    if not db.check_credentials(g.session.get("username"), old):
        errors.append("Nieprawidłowe stare hasło.")

    if len(errors) == 0:
        db.change_password(username, new1)
        flash("Hasło zostało zmienione.", "success")
        return redirect(url_for("settings"))

    for error in errors:
        flash(error, "danger")
    return redirect(url_for("password_change"))


@app.route("/reset-password", methods=["GET", "POST"])
def password_reset():
    if request.method == "GET":
        return render_template("forms/password_reset.html")

    email = request.form.get("email")

    if not email:
        flash("Adres email jest wymagany.", "danger")
        return redirect(url_for("password_reset"))

    flash("Email z linkiem do zmiany hasła został wysłany.", "success")

    if db.email_taken(email):
        token = db.request_password_reset(email)
        return render_template("forms/password_reset.html", token=token, email=email)

    return render_template("forms/password_reset.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def password_reset_token(token):
    if request.method == "GET":
        return render_template("forms/password_reset2.html")

    email = request.form.get("email")
    password1 = request.form.get("password1")
    password2 = request.form.get("password2")

    errors = utils.check_password(password1, password2)
    if len(errors) > 0:
        for error in errors:
            flash(error, "danger")
        return redirect(url_for("password_reset_token", token=token))

    success = db.reset_password(email, token, password1)
    if success:
        flash("Hasło zostało zmienione", "success")
        return redirect(url_for("login"))
    else:
        flash("Błędny adres email, lub prośba o zmianę hasła wygasła.", "danger")
        return redirect(url_for("password_reset_token", token=token))


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
