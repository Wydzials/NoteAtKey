from flask import Flask, render_template, request, \
    flash, redirect, url_for, g, make_response
from functools import wraps
from yaml import safe_load
from os import getenv
from dotenv import load_dotenv

import utils
import db
import session
import notes


app = Flask(__name__)
load_dotenv()
app.secret_key = getenv("FLASH_SECRET")

utils.check_config()
config = safe_load(open("config.yaml"))


def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if not g.get("session").get("username"):
            flash("Sesja wygasła, zaloguj się ponownie.", "success")
            return redirect(url_for("login"))

        return function(*args, **kwargs)
    return wrapper


@app.before_request
def before():
    session_id = request.cookies.get("session_id")
    g.session = session.get(session_id)
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

    errors = []

    if not username or len(username) < 1:
        errors.append("Nazwa użytkownika nie może być pusta.")

    if not password or len(password) < 1:
        errors.append("Hasło nie może być puste.")

    seconds_to_login = db.seconds_to_next_login(username)
    if seconds_to_login > 0:
        flash(
            f"Przed kolejną próbą logowania zaczekaj {seconds_to_login} sekund.", "danger")
        return redirect(url_for("login"))

    if len(errors) == 0 and not db.check_credentials(username, password):
        errors.append("Nieprawidłowa nazwa użytkownika lub hasło.")

    if len(errors) == 0:
        db.save_login_attempt(username, True, utils.get_ip(request))

        session_id = session.save(username)
        response = make_response(redirect(url_for("index")))
        response.set_cookie("session_id", session_id, httponly=True, secure=True,
                            max_age=config["session_expire_seconds"])

        flash("Zalogowano pomyślnie!", "success")
        return response
    else:
        for error in errors:
            flash(error, "danger")

        if db.username_taken(username):
            db.save_login_attempt(username, False, utils.get_ip(request))
        return redirect(url_for("login"))


@app.route("/logout")
def logout():
    session.clear(g.session.get("username"))
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
        flash("Hasło zostało zmienione.", "success")
        return redirect(url_for("login"))
    else:
        flash("Błędny adres email, lub prośba o zmianę hasła wygasła.", "danger")
        return redirect(url_for("password_reset_token", token=token))


@app.route("/new-note", methods=["GET", "POST"])
@login_required
def new_note():
    if request.method == "GET":
        return render_template("new_note.html")

    title = request.form.get("title")
    content = request.form.get("content")
    readers = request.form.get("readers")
    public = (request.form.get("public") != None)

    errors = []

    max_length = config["max_note_length"]
    max_title_length = config["max_note_title_length"]
    max_lines = config["max_note_lines"]
    max_readers_length = config["max_note_readers_length"]

    if len(content) > max_length:
        errors.append(
            f"Długość notatki nie może przekraczać {max_length} znaków.")

    if len(title) > max_title_length:
        errors.append(
            f"Długość tytułu nie może przekraczać {max_title_length} znaków.")

    if content.count("\n") > max_lines:
        errors.append(f"Notatka nie może mieć więcej niż {max_lines} linii")

    if len(readers) > max_readers_length:
        errors.append("Nie można udostępnić notatki aż tylu użytkownikom.")

    if not public and len(errors) == 0:
        incorrect_reader = notes.check_readers(readers)
        if incorrect_reader != True:
            errors.append(f"Nieprawidłowy użytkownik: '{incorrect_reader}'.")

    if len(errors) > 0:
        for error in errors:
            flash(error, "danger")

        if (len(content) > max_length * 3 or
                len(title) > max_title_length * 3 or
                len(readers) > max_readers_length * 3):
            return render_template(
                "new_note.html",
                title=title[:max_title_length*3],
                content=content[:max_length*3],
                readers=readers[:max_readers_length*3])
        else:
            return render_template("new_note.html", title=title, content=content, readers=readers)
    else:
        notes.create(g.session.get("username"),
                     title, content, readers, public)
        return redirect(url_for("new_note"))


@app.route("/my-notes")
@login_required
def my_notes():
    my_notes = notes.get_my_notes(g.session.get("username"))
    return render_template("my_notes.html", notes=my_notes)


@app.route("/delete-note/<note_id>")
@login_required
def delete_note(note_id):
    note = notes.get(note_id)
    if note.get("author") == g.session.get("username"):
        notes.delete(note_id)
    return redirect(url_for("my_notes"))


@app.route("/public-notes")
def public_notes():
    public = notes.get_public()
    return render_template("public_notes.html", notes=public)


@app.route("/shared-notes")
@login_required
def shared_notes():
    shared = notes.get_shared(g.session.get("username"))
    return render_template("shared_notes.html", notes=shared)
