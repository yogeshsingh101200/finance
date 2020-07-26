""" Logic for webserver of finance application """
import os

import re

from datetime import datetime
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from flask_session import Session
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


@app.after_request
def after_request(response):
    """ Ensure responses aren't cached """
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Make sure DATABASE url is set
if not os.getenv("DATABASE_URL"):
    raise RuntimeError("DATABASE_URL is not set")

# Configuration to use database
engine = create_engine(os.getenv("DATABASE_URL"), echo=True)
db = scoped_session(sessionmaker(bind=engine))

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # List of dictionaries with html table columns as keys
    table = []

    # Queries distinct list of symbols and there total shares
    rows = db.execute(
        "SELECT DISTINCT symbol, SUM(shares) FROM history WHERE id = :id GROUP BY symbol", {
            "id": session["user_id"]
        })

    # To store total valuation of shares
    total_price = 0

    # Populating the table with data
    for row in rows:
        quote = lookup(row["symbol"])

        # Adds to table the various data collected
        if row["sum"]:
            table.append({
                "symbol": quote["symbol"],
                "name": quote["name"],
                "shares": row["sum"],
                "price": quote["price"],
                "total": row["sum"] * quote["price"]
            })
            total_price += row["sum"] * quote["price"]

    # For showing available cash
    cash = db.execute("SELECT cash FROM users WHERE id = :id", {
        "id": session["user_id"]
    }).fetchone()

    # For showing grand total
    grand_total = total_price + float(cash["cash"])

    return render_template("index.html", table=table, cash=cash["cash"], grand_total=grand_total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # If user reaches to route via post as by submitting the form
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # Validation
        if not symbol:
            return apology("NO SYMBOL PROVIDED!")
        if not shares:
            return apology("NO SHARES PROVIDED!")
        if not shares.isdigit():
            return apology("INVALID SHARES PROVIDED!")

        # Lookup for shares prices
        quote = lookup(symbol)

        # Validation
        if not quote:
            return apology("INVALID SYMBOL!")

        # Checks for affordability
        total = int(shares) * quote["price"]
        cash = db.execute(
            "SELECT cash FROM users WHERE id = :id", {"id": session["user_id"]}).fetchone()
        if cash["cash"] < total:
            return apology("CAN'T AFFORD!")

        # Records
        db.execute("""
        INSERT INTO history(id, symbol, shares, price, total, transacted)
        VALUES(:id, :symbol, :shares, :price, :total, :transacted)""", {
            "id": session["user_id"],
            "symbol": quote["symbol"],
            "shares": int(shares),
            "price": quote["price"],
            "total": total,
            "transacted": datetime.utcnow()
        })

        # Update
        cash = float(cash["cash"]) - total
        db.execute("UPDATE users SET cash = :cash WHERE id = :id", {
            "cash": cash, "id": session["user_id"]
        })

        db.commit()

        # Notifies to user
        flash("BOUGHT!")

        return redirect("/")

    # If user reaches to route via get as by clicking on the tab
    return render_template("buy.html")


@app.route("/check", methods=["GET", "POST"])
def check():
    """Return true if username available, else false, in JSON format"""
    username = request.args.get("username")

    # Queries and check database for availability of username
    row = db.execute("SELECT username FROM users WHERE username = :username",
                     {"username": username}).fetchone()

    if row:
        return jsonify(False)

    return jsonify(True)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Query history table to get all the data to display at history.html
    rows = db.execute("SELECT * FROM history WHERE id = :id", {
        "id": session["user_id"]
    })
    return render_template("history.html", rows=rows)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("MUST PROVIDE USERNAME!", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("MUST PROVIDE PASSWORD!", 403)

        # Query database for username
        row = db.execute("SELECT * FROM users WHERE username = :username", {
            "username": request.form.get("username")
        }).fetchone()

        # Ensure username exists and password is correct
        if not row or not check_password_hash(row["hash"],
                                              request.form.get("password")):
            return apology("INVALID USERNAME/PASSWORD!", 403)

        # Remember which user has logged in
        session["user_id"] = row["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # If user reached to route via post like by submitting form
    if request.method == "POST":
        # Stores symbol from user's form
        symbol = request.form.get("symbol")

        # Validation
        if not symbol:
            return apology("ENTER A SYMBOL!")

        # Lookup for quote
        quote = lookup(symbol)

        # Return apology if symbol is not a valid symbol
        if not quote:
            return apology("ENTER A VALID SYMBOL!")

        return render_template("quoted.html", quote=quote)

    # If user reached to route via get like by clicking quote tab
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # If user reaches to route via post as by submitting form via post
    if request.method == "POST":
        # Validation
        username = request.form.get("username")
        if not username:
            return apology("MUST PROVIDE USERNAME!")

        if db.execute("""
            SELECT username FROM users
            WHERE username = :username """, {"username": username}).fetchone():
            return apology("USERNAME NOT AVAILABLE!")

        password = request.form.get("password")
        if not password:
            return apology("MUST PROVIDE PASSWORD!")

        confirmation = request.form.get("confirmation")
        if not confirmation:
            return apology("RE-ENTER PASSWORD TO CONFIRM!")

        if not confirmation == password:
            return apology("YOU ENTERED TWO DIFFERENT PASSWORDS!")

        if len(password) < 8:
            return apology("THE PASSWORD MUST CONTAIN ATLEAST 8 CHARACTERS!")

        if not (re.search(r"[0-9]", password)
                and re.search(r"[a-z]", password)
                and re.search(r"[A-Z]", password)
                and re.search(r"\W", password)):
            return apology(""" THE PASSWORD MUST CONTAIN ATLEAST ONE OUT OF
                            0-9, a-z, A-Z AND SPECIAL CHARACTERS! """)

        # Inserts user into database(name=users)
        db.execute("INSERT INTO users(username, hash) VALUES(:username, :hash)", {
            "username": username,
            "hash": generate_password_hash(password)
        })
        db.commit()

        # Redirects to homepage
        return redirect("/")

    # If user reaches to route via get as by clicking on a link to /register
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # If users reches to route via post like by submitting a form
    if request.method == "POST":
        symbol = request.form.get("symbol")

        # Validation
        if not symbol:
            return apology("NO SYMBOL SELECTED!")
        row = db.execute("SELECT SUM(shares) FROM history WHERE id = :id AND symbol = :symbol", {
            "id": session["user_id"], "symbol": symbol
        }).fetchone()
        if row["sum"] is None:
            return apology("YOU DON'T HAVE SHARES OF THIS COMPANY!")
        shares = request.form.get("shares")
        if not shares:
            return apology("NO SHARES PROVIDED!")
        if not shares.isdigit():
            return apology("INVALID SHARES PROVIDED!")

        # Checks affordability
        if int(shares) > row["sum"]:
            return apology("YOU HAVE ONLY {} SHARES OF THIS COMPANY!".format(row["sum"]))

        # Records in history table
        quote = lookup(symbol)
        db.execute(""" INSERT INTO history (id, symbol, shares, price, total, transacted)
                    VALUES (:id, :symbol, :shares, :price, :total, :transacted) """, {"id": session["user_id"],
                                                                                      "symbol": quote["symbol"],
                                                                                      "shares": -int(shares),
                                                                                      "price": quote["price"],
                                                                                      "total": int(shares) * quote["price"],
                                                                                      "transacted": datetime.utcnow()
                                                                                      })

        # Updates cash in users table
        cash = db.execute(
            "SELECT cash FROM users WHERE id = :id", {"id": session["user_id"]}).fetchone()

        updated_cash = float(cash["cash"]) + quote["price"] * int(shares)
        db.execute("UPDATE users SET cash = :cash WHERE id = :id", {
            "cash": updated_cash, "id": session["user_id"]
        })

        db.commit()

        # Notifies to user
        flash("SOLD!")

        # Redirects to homepage
        return redirect("/")

    # If users reches to route via get like by clicking on sell tab
    else:
        rows = db.execute(
            "SELECT DISTINCT symbol, SUM(shares) FROM history WHERE id = :id GROUP BY symbol", {
                "id": session["user_id"]
            })
        return render_template("sell.html", rows=rows)


@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    """ Changes user password """

    # When user submit the form
    if request.method == "POST":

        # Authentication of user
        old_pswrd = request.form.get("old_pswrd")
        if not old_pswrd:
            return apology("PROVIDE OLD PASSWORD TO CONTINUE!")
        row = db.execute(
            "SELECT hash FROM users WHERE id = :id", {"id": session["user_id"]}).fetchone()
        if not check_password_hash(row["hash"], old_pswrd):
            return apology("INAVLID PASSWORD!")

        # New password validation
        new_pswrd = request.form.get("new_pswrd")
        if not new_pswrd:
            return apology("PROVIDE NEW PASSWORD!")
        if len(new_pswrd) < 8:
            return apology("THE PASSWORD MUST CONTAIN ATLEAST 8 CHARACTERS!")
        if not (re.search(r"[0-9]", new_pswrd)
                and re.search(r"[a-z]", new_pswrd)
                and re.search(r"[A-Z]", new_pswrd)
                and re.search(r"\W", new_pswrd)):
            return apology("""THE PASSWORD MUST CONTAIN ATLEAST ONE OUT OF
                            0-9, a-z, A-Z AND SPECIAL CHARACTERS!""")

        # Updating the database
        db.execute("UPDATE users SET hash = :hash WHERE id = :id", {
            "hash": generate_password_hash(new_pswrd),
            "id": session["user_id"]
        })
        db.commit()

        # Inform the user
        flash("PASSWORD CHANGED SUCCESSFULLY!")
        return redirect("/")

    # When user visits the page
    else:
        return render_template("change.html")


@app.route("/alert")
def alert():
    """ Sends alerts to user in json format """

    # Takes alert message
    message = request.args.get("message")

    # Gets html content of alert.html and return in JSON format
    return jsonify(render_template("alert.html", message=message))


def errorhandler(error):
    """Handle error"""
    if not isinstance(error, HTTPException):
        error = InternalServerError()
    return apology(error.name, error.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
