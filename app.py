import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///familyexpenses.db")


@app.route("/")
@login_required
def index():
    """Show portfolio of user"""
    users = db.execute("SELECT total FROM family WHERE family_id = :user_id", user_id=session["user_id"])
    qtys = db.execute(
        "SELECT category, SUM(quantity) as total_qty, amt_per_qty FROM transactions WHERE user_id = :user_id GROUP BY category HAVING total_qty > 0", user_id=session["user_id"])

    cash_remaining = users[0]["cash"]
    total = cash_remaining

    return render_template("index.html", qtys=qtys, total=total, cash_remaining=cash_remaining)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("familyname"):
            return apology("must provide familyname", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM family WHERE familyname = :familyname",
                          familyname=request.form.get("familyname"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["passcode"], request.form.get("password")):
            return apology("invalid familyname and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["family_id"]

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

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    else:
        rows = db.execute("SELECT * from family where familyname = :familyname",
        familyname = request.form.get("familyname"))
        print(request.form.get("familyname"))
        if len(rows) == 1 or not request.form.get("familyname"):
            return apology("Family name invalid!")

        elif not request.form.get("password"):
            return apology("Please enter password!")

        elif request.form.get("password") != request.form.get("password(again)"):
            return apology("The two passwords do not match!")

        familyname = request.form.get("familyname")
        password = request.form.get("password")

        user_names = [request.form.get("user1"), request.form.get("user2"), request.form.get("user3"), request.form.get("user4")]
        n_users = 0
        for user in user_names:
            if len(user) > 1:
                 n_users += 1


        db.execute("INSERT INTO family (familyname, passcode, total, n_users) VALUES (:familyname, :passcode, :total, :n_users)", familyname=familyname, passcode=generate_password_hash(password), total=0, n_users=n_users)

        for user in user_names:
            if len(user) > 1:
                db.execute("INSERT INTO users (family_id, user_name) VALUES (:family_id, :user_name)", family_id=session["user_id"], user_name=user)


        return redirect("/")

@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """Allow user to change her password"""

    if request.method == "POST":

        # Ensure current password is not empty
        if not request.form.get("current_password"):
            return apology("must provide current password", 400)

        # Query database for user_id
        rows = db.execute("SELECT passcode FROM family WHERE family_id = :family_id", family_id=session["user_id"])

        # Ensure current password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["passcode"], request.form.get("current_password")):
            return apology("invalid password", 400)

        # Ensure new password is not empty
        if not request.form.get("new_password"):
            return apology("must provide new password", 400)

        # Ensure new password confirmation is not empty
        elif not request.form.get("new_password_confirmation"):
            return apology("must provide new password confirmation", 400)

        # Ensure new password and confirmation match
        elif request.form.get("new_password") != request.form.get("new_password_confirmation"):
            return apology("new password and confirmation must match", 400)

        # Update database
        hash = generate_password_hash(request.form.get("new_password"))
        rows = db.execute("UPDATE users SET passcode = :passcode WHERE family_id = :family_id", family_id=session["user_id"], passcode=passcode)

        # Show flash
        flash("Changed!")

    return render_template("change_password.html")

@app.route("/expense", methods=["GET", "POST"])
@login_required
def expense():
    """Bought an item (Input amount)"""
    if request.method == "POST":
        #quote = lookup(request.form.get("symbol"))

        # Check if the category exists
        try:
            category = request.form.get("category")
        except:
            return apology("Category must be entered", 400)

        # Check if quantity exists
        try:
            quantity = int(request.form.get("quantity"))
        except:
            return apology("Quantity must be a positive integer", 400)

        # Check if quantity requested was 0
        if quantity <= 0:
            return apology("Quantity can't be less than or equal to 0", 400)

        # Query database for username
        rows = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])

        # How much $$$ the user still has in her account
        cash_remaining = rows[0]["cash"]
        amt_per_qty = int(request.form.get("amt_per_qty"))

        # Calculate the price of requested shares
        total_price = amt_per_qty * quantity

        if total_price > cash_remaining:
            return apology("not enough funds")

        # Book keeping (TODO: should be wrapped with a transaction)
        db.execute("UPDATE users SET cash = cash - :price WHERE id = :user_id", price=total_price, user_id=session["user_id"])
        db.execute("INSERT INTO transactions (user_id, category, quantity, amt_per_qty) VALUES(:user_id, :category, :quantity, :amt_per_qty)",
                   user_id=session["user_id"],
                   category=category,
                   quantity=quantity,
                   amt_per_qty=amt_per_qty)

        flash("Done!")

        return redirect("/expense")

    else:
        return render_template("expense.html")




@app.route("/default", methods=["GET", "POST"])
@login_required
def default():
    """Edit user's transactions"""
    if request.method == "POST":

        # Check if the category exists
        try:
            category = request.form.get("category")
        except:
            return apology("Category must exist", 400)

        # Check if quantity exists
        try:
            quantity = int(request.form.get("quantity"))
        except:
            return apology("Quantity must be there", 400)

        # Check if quantity requested was less than or equal to 0
        if quantity <= 0:
            return apology("Quantity cannot be less than or equal to 0", 400)

        # Check if we have enough qty
        qty = db.execute("SELECT SUM(quantity) as total_qty FROM transactions WHERE user_id = :user_id AND category = :category GROUP BY category",
                           user_id=session["user_id"], category=category)

        if len(qty) != 1 or qty[0]["total_qty"] <= 0 or qty[0]["total_qty"] < quantity:
            return apology("Invalid request", 400)

        # Query database for username
        rows = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])

        # How much $$$ the user still has in her account
        cash_remaining = rows[0]["cash"]

        # Query database for amount per quantity of the category selected
        rows_1 = db.execute("SELECT amt_per_qty FROM transactions WHERE category = :category", category=category)
        amt_per_qty = rows_1[0]["amt_per_qty"]

        # Calculate the price of requested shares
        total_price = amt_per_qty * quantity

        # Book keeping
        db.execute("UPDATE users SET cash = cash + :price WHERE id = :user_id", price=total_price, user_id=session["user_id"])
        db.execute("UPDATE transactions SET quantity=:quantity WHERE category=:category", quantity=qty[0]["total_qty"]-quantity, category=category)

        flash("Edited!")

        return redirect("/default")

    else:
        qtys = db.execute(
            "SELECT category, SUM(quantity) as total_qty FROM transactions WHERE user_id = :user_id GROUP BY category HAVING total_qty > 0", user_id=session["user_id"])

        return render_template("default.html", qtys=qtys)



@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute(
        "SELECT category, quantity, amt_per_qty FROM transactions WHERE user_id = :user_id", user_id=session["user_id"])

    return render_template("history.html", transactions=transactions)

@app.route("/analysis")
@login_required
def analysis():
    """ Show distribution of spending """
    users = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])
    qtys = db.execute(
        "SELECT category, SUM(quantity) as total_qty, amt_per_qty FROM transactions WHERE user_id = :user_id GROUP BY category HAVING total_qty > 0", user_id=session["user_id"])

    cash_remaining = users[0]["cash"]
    total = cash_remaining

    return render_template("analysis.html", qtys=qtys, total=total, cash_remaining=cash_remaining)

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)

# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
