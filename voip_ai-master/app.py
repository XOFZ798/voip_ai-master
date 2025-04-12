from flask import Flask, request, render_template, redirect, url_for, flash, session
from werkzeug.security import check_password_hash, generate_password_hash
from src.model import LoginUser, User, validate_phone

app = Flask(__name__)
app.config["SECRET_KEY"] = "your-secret-key-here"  # یه کلید امن بذار


# دکوراتور برای محافظت مسیرها
def login_required(f):
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("لطفاً اول وارد شوید!", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    wrapper.__name__ = f.__name__
    return wrapper


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        try:
            user = LoginUser.get(LoginUser.email == email)
            if check_password_hash(user.password, password):
                session["user_id"] = user.id
                flash("ورود با موفقیت انجام شد!", "success")
                return redirect(url_for("main"))
            else:
                flash("رمز عبور نادرست است.", "error")
        except LoginUser.DoesNotExist:
            flash("کاربری با این ایمیل یافت نشد.", "error")

    return render_template("form.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        try:
            if LoginUser.get(LoginUser.email == email):
                flash("این ایمیل قبلاً ثبت شده است!", "error")
                return redirect(url_for("register"))
        except LoginUser.DoesNotExist:
            hashed_password = generate_password_hash(password)
            LoginUser.create(email=email, password=hashed_password)
            flash("ثبت‌نام با موفقیت انجام شد!", "success")
            return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/main", methods=["GET", "POST"])
@login_required
def main():
    query = request.form.get("query")
    if query:
        users = User.select().where(
            (User.name.contains(query))
            | (User.telephone.contains(query))
            | (User.coldrooms_code.contains(query))
        )
    else:
        users = User.select()

    return render_template("index.html", users=users)


@app.route("/delete_user/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    try:
        user = User.get(user_id)
        user.delete_instance()
        flash("کاربر با موفقیت حذف شد!", "success")
    except Exception as e:
        flash(f"خطا در حذف کاربر: {str(e)}", "error")
    return redirect(url_for("main"))


@app.route("/add_user", methods=["POST"])
@login_required
def add_user():
    name = request.form["name"]
    telephone = validate_phone(request.form["telephone"])
    city = request.form["city"]
    coldrooms_code = request.form["coldrooms_code"]
    coldrooms_phone = validate_phone(request.form["coldrooms_phone"])

    if not telephone:
        flash("شماره تلفن نامعتبر است.", "error")
        return render_template("index.html", users=User.select())

    try:
        User.create(
            name=name,
            telephone=telephone,
            city=city,
            coldrooms_code=coldrooms_code,
            coldrooms_phone=coldrooms_phone,
        )
        flash("اطلاعات با موفقیت ثبت شد.", "success")
    except Exception as e:
        flash(f"خطا در ذخیره اطلاعات: {str(e)}", "error")

    return render_template("index.html", users=User.select())


@app.route("/edit_user/", methods=["POST"])
@login_required
def edit_user():
    try:
        id = request.form["id"]
        user = User.get(User.id == id)
        rows_updated = (
            User.update(
                name=request.form["name"],
                telephone=request.form["telephone"],
                city=request.form["city"],
                coldrooms_code=request.form["coldrooms_code"],
                coldrooms_phone=request.form["coldrooms_phone"],
            )
            .where(User.id == id)
            .execute()
        )
        flash("کاربر با موفقیت ویرایش شد!", "success")
    except Exception as e:
        flash(f"خطا در ویرایش کاربر: {str(e)}", "error")

    return render_template("index.html", users=User.select())


@app.route("/logout")
@login_required
def logout():
    session.pop("user_id", None)
    flash("شما با موفقیت خارج شدید!", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
