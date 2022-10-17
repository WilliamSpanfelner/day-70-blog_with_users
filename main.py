import bleach
from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, NewCommentForm
from flask_gravatar import Gravatar
from functools import wraps
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)

YEAR = date.today().year

# CONNECT TO DB
uri = os.getenv("DATABASE_URL", "sqlite:///blog.db")
print(f"uri is {uri}")
if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# CONFIGURE TABLES
class Comment(db.Model):  # child
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)

    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    author = relationship("User", back_populates='comments')

    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    parent_post = relationship("BlogPost", back_populates='comments')


class BlogPost(db.Model):  # child of user # parent to comments
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    author = relationship("User", back_populates='posts')

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    comments = relationship("Comment", back_populates='parent_post')


# Create a login manager and initialize it.
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


class User(UserMixin, db.Model):  # parent
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))

    posts = relationship("BlogPost", back_populates='author')
    comments = relationship("Comment", back_populates='author')


with app.app_context():
    db.create_all()


# Create the user loader for a session cookie
@login_manager.user_loader
def load_user(user_id):
    # user_id is the primary key of the User table
    return User.query.get(user_id)


def admin_only(function):
    @wraps(function)
    def decorator(*args, **kwargs):
        if current_user.is_anonymous:
            return "<h1>Forbidden</h1><p>Insufficient access privileges to perform this action.</p>", 403
        elif current_user.id == 1 or current_user.id == 2:
            return function(*args, **kwargs)
        return "<h1>Forbidden</h1><p>Insufficient access privileges to perform this action.</p>", 403

    return decorator


def sanitize(content):
    """Returns 'clean' HTML content from CKEditor
    content: text
    return: text
    """
    allowed_tags = [
        'a', 'abbr', 'acronym', 'address', 'b', 'br', 'div', 'dl', 'dt',
        'em', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr', 'i', 'img',
        'li', 'ol', 'p', 'pre', 'q', 's', 'small', 'strike',
        'span', 'sub', 'sup', 'table', 'tbody', 'td', 'tfoot', 'th',
        'thead', 'tr', 'tt', 'u', 'ul'
    ]

    allowed_attrs = {
        'a': ['href', 'target', 'title'],
        'img': ['src', 'alt', 'width', 'height'],
    }

    cleaned = bleach.clean(content,
                           tags=allowed_tags,
                           attributes=allowed_attrs,
                           strip=True)
    return cleaned


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.order_by(BlogPost.id.desc()).all()
    return render_template("index.html", all_posts=posts, yr=YEAR)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        name = form.name.data

        existing_user = User.query.filter_by(email=email).first()  # a user exists if this line returns a result
        if existing_user:
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        hashed_pw = generate_password_hash(password, method="pbkdf2:sha256", salt_length=8)
        new_user = User(email=email, name=name, password=hashed_pw)

        db.session.add(new_user)
        db.session.commit()

        # Create a session cookie for the user
        login_user(new_user)
        return redirect(url_for('get_all_posts'))

    return render_template("register.html", form=form, yr=YEAR)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        existing_user = User.query.filter_by(email=email).first()  # if this query returns something all systems go

        # Prevent crash from checking non-existent user password
        try:
            # Compare passwords if possible
            pw_good = check_password_hash(existing_user.password, password)
        except AttributeError:
            # Arriving here means no user with email entered is in db.
            flash("No record of that email exists. Please try again.")
            return redirect(url_for('login'))
        else:
            # Here the user must be in db.  Check if pw is good, otherwise error.
            if pw_good:
                login_user(existing_user)
                return redirect(url_for('get_all_posts'))
            flash('Incorrect password. Please check credentials and try again.')
            return redirect(url_for('login'))

    return render_template("login.html", form=form, yr=YEAR)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    form = NewCommentForm()
    requested_post = BlogPost.query.get(post_id)
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("Please login or register to comment.")
            return redirect(url_for('login'))

        print("Your comments will be logged.")
        new_comment = Comment(
            text=form.comment.data,
            author_id=current_user.id,
            post_id=post_id
        )
        db.session.add(new_comment)
        db.session.commit()

    return render_template("post.html", post=requested_post, form=form, yr=YEAR)


@app.route("/about")
def about():
    return render_template("about.html", yr=YEAR)


@app.route("/contact")
def contact():
    return render_template("contact.html", yr=YEAR)


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=sanitize(form.body.data),
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, yr=YEAR)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        # author=post.author,  # look at this should it be set to current_user?
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        # post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, yr=YEAR)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
