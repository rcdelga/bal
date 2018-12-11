from flask import Flask, request, redirect, render_template, session, flash
from flask_sqlalchemy import SQLAlchemy
import cgi
import random
import hashlib
import string
import csv
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename
import codecs


# Start App Setup
app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://balto:balto@localhost:8889/balto'
app.config['SQLALCHEMY_ECHO'] = True
app.secret_key = 'YGz1lp3gm5S15E2EkH77'

db = SQLAlchemy(app)
# End App Setup


# Start Models - Note to self: Any changes to this section will result in having to drop and recreate the database.
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(120))
    movies = db.relationship('Movie', backref='owner')
    
    def __init__(self, email, password):
        self.email = email
        self.password = make_pw_hash(password)
    
    def __repr__(self):
        return '<User %r>' % self.email

class Movie(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    year = db.Column(db.Integer)
    title = db.Column(db.String(120))
    origin = db.Column(db.String(120))
    director = db.Column(db.String(120))
    cast = db.Column(db.String(120))
    genre = db.Column(db.String(120))
    wiki = db.Column(db.String(120))
    plot = db.Column(db.Text())
    deleted = db.Column(db.Boolean)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __init__(self, title, year, origin, director, cast, genre, wiki, plot, owner):
        self.title = title
        self.year = year
        self.origin = origin
        self.director = director
        self.cast = cast
        self.genre = genre
        self.wiki = wiki
        self.plot = plot
        self.deleted = False
        self.owner = owner

    def __repr__(self):
        return '<Movie %r %r>' % (self.id, self.title)
# End Models


# Start Functions
def make_salt():
	return ''.join([random.choice(string.ascii_letters) for x in range(5)])

def make_pw_hash(password, salt=None):
	if not salt:
		salt = make_salt()
	hash = hashlib.sha256(str.encode(password)).hexdigest()
	return '{0},{1}'.format(hash, salt)

def check_pw_hash(password, hash):
	salt = hash.split(',')[1]
	if make_pw_hash(password, salt) == hash:
		return True
	return False

def is_email(string):
    atsign_index = string.find('@')
    atsign_present = atsign_index >= 0
    if not atsign_present:
        return False
    else:
        domain_dot_index = string.find('.', atsign_index)
        domain_dot_present = domain_dot_index >= 0
        return domain_dot_present

def existing_user(email):
	return User.query.filter_by(email=email).first()

def add_user(email,password):	
	db.session.add(User(email,password))
	db.session.commit()

def get_current_movielist(current_user_id):
    return Movie.query.filter_by(deleted=False, owner_id=current_user_id).all()

def get_deleted_movies(current_user_id):
    return Movie.query.filter_by(deleted=True, owner_id=current_user_id).all()

def logged_in_user():
    owner = User.query.filter_by(email=session['user']).first()
    return owner
# End Functions



# Start Routes

# Redirect user to login if not logged in
allowed_routes = ['login', 'register']
@app.before_request
def require_login():
	if (request.endpoint not in allowed_routes
		and '/static/' not in request.path
		and 'user' not in session):
		return redirect('/login')

# Login Page
@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        users = User.query.filter_by(email=email)
        if users.count() == 1:
            user = users.first()
            if check_pw_hash(password,user.password):
                session['user'] = user.email
                flash(f"{user.email}! Good to see you again!")
                return redirect("/")
        flash('Invalid email or password.')
        return redirect("/login")

# Registry Page
@app.route("/register", methods=['GET', 'POST'])
def register():
	if request.method == 'POST':

		entries = {'email':request.form['email'],
					'password1':request.form['password1'],
					'verify':request.form['verify']}
		errors = {}

		for entry in entries:
			if not 5 < len(entries[entry]) < 25 and ' ' not in entries[entry]:
				errors[entry+'_error'] = "Invalid Entry: Requires 5-25 characters with no spaces."
				if entry == 'email':
					entries[entry] = ''
		if not is_email(entries['email']):
			flash(f"{entries['email']} is an invalid email")
			return redirect('/register')
		if entries['password1'] != entries['verify']:
			error = "Passwords do not match."
			errors['password1_error'] = error
			errors['verify_error'] = error
		if existing_user(entries['email']):
			errors['email_error'] = "[{0}] is already registered.".format(entries['email'])
			del entries['email']
		if errors:
			del entries['password1']
			del entries['verify']
			return render_template('register.html', **entries, **errors)
		add_user(entries['email'],entries['password1'])
		session['user'] = entries['email']
		return redirect('/')
	return render_template('register.html')

# Main Page: Shows list of movies for user
@app.route("/")
def index():
    encoded_error = request.args.get("error")
    return render_template('index.html', movielist=get_current_movielist(logged_in_user().id), error=encoded_error and cgi.escape(encoded_error, quote=True))

# Remove movie from user's list
@app.route("/remove", methods=['POST'])
def remove_movie():
    remove_movie_id = request.form['remove-movie']

    remove_movie = Movie.query.get(remove_movie_id)
    if not remove_movie:
        return redirect("/?error=Cannot remove a movie not in database.")

    db.session.delete(remove_movie)
    db.session.commit()
    return redirect('/')


# Adds Movie at POST or renders the add movie form at GET
@app.route("/add_movie", methods=['GET','POST'])
def add_movie():
	if request.method == 'POST':
		entries = {'title' : request.form['title'],
					'year' : request.form['year'],
					'origin' : request.form['origin'],
					'director' : request.form['director'],
					'cast' : request.form['cast'],
					'genre' : request.form['genre'],
					'wiki' : request.form['wiki'],
					'plot' : request.form['plot']}

		errors = {}

		movie = Movie(entries['title'],
					entries['year'],
					entries['origin'],
					entries['director'],
					entries['cast'],
					entries['genre'],
					entries['wiki'],
					entries['plot'],
					logged_in_user())
		db.session.add(movie)
		db.session.commit()
		return redirect('/')
	return render_template("add.html")

# Directs to an edit page with the selected movie ID's fields
@app.route("/edit", methods=["POST"])
def edit():
	edit_movie_id = request.form['edit-movie']
	edit_movie = Movie.query.get(edit_movie_id)
	if not edit_movie:
		return redirect("/?error=Cannot edit a movie not in database.")
	return render_template("edit.html",movie=edit_movie)

# Submits the edited fields to the database
@app.route("/edit_movie", methods=["POST"])
def edit_movie():
	entries = {'id' : request.form['id'],
			'title' : request.form['title'],
			'year' : request.form['year'],
			'origin' : request.form['origin'],
			'director' : request.form['director'],
			'cast' : request.form['cast'],
			'genre' : request.form['genre'],
			'wiki' : request.form['wiki'],
			'plot' : request.form['plot']}

	errors = {}

	movie_to_edit = Movie.query.get(entries['id'])
	movie_to_edit.title = entries['title']
	movie_to_edit.year = entries['year']
	movie_to_edit.origin = entries['origin']
	movie_to_edit.director = entries['director']
	movie_to_edit.cast = entries['cast']
	movie_to_edit.genre = entries['genre']
	movie_to_edit.wiki = entries['wiki']
	movie_to_edit.plot = entries['plot']

	db.session.add(movie_to_edit)
	db.session.commit()
	return redirect("/")

# Displays search form at GET and submits the form at POST with the selected searchCategory and searchTerm
@app.route("/search", methods=['GET', 'POST'])
def search():
	if request.method == 'POST':
		searchCategory = request.form['category']
		searchTerm = request.form['searchTerm']
		if searchCategory == "title":
			result_list = Movie.query.filter(Movie.title.contains(searchTerm))
		if searchCategory == "year":
			result_list = Movie.query.filter(Movie.year.contains(searchTerm))
		if searchCategory == "origin":
			result_list = Movie.query.filter(Movie.origin.contains(searchTerm))
		if searchCategory == "director":
			result_list = Movie.query.filter(Movie.director.contains(searchTerm))
		if searchCategory == "cast":
			result_list = Movie.query.filter(Movie.cast.contains(searchTerm))
		if searchCategory == "genre":
			result_list = Movie.query.filter(Movie.genre.contains(searchTerm))
		if searchCategory == "plot":
			result_list = Movie.query.filter(Movie.plot.contains(searchTerm))
		return render_template("search.html",movie_list=result_list)
	return render_template("search.html")

# Allows user to upload a CSV file
@app.route("/upload", methods=['GET','POST'])
def upload():
	if request.method == 'POST':
		file = request.files['inputFile']
		# print(f"{file._file} some thing here so that we know")

		bytes_str = file._file.read()
		string_var = bytes_str.decode('UTF-8')

		# FileStorage(file).save("/upload.csv")
		# newFile = open("/upload.csv", "rb")

		try:

			reader = csv.reader(string_var.splitlines(), delimiter=',')
			firstline = True
			for row in reader:
				if firstline:
					firstline= False
					continue
				else:
					new_movie = Movie(row[1],row[0],row[2],row[3],row[4],row[5],row[6],row[7],logged_in_user())
					db.session.add(new_movie)
					db.session.commit()					
		except:
			error = "Failed to Upload"
			return render_template("index.html",error=error)
		return redirect("/")	

	return render_template("upload.html")


# Logs user out of system
@app.route("/logout", methods=['POST'])
def logout():
    del session['user']
    return redirect("/")


if __name__ == "__main__":
    app.run()