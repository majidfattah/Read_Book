from flask import Flask, render_template, redirect, session, flash, request
from flask_bcrypt import Bcrypt
from mysqlconnection import connectToMySQL
import re

app = Flask(__name__)
app.secret_key = "ReadGoodBook"
bcrypt = Bcrypt(app)
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['POST'])
def register():
    # All validation below:
    error = False
    for key, val in request.form.items():
        if len(val) == 0:
            flash(key + ' cannot be empty.', 'register')
            error = True
        if len(val) < 1:
            flash(key + ' cannot be more than 60 characters', 'register')
            error = True
    if len(request.form['password']) > 0 and len(request.form['password']) < 8:
        flash('password must be at least 8 characters.', 'register')
        error = True
    if request.form['confirm_password'] != request.form['password']:
        flash('confrim password must match password', 'register')
        error = True
    if len(request.form['email']) > 0 and not EMAIL_REGEX.match(request.form['email']):
        flash('invalid email address.', 'register')
        error = True
    else:
        exists_query = 'SELECT id FROM users WHERE email = %(email)s;'
        exists_data = {'email': request.form['email']}
        mysql = connectToMySQL('DojoRead')
        exists = mysql.query_db(exists_query, exists_data)
    if len(exists) != 0:
            flash('email already in database, please log in.', 'register')
            error = True
    if error:
        return redirect('/')

    # Passed validation at this point, so INSERT into database
    insert_query = 'INSERT INTO users (first_name, last_name, email, password) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s);'
    pw_hash = bcrypt.generate_password_hash(request.form['password'])
    insert_data = {'first_name': request.form['first_name'],'last_name': request.form['last_name'], 'email': request.form['email'], 'password': pw_hash}
    mysql = connectToMySQL('DojoRead')
    new_id = mysql.query_db(insert_query, insert_data)
    session['user_id'] = new_id
    return redirect('/')


# Login
@app.route('/login', methods=['POST'])
def login():
    email_query = 'SELECT * FROM users WHERE email = %(email)s;'
    email_data = {'email': request.form['email']}
    mysql = connectToMySQL('DojoRead')
    result = mysql.query_db(email_query, email_data)
    if len(result) == 0:
        flash('invalid login, try again.', 'login')
        return redirect('/')
    if not bcrypt.check_password_hash(result[0]['password'], request.form['password']):
        flash('invalid login, try again.', 'login')
        return redirect('/')
    session['user_id'] = result[0]['id']
    return redirect('/books')

# Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


@app.route('/books')
def jobs():
    # test if user is logged in
    if 'user_id' not in session:
        flash('please log in first.', 'login')
        return redirect('/')

    # get info for logged in user
    mysql = connectToMySQL('DojoRead')
    user_query = 'SELECT * FROM users WHERE id = %(id)s;'
    user_data = {'id': session['user_id']}
    user_info = mysql.query_db(user_query, user_data)

    # get all jobs name
    mysql = connectToMySQL("DojoRead")
    jobs = mysql.query_db("SELECT * FROM jobs;")

    #get the job along to current user
    mysql = connectToMySQL("DojoRead")
    job_query = 'SELECT * FROM jobs WHERE user_id = %(id)s;'
    job_data = {'id': session['user_id']}
    job_info = mysql.query_db(job_query, job_data)

    print(jobs)
    return render_template("dashboard.html" , jobs=jobs, user_job=job_info, user=user_info[0])



if __name__ == '__main__':
    app.run(debug=True)
