from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from werkzeug.utils import secure_filename
import os
import mysql.connector
from flask_login import LoginManager, login_user, login_required, current_user, UserMixin, logout_user

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a more secure key in production
app.config['UPLOAD_FOLDER'] = 'static/images'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}


# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth_page'  # Set the login view

def get_db_connection():
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database="data"
        )
        return conn
    except mysql.connector.Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']
           
@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(user_id)
@app.route('/logout')
@login_required  # Ensure user is logged in to access this route
def logout():
    logout_user()  # This logs out the user
    flash('You have been logged out.', category='success')
    return redirect(url_for('home'))
@app.route('/update_profile', methods=['GET', 'POST'])
@login_required
def update_profile():
    if request.method == 'POST':
        # Retrieve form data
        email = request.form.get('email')
        username = request.form.get('username')
        first_name = request.form.get('first_name')
        bio = request.form.get('bio')

        # Check if profile_picture is in request files
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file.filename != '' and allowed_file(file.filename):
                # Secure the filename and save the file to the UPLOAD_FOLDER
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                try:
                    file.save(file_path)
                    print(f"Profile picture saved successfully to {file_path}")
                    image_path = filename
                except Exception as e:
                    print(f"Error saving profile picture: {str(e)}")
                    image_path = current_user.image_path  # Use the current image if there's an error
            else:
                print("Invalid file or no file selected, using the current image path.")
                image_path = current_user.image_path  # Use the current image if the file is invalid
        else:
            print("No profile_picture in request.files, using the current image path.")
            image_path = current_user.image_path  # Fallback to current user's image path

        # Get the database connection
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            try:
                # Update user information in the database
                cursor.execute("""
                    UPDATE users SET email = %s, username = %s, first_name = %s, bio = %s, image_path = %s WHERE id = %s
                """, (email, username, first_name, bio, image_path, current_user.id))
                conn.commit()

                # Reflect changes in the current_user object for the current session
                current_user.email = email
                current_user.username = username
                current_user.first_name = first_name
                current_user.bio = bio
                current_user.image_path = image_path

                flash('Profile updated successfully!', category='success')
                print("Profile updated successfully in the database.")
            except mysql.connector.Error as e:
                conn.rollback()
                print(f"Database error: {str(e)}")
                flash(f'An error occurred: {str(e)}', category='error')
            finally:
                cursor.close()
                conn.close()

        return redirect(url_for('profile'))

    return render_template('update_profile.html', user=current_user)



@app.route('/profile')
def profile():
    return render_template('viewprofile.html', user=current_user)
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password  = request.form.get('current_password')
        new_password =  request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not check_password_hash(current_user.password, current_password):
            flash('Current password is incorrect')
            return render_template('change_pass.html', user=current_user)

        elif new_password != confirm_password:
            flash("New or Confirm password doesn't match")
            return render_template('change_pass.html', user=current_user)

        elif len(new_password) < 7:
            flash('Password is too short')
        else:
            hash_password = generate_password_hash(new_password,  method='pbkdf2:sha256')
            
            conn = get_db_connection()
            if conn:
                cursor = conn.cursor()
                try:
                    cursor.execute(""" UPDATE users SET password = %s WHERE id = %s """, (hash_password, current_user.id))
                    conn.commit()
                    flash('Password updated successfully', category='success')
                    return redirect(url_for('profile'))
                except mysql.connector.Error as e:
                    conn.rollback()
                    flash(f'An error occurred: {str(e)}', category='error')
                finally:
                    cursor.close()
                    conn.close()
        return redirect(url_for('profile'))

    return render_template('change_pass.html', user=current_user)

@app.route('/', methods=['GET', 'POST'])
def home():
    if current_user.is_authenticated:
        # Check if the authenticated user has an image path, else use a default image
        profile_image = current_user.image_path if current_user.image_path else 'default_profile.png'
    else:
        # For anonymous users, use a default image
        profile_image = 'default_profile.png'

    if 'user_id' in session:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT * FROM users WHERE id = %s', (session['user_id'],))
            user = cursor.fetchone()
            cursor.close()
            conn.close()
    return render_template('home.html', user=current_user, profile_image=profile_image)  # Ensure user is always passed

@app.route('/login', methods=['GET', 'POST'])
def auth_page():
    if request.method == 'POST':
        if 'login' in request.form:
            email = request.form.get('email')
            password = request.form.get('password')

            user = User.get_by_email(email)  # Fetch user by email
            if user:
                if check_password_hash(user.password, password):
                    session['user_id'] = user.id
                    login_user(user, remember=True)

                    flash('Logged in successfully!', category='success')
                    return redirect(url_for('home'))  # Redirect to home
                else:
                    flash('Invalid email or password.', category='error')
            else:
                flash('No user found with this email.', category='error')

        elif 'sign_up' in request.form:
            email = request.form.get('email')
            first_name = request.form.get('firstName')
            username = request.form.get('username')
            password1 = request.form.get('password1')
            password2 = request.form.get('password2')
            
            existing_user = User.get_by_email(email)
            
            if existing_user:
                flash('Email already exists', category='error')
            elif len(email) < 4:
                flash('Email must be greater than 4 characters', category='error')
            elif len(first_name) < 2:
                flash('First Name must be greater than 2 characters', category='error')
            elif password1 != password2:
                flash('Passwords do not match', category='error')
            elif len(password1) < 7:
                flash('Password must be at least 7 characters', category='error')
            else:
                hashed_password = generate_password_hash(password1, method='pbkdf2:sha256')

                connection = get_db_connection()
                cursor = connection.cursor()
                try:
                    cursor.execute(""" 
                        INSERT INTO users (email, username, first_name, password, date_joined, image_path) 
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (email, username, first_name, hashed_password, datetime.now(), 'default.jpg'))  # Add default image path
                    connection.commit()
                    
                    new_user = User.get_by_email(email)
                    login_user(new_user, remember=True)
              
                    flash('Account created successfully!', category="success")
                    return redirect(url_for('home'))
                except Exception as e:
                    connection.rollback()
                    flash(f'An error occurred: {str(e)}', category='error')
                finally:
                    cursor.close()
                    connection.close()

    return render_template('register.html', user=current_user)  # Always pass user to template

@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    if request.method == 'POST':
        product_names = request.form.getlist('product_name[]')
        current_prices = request.form.getlist('current_price[]')
        previous_prices = request.form.getlist('previous_price[]')
        in_stocks = request.form.getlist('in_stock[]')
        flash_sales = request.form.getlist('flash_sale[]')
        date_addeds = request.form.getlist('date_added[]')

        # Handle multiple product pictures
        product_pictures = request.files.getlist('product_picture[]')

        # Use zip to safely iterate over multiple lists
        for i, (product_name, current_price, previous_price, in_stock, flash_sale, date_added) in enumerate(zip(product_names, current_prices, previous_prices, in_stocks, flash_sales, date_addeds)):
            print(f"Adding product: {product_name}, Current Price: {current_price}, Previous Price: {previous_price}, In Stock: {in_stock}, Flash Sale: {flash_sale}, Date Added: {date_added}")

            if product_pictures[i].filename != '' and allowed_file(product_pictures[i].filename):
                filename = secure_filename(product_pictures[i].filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                try:
                    product_pictures[i].save(file_path)
                    product_picture = filename
                except Exception as e:
                    product_picture = 'default_product.png'
            else:
                product_picture = 'default_product.png'

            # Insert into the database for each product
            Product.add_products(
                product_name,
                current_price,
                previous_price,
                in_stock,
                product_picture,
                flash_sale,
                date_added
            )

        flash('Products added successfully')
        return redirect(url_for('products'))

    return render_template('add_product.html', user=current_user)


@app.route('/products', methods=['GET'])
def products():
    page = request.args.get('page', 1, type=int)
    limit = 20  # Number of products per page
    offset = (page - 1) * limit
    products = Product.get_all(limit, offset)
    return render_template('products.html', products=products, page=page, user=current_user)
    


class User(UserMixin):
    def __init__(self, id, email, username, first_name, password, date_joined, image_path, bio):
        self.id = id
        self.email = email
        self.username = username
        self.first_name = first_name
        self.password = password
        self.date_joined = date_joined
        self.image_path = image_path
        self.bio = bio
        

    @staticmethod
    def get_by_email(email):
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        try:
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user_data = cursor.fetchone()
            if user_data:
                return User(
                    user_data['id'], 
                    user_data['email'], 
                    user_data['username'], 
                    user_data['first_name'], 
                    user_data['password'],
                    user_data['date_joined'],
                    user_data['image_path'],
                    user_data['bio']
                )
            return None
        finally:
            cursor.close()
            connection.close()

    @staticmethod
    def get_by_id(user_id):
        connection = get_db_connection()  # Get a new connection
        cursor = connection.cursor(dictionary=True)  # Create a cursor
        try:
            cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            user_data = cursor.fetchone()
            if user_data:
                return User(
                    user_data['id'], 
                    user_data['email'], 
                    user_data['username'], 
                    user_data['first_name'], 
                    user_data['password'],
                    user_data['date_joined'],
                    user_data['image_path'],
                    user_data['bio']
                )
            return None
        finally:
            cursor.close() 
            connection.close()
class Product:
    def __init__(self, id, product_name, current_price, previous_price, in_stock, product_picture, flash_sale, date_added):
        self.id = id
        self.product_name = product_name
        self.current_price = current_price
        self.previous_price = previous_price
        self.in_stock = in_stock
        self.product_picture = product_picture
        self.flash_sale = flash_sale
        self.date_added = date_added

    @staticmethod
    def get_all(limit=None, offset=None):
        query = "SELECT * FROM product"
        if limit:
            query += " LIMIT %s OFFSET %s"  # Add pagination clause

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        if limit:
            cursor.execute(query, (limit, offset))
        else:
            cursor.execute(query)

        products = cursor.fetchall()
        cursor.close()
        connection.close()
        return products
    @staticmethod
    def add_products(product_name, current_price, previous_price, in_stock, product_picture, flash_sale, date_added):
        connection = get_db_connection()
        cursor = connection.cursor()
        try:
            cursor.execute(
                "INSERT INTO product (product_name, current_price, previous_price, in_stock, product_picture, flash_sale, date_added) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (product_name, current_price, previous_price, in_stock, product_picture, flash_sale, date_added)
            )
            connection.commit()
        except Exception as e:
            print(f"Error inserting product: {e}")  # Log the error
            connection.rollback()  # Rollback if there's an error
        finally:
            cursor.close()
            connection.close()


if __name__ == '__main__':
    app.run(debug=True)
