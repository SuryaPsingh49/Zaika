from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response
import os
import json
from datetime import datetime, UTC
from werkzeug.security import generate_password_hash, check_password_hash
from flask_moment import Moment
import psycopg2
from psycopg2 import extras
from dotenv import load_dotenv
from werkzeug.utils import secure_filename # Import secure_filename

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this-in-production')

# Configuration for file uploads
UPLOAD_FOLDER = 'static/uploads/menu_images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create upload folder if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Initialize Flask-Moment
moment = Moment(app)

# Context processor to make 'now' available in all templates
@app.context_processor
def inject_now():
    return {'now': datetime.now(UTC)}

# Custom Jinja2 filter to escape strings for JavaScript
@app.template_filter('js_string')
def js_string_filter(s):
    """Escapes a string for use in JavaScript within HTML."""
    return json.dumps(s)

# Database configuration for PostgreSQL
DATABASE_URL = os.environ.get('DATABASE_URL')
print(f"DEBUG: DATABASE_URL loaded: {DATABASE_URL}")

def allowed_file(filename):
    """Checks if the uploaded file has an allowed extension."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db_connection():
    """Establishes a connection to the PostgreSQL database."""
    if not DATABASE_URL:
        raise ValueError("DATABASE_URL environment variable not set.")
    try:
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    except Exception as e:
        print(f"Error connecting to database: {e}")
        raise

def init_db():
    """Initialize the database with tables for PostgreSQL."""
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'cook', 'biller', 'customer')),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        ''')

        # Menu items table - Added image_url column
        cur.execute('''
            CREATE TABLE IF NOT EXISTS menu_items (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                price REAL NOT NULL,
                category TEXT NOT NULL,
                image_url TEXT, -- New column for image URL (can be local path or external URL)
                available BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS orders (
                id SERIAL PRIMARY KEY,
                customer_id INTEGER NOT NULL,
                cook_id INTEGER,
                total_amount REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'received', 'preparing', 'ready', 'completed')),
                order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (customer_id) REFERENCES users (id),
                FOREIGN KEY (cook_id) REFERENCES users (id)
            );
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS order_items (
                id SERIAL PRIMARY KEY,
                order_id INTEGER NOT NULL,
                menu_item_id INTEGER NOT NULL,
                quantity INTEGER NOT NULL,
                price REAL NOT NULL,
                FOREIGN KEY (order_id) REFERENCES orders (id),
                FOREIGN KEY (menu_item_id) REFERENCES menu_items (id)
            );
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS reservations (
                id SERIAL PRIMARY KEY,
                customer_id INTEGER NOT NULL,
                customer_name TEXT NOT NULL,
                phone TEXT NOT NULL,
                email TEXT,
                table_number INTEGER,
                guest_count INTEGER NOT NULL,
                reservation_date DATE NOT NULL,
                reservation_time TIME NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'confirmed', 'cancelled', 'completed')),
                special_requests TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (customer_id) REFERENCES users (id)
            );
        ''')

        admin_password = generate_password_hash('admin123')
        cur.execute('''
            INSERT INTO users (username, email, password, role)
            VALUES ('admin', 'admin@restaurant.com', %s, 'admin')
            ON CONFLICT (username) DO NOTHING;
        ''', (admin_password,))

        conn.commit()
    except Exception as e:
        print(f"Error initializing database: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            conn.close()

with app.app_context():
    init_db()

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=extras.RealDictCursor)
            cur.execute('SELECT * FROM users WHERE username = %s', (username,))
            user = cur.fetchone()
            cur.close()

            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                flash(f'Welcome {user["username"]}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password', 'error')
        except Exception as e:
            flash(f'Database error: {e}', 'error')
            print(f"Login error: {e}")
        finally:
            if conn:
                conn.close()

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form.get('role', 'customer')

        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()

            existing_user = conn.execute('SELECT * FROM users WHERE username = %s OR email = %s',
                                   (username, email)).fetchone()

            if existing_user:
                flash('Username or email already exists', 'error')
            else:
                hashed_password = generate_password_hash(password)
                cur.execute('INSERT INTO users (username, email, password, role) VALUES (%s, %s, %s, %s)',
                            (username, email, hashed_password, role))
                conn.commit()
                flash('Registration successful! Please login.', 'success')
                cur.close()
                return redirect(url_for('login'))
        except Exception as e:
            flash(f'Database error: {e}', 'error')
            print(f"Registration error: {e}")
            if conn:
                conn.rollback()
        finally:
            if conn:
                conn.close()

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = None
    data = {}
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=extras.RealDictCursor)
        role = session['role']

        if role == 'admin':
            cur.execute('SELECT COUNT(*) as count FROM orders')
            total_orders = cur.fetchone()['count']
            cur.execute('SELECT COUNT(*) as count FROM orders WHERE status = %s', ('pending',))
            pending_orders = cur.fetchone()['count']
            cur.execute('SELECT SUM(total_amount) as total FROM orders WHERE status = %s', ('completed',))
            total_revenue = cur.fetchone()['total'] or 0
            cur.execute('SELECT COUNT(*) as count FROM users WHERE role = %s', ('customer',))
            total_customers = cur.fetchone()['count']

            cur.execute('''
                SELECT o.*, u.username as customer_name
                FROM orders o
                JOIN users u ON o.customer_id = u.id
                ORDER BY o.order_date DESC LIMIT 5
            ''')
            recent_orders = cur.fetchall()

            data = {
                'total_orders': total_orders,
                'pending_orders': pending_orders,
                'total_revenue': total_revenue,
                'total_customers': total_customers,
                'recent_orders': recent_orders
            }

        elif role == 'cook':
            cur.execute('''
                SELECT o.*, u.username as customer_name
                FROM orders o
                JOIN users u ON o.customer_id = u.id
                WHERE o.cook_id = %s AND o.status IN (%s, %s)
                ORDER BY o.order_date ASC
            ''', (session['user_id'], 'received', 'preparing'))
            assigned_orders = cur.fetchall()

            data = {'assigned_orders': assigned_orders}

        elif role == 'biller':
            cur.execute('''
                SELECT o.*, u.username as customer_name
                FROM orders o
                JOIN users u ON o.customer_id = u.id
                WHERE o.status = %s
                ORDER BY o.order_date ASC
            ''', ('ready',))
            ready_orders = cur.fetchall()

            data = {'ready_orders': ready_orders}

        else:  # customer
            cur.execute('''
                SELECT * FROM orders
                WHERE customer_id = %s
                ORDER BY order_date DESC LIMIT 10
            ''', (session['user_id'],))
            customer_orders = cur.fetchall()

            data = {'customer_orders': customer_orders}
        cur.close()
    except Exception as e:
        flash(f'Database error: {e}', 'error')
        print(f"Dashboard error: {e}")
    finally:
        if conn:
            conn.close()

    return render_template('dashboard.html', data=data)

@app.route('/menu')
def menu():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = None
    menu_items = []
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=extras.RealDictCursor)
        cur.execute('SELECT id, name, description, price, category, image_url, available, created_at FROM menu_items WHERE available = TRUE ORDER BY category, name')
        menu_items = cur.fetchall()
        cur.close()
    except Exception as e:
        flash(f'Database error: {e}', 'error')
        print(f"Menu error: {e}")
    finally:
        if conn:
            conn.close()

    return render_template('menu.html', menu_items=menu_items)

@app.route('/add_menu_item', methods=['POST'])
def add_menu_item():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    name = request.form['name']
    description = request.form['description']
    price = float(request.form['price'])
    category = request.form['category']
    image_url = request.form.get('image_url', '') # Get the image URL from the form

    # Handle file upload
    if 'image_file' in request.files:
        file = request.files['image_file']
        if file.filename != '' and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            image_url = url_for('static', filename=f'uploads/menu_images/{filename}') # Store static URL

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('INSERT INTO menu_items (name, description, price, category, image_url) VALUES (%s, %s, %s, %s, %s)',
                    (name, description, price, category, image_url))
        conn.commit()
        flash('Menu item added successfully!', 'success')
        cur.close()
    except Exception as e:
        flash(f'Database error: {e}', 'error')
        print(f"Add menu item error: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            conn.close()

    return redirect(url_for('menu'))

@app.route('/edit_menu_item/<int:item_id>', methods=['POST'])
def edit_menu_item(item_id):
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    name = request.form['name']
    description = request.form['description']
    price = float(request.form['price'])
    category = request.form['category']
    image_url = request.form.get('image_url', '') # Get existing/new URL from form
    available = True if 'available' in request.form else False

    # Handle file upload for edit
    if 'image_file' in request.files:
        file = request.files['image_file']
        if file.filename != '' and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            image_url = url_for('static', filename=f'uploads/menu_images/{filename}') # New image takes precedence

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('''
            UPDATE menu_items
            SET name = %s, description = %s, price = %s, category = %s, image_url = %s, available = %s
            WHERE id = %s
        ''', (name, description, price, category, image_url, available, item_id))
        conn.commit()
        flash('Menu item updated successfully!', 'success')
        cur.close()
    except Exception as e:
        flash(f'Database error: {e}', 'error')
        print(f"Edit menu item error: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            conn.close()

    return redirect(url_for('menu'))

@app.route('/delete_menu_item/<int:item_id>')
def delete_menu_item(item_id):
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('DELETE FROM menu_items WHERE id = %s', (item_id,))
        conn.commit()
        flash('Menu item deleted successfully!', 'success')
        cur.close()
    except Exception as e:
        flash(f'Database error: {e}', 'error')
        print(f"Delete menu item error: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            conn.close()

    return redirect(url_for('menu'))

@app.route('/place_order', methods=['POST'])
def place_order():
    if 'user_id' not in session or session['role'] != 'customer':
        return redirect(url_for('login'))

    cart_items = request.form.getlist('cart_items')
    quantities = request.form.getlist('quantities')

    if not cart_items:
        flash('Please select items to order', 'error')
        return redirect(url_for('menu'))

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        total_amount = 0
        order_items = []

        for i, item_id in enumerate(cart_items):
            quantity = int(quantities[i])
            cur.execute('SELECT * FROM menu_items WHERE id = %s', (item_id,))
            menu_item = cur.fetchone()
            if menu_item:
                item_total = menu_item[3] * quantity
                total_amount += item_total
                order_items.append({
                    'menu_item_id': item_id,
                    'quantity': quantity,
                    'price': menu_item[3]
                })

        cur.execute('''
            INSERT INTO orders (customer_id, total_amount, status)
            VALUES (%s, %s, 'pending') RETURNING id;
        ''', (session['user_id'], total_amount))

        order_id = cur.fetchone()[0]

        for item in order_items:
            cur.execute('''
                INSERT INTO order_items (order_id, menu_item_id, quantity, price)
                VALUES (%s, %s, %s, %s)
            ''', (order_id, item['menu_item_id'], item['quantity'], item['price']))

        conn.commit()
        flash(f'Order placed successfully! Order ID: {order_id}', 'success')
        cur.close()
    except Exception as e:
        flash(f'Database error: {e}', 'error')
        print(f"Place order error: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            conn.close()

    return redirect(url_for('dashboard'))

@app.route('/orders')
def orders():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = None
    orders_list = []
    cooks = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=extras.RealDictCursor)
        role = session['role']

        if role == 'admin':
            cur.execute('''
                SELECT o.*, u.username as customer_name, c.username as cook_name
                FROM orders o
                JOIN users u ON o.customer_id = u.id
                LEFT JOIN users c ON o.cook_id = c.id
                ORDER BY o.order_date DESC
            ''')
            orders_list = cur.fetchall()

            cur.execute('SELECT * FROM users WHERE role = %s', ('cook',))
            cooks = cur.fetchall()

        elif role == 'cook':
            cur.execute('''
                SELECT o.*, u.username as customer_name
                FROM orders o
                JOIN users u ON o.customer_id = u.id
                WHERE o.cook_id = %s AND o.status IN (%s, %s)
                ORDER BY o.order_date ASC
            ''', (session['user_id'], 'received', 'preparing'))
            orders_list = cur.fetchall()

        elif role == 'biller':
            cur.execute('''
                SELECT o.*, u.username as customer_name
                FROM orders o
                JOIN users u ON o.customer_id = u.id
                WHERE o.status IN (%s, %s)
                ORDER BY o.order_date DESC
            ''', ('ready', 'completed'))
            orders_list = cur.fetchall()

        else:
            cur.execute('''
                SELECT * FROM orders
                WHERE customer_id = %s
                ORDER BY order_date DESC
            ''', (session['user_id'],))
            orders_list = cur.fetchall()
        cur.close()
    except Exception as e:
        flash(f'Database error: {e}', 'error')
        print(f"Orders page error: {e}")
    finally:
        if conn:
            conn.close()

    return render_template('orders.html', orders=orders_list, cooks=cooks)

@app.route('/assign_order/<int:order_id>/<int:cook_id>')
def assign_order(order_id, cook_id):
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('UPDATE orders SET cook_id = %s, status = %s WHERE id = %s', (cook_id, 'received', order_id))
        conn.commit()
        flash('Order assigned successfully!', 'success')
        cur.close()
    except Exception as e:
        flash(f'Database error: {e}', 'error')
        print(f"Assign order error: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            conn.close()

    return redirect(url_for('orders'))

@app.route('/update_order_status/<int:order_id>/<status>')
def update_order_status(order_id, status):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    valid_statuses = ['received', 'preparing', 'ready', 'completed']
    if status not in valid_statuses:
        flash('Invalid status', 'error')
        return redirect(url_for('orders'))

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('UPDATE orders SET status = %s WHERE id = %s', (status, order_id))
        conn.commit()
        flash(f'Order status updated to {status}!', 'success')
        cur.close()
    except Exception as e:
        flash(f'Database error: {e}', 'error')
        print(f"Update order status error: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            conn.close()

    return redirect(url_for('orders'))

@app.route('/get_order_details/<int:order_id>')
def get_order_details(order_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = None
    items = []
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=extras.RealDictCursor)
        cur.execute('''
            SELECT oi.*, mi.name as item_name
            FROM order_items oi
            JOIN menu_items mi ON oi.menu_item_id = mi.id
            WHERE oi.order_id = %s
        ''', (order_id,))
        order_items = cur.fetchall()
        cur.close()

        for item in order_items:
            items.append({
                'name': item['item_name'],
                'quantity': item['quantity'],
                'price': item['price'],
                'total': item['quantity'] * item['price']
            })
    except Exception as e:
        print(f"Get order details error: {e}")
        return jsonify({'error': 'Failed to fetch order details'}), 500
    finally:
        if conn:
            conn.close()

    return jsonify({'items': items})

@app.route('/reservations')
def reservations():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = None
    reservations_list = []
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=extras.RealDictCursor)
        role = session['role']

        if role in ['admin', 'biller']:
            cur.execute('''
                SELECT r.*, u.username as customer_username
                FROM reservations r
                JOIN users u ON r.customer_id = u.id
                ORDER BY r.reservation_date DESC, r.reservation_time DESC
            ''')
            reservations_list = cur.fetchall()
        else:
            cur.execute('''
                SELECT * FROM reservations
                WHERE customer_id = %s
                ORDER BY reservation_date DESC, reservation_time DESC
            ''', (session['user_id'],))
            reservations_list = cur.fetchall()
        cur.close()
    except Exception as e:
        flash(f'Database error: {e}', 'error')
        print(f"Reservations page error: {e}")
    finally:
        if conn:
            conn.close()

    return render_template('reservations.html', reservations=reservations_list)

@app.route('/make_reservation', methods=['POST'])
def make_reservation():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    customer_name = request.form['customer_name']
    phone = request.form['phone']
    email = request.form['email']
    guest_count = int(request.form['guest_count'])
    reservation_date = request.form['reservation_date']
    reservation_time = request.form['reservation_time']
    special_requests = request.form.get('special_requests', '')

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('''
            INSERT INTO reservations
            (customer_id, customer_name, phone, email, guest_count, reservation_date, reservation_time, special_requests)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ''', (session['user_id'], customer_name, phone, email, guest_count, reservation_date, reservation_time, special_requests))
        conn.commit()
        flash('Reservation made successfully!', 'success')
        cur.close()
    except Exception as e:
        flash(f'Database error: {e}', 'error')
        print(f"Make reservation error: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            conn.close()

    return redirect(url_for('reservations'))

@app.route('/update_reservation_status/<int:reservation_id>/<status>')
def update_reservation_status(reservation_id, status):
    if 'user_id' not in session or session['role'] not in ['admin', 'biller']:
        return redirect(url_for('login'))

    valid_statuses = ['confirmed', 'cancelled', 'completed']
    if status not in valid_statuses:
        flash('Invalid status', 'error')
        return redirect(url_for('reservations'))

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('UPDATE reservations SET status = %s WHERE id = %s', (status, reservation_id))
        conn.commit()
        flash(f'Reservation status updated to {status}!', 'success')
        cur.close()
    except Exception as e:
        flash(f'Database error: {e}', 'error')
        print(f"Update reservation status error: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            conn.close()

    return redirect(url_for('reservations'))

@app.route('/bill/<int:order_id>')
def bill(order_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = None
    order = None
    order_items = []
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=extras.RealDictCursor)

        cur.execute('''
            SELECT o.*, u.username as customer_name, u.email as customer_email
            FROM orders o
            JOIN users u ON o.customer_id = u.id
            WHERE o.id = %s
        ''', (order_id,))
        order = cur.fetchone()

        if not order:
            flash('Order not found', 'error')
            return redirect(url_for('orders'))

        cur.execute('''
            SELECT oi.*, mi.name as item_name
            FROM order_items oi
            JOIN menu_items mi ON oi.menu_item_id = mi.id
            WHERE oi.order_id = %s
        ''', (order_id,))
        order_items = cur.fetchall()
        cur.close()
    except Exception as e:
        flash(f'Database error: {e}', 'error')
        print(f"Bill page error: {e}")
    finally:
        if conn:
            conn.close()

    return render_template('bill.html', order=order, order_items=order_items)

@app.route('/download_bill/<int:order_id>')
def download_bill(order_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = None
    order = None
    order_items = []
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=extras.RealDictCursor)

        cur.execute('''
            SELECT o.*, u.username as customer_name, u.email as customer_email
            FROM orders o
            JOIN users u ON o.customer_id = u.id
            WHERE o.id = %s
        ''', (order_id,))
        order = cur.fetchone()

        if not order:
            flash('Order not found', 'error')
            return redirect(url_for('orders'))

        cur.execute('''
            SELECT oi.*, mi.name as item_name
            FROM order_items oi
            JOIN menu_items mi ON oi.menu_item_id = mi.id
            WHERE oi.order_id = %s
        ''', (order_id,))
        order_items = cur.fetchall()
        cur.close()
    except Exception as e:
        flash(f'Database error: {e}', 'error')
        print(f"Download bill error: {e}")
        return redirect(url_for('orders'))
    finally:
        if conn:
            conn.close()

    order_datetime = order['order_date']

    bill_content = f"""
Zaika Restaurant - Bill
----------------------------------
Order ID: # {order['id']}
Customer: {order['customer_name']}
Date:     {order_datetime.strftime('%B %d, %Y, %I:%M:%S %p')}
----------------------------------
Items:
"""

    for item in order_items:
        bill_content += f"{item['item_name']} (x{item['quantity']}) - ${item['price']:.2f} each - Total: ${item['quantity'] * item['price']:.2f}\n"

    bill_content += f"""
----------------------------------
Grand Total: $ {order['total_amount']:.2f}
----------------------------------
Thank you for your business!
"""

    response = Response(bill_content, mimetype='text/plain')
    response.headers['Content-Disposition'] = f"attachment; filename=bill_order_{order['id']}.txt"
    return response


@app.route('/reports')
def reports():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    conn = None
    daily_sales = []
    popular_items = []
    customer_stats = []
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=extras.RealDictCursor)

        cur.execute('''
            SELECT DATE(order_date) as date, COUNT(*) as order_count, SUM(total_amount) as total_sales
            FROM orders
            WHERE status = %s
            GROUP BY DATE(order_date)
            ORDER BY date DESC
            LIMIT 30
        ''', ('completed',))
        daily_sales = cur.fetchall()

        cur.execute('''
            SELECT mi.name, SUM(oi.quantity) as total_quantity, SUM(oi.quantity * oi.price) as total_revenue
            FROM order_items oi
            JOIN menu_items mi ON oi.menu_item_id = mi.id
            JOIN orders o ON oi.order_id = o.id
            WHERE o.status = %s
            GROUP BY mi.id, mi.name
            ORDER BY total_quantity DESC
            LIMIT 10
        ''', ('completed',))
        popular_items = cur.fetchall()

        cur.execute('''
            SELECT u.username, COUNT(o.id) as order_count, SUM(o.total_amount) as total_spent
            FROM users u
            JOIN orders o ON u.id = o.customer_id
            WHERE u.role = %s AND o.status = %s
            GROUP BY u.id, u.username
            ORDER BY total_spent DESC
            LIMIT 10
        ''', ('customer', 'completed'))
        customer_stats = cur.fetchall()
        cur.close()
    except Exception as e:
        flash(f'Database error: {e}', 'error')
        print(f"Reports page error: {e}")
    finally:
        if conn:
            conn.close()

    return render_template('reports.html',
                         daily_sales=daily_sales,
                         popular_items=popular_items,
                         customer_stats=customer_stats)

@app.route('/users')
def users():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    conn = None
    users_list = []
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=extras.RealDictCursor)
        cur.execute('SELECT * FROM users ORDER BY role, username')
        users_list = cur.fetchall()
        cur.close()
    except Exception as e:
        flash(f'Database error: {e}', 'error')
        print(f"Users page error: {e}")
    finally:
        if conn:
            conn.close()

    return render_template('users.html', users=users_list)

@app.route('/add_user', methods=['POST'])
def add_user():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    role = request.form['role']

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        existing_user = conn.execute('SELECT * FROM users WHERE username = %s OR email = %s',
                               (username, email)).fetchone()

        if existing_user:
            flash('Username or email already exists', 'error')
        else:
            hashed_password = generate_password_hash(password)
            cur.execute('INSERT INTO users (username, email, password, role) VALUES (%s, %s, %s, %s)',
                        (username, email, hashed_password, role))
            conn.commit()
            flash('User added successfully!', 'success')
        cur.close()
    except Exception as e:
        flash(f'Database error: {e}', 'error')
        print(f"Add user error: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            conn.close()

    return redirect(url_for('users'))

@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    if user_id == session['user_id']:
        flash('Cannot delete your own account', 'error')
        return redirect(url_for('users'))

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('DELETE FROM users WHERE id = %s', (user_id,))
        conn.commit()
        flash('User deleted successfully!', 'success')
        cur.close()
    except Exception as e:
        flash(f'Database error: {e}', 'error')
        print(f"Delete user error: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            conn.close()

    return redirect(url_for('users'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('FLASK_DEBUG') == '1')
