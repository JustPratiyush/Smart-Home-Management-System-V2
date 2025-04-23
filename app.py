from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import os
import bcrypt
from config import Config
from database.db_config import get_db_connection, fetch_all, fetch_one, insert_data, update_data, delete_data
from functools import wraps

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'error')
            return redirect(url_for('login'))
        if not session.get('is_admin'):
            flash('Admin privileges required', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = fetch_one("SELECT * FROM users WHERE email = %s", (email,))
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            session['user_id'] = user['user_id']
            session['user_name'] = user['name']
            session['is_admin'] = user['is_admin']
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        contact = request.form['contact']
        address = request.form['address']
        
        # Check if email already exists
        existing_user = fetch_one("SELECT * FROM users WHERE email = %s", (email,))
        if existing_user:
            flash('Email already registered', 'error')
            return render_template('register.html')
        
        # Hash password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Insert new user
        user_id = insert_data(
            "INSERT INTO users (name, email, password, contact_number, address) VALUES (%s, %s, %s, %s, %s)",
            (name, email, hashed_password, contact, address)
        )
        
        if user_id:
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Registration failed', 'error')
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    is_admin = session.get('is_admin', False)
    
    # Get counts for dashboard
    room_count = fetch_one("SELECT COUNT(*) as count FROM rooms WHERE user_id = %s", (user_id,))
    device_count = fetch_one("SELECT COUNT(*) as count FROM devices WHERE user_id = %s", (user_id,))
    sensor_count = fetch_one("""
        SELECT COUNT(*) as count FROM sensors 
        WHERE room_id IN (SELECT room_id FROM rooms WHERE user_id = %s)
    """, (user_id,))
    rule_count = fetch_one("""
        SELECT COUNT(*) as count FROM automation_rules 
        WHERE device_id IN (SELECT device_id FROM devices WHERE user_id = %s)
    """, (user_id,))
    
    counts = {
        'rooms': room_count['count'] if room_count else 0,
        'devices': device_count['count'] if device_count else 0,
        'sensors': sensor_count['count'] if sensor_count else 0,
        'rules': rule_count['count'] if rule_count else 0
    }
    
    return render_template('dashboard.html', counts=counts, is_admin=is_admin)

# User management routes (admin only)
@app.route('/users')
@admin_required
def users():
    users_list = fetch_all("SELECT * FROM users")
    return render_template('users.html', users=users_list)

@app.route('/api/users', methods=['GET', 'POST', 'PUT', 'DELETE'])
@admin_required
def manage_users():
    if request.method == 'GET':
        users_list = fetch_all("SELECT user_id, name, email, contact_number, address, is_admin FROM users")
        return jsonify(users_list)
    
    elif request.method == 'POST':
        data = request.json
        name = data.get('name')
        email = data.get('email')
        password = data.get('password')
        contact = data.get('contact')
        address = data.get('address')
        is_admin = data.get('is_admin', False)
        
        # Check if email already exists
        existing_user = fetch_one("SELECT * FROM users WHERE email = %s", (email,))
        if existing_user:
            return jsonify({'success': False, 'message': 'Email already registered'})
        
        # Hash password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Insert new user
        user_id = insert_data(
            "INSERT INTO users (name, email, password, contact_number, address, is_admin) VALUES (%s, %s, %s, %s, %s, %s)",
            (name, email, hashed_password, contact, address, is_admin)
        )
        
        if user_id:
            return jsonify({'success': True, 'user_id': user_id})
        else:
            return jsonify({'success': False, 'message': 'Failed to create user'})
    
    elif request.method == 'PUT':
        data = request.json
        user_id = data.get('user_id')
        name = data.get('name')
        email = data.get('email')
        contact = data.get('contact')
        address = data.get('address')
        is_admin = data.get('is_admin', False)
        
        # Check if email already exists for another user
        existing_user = fetch_one("SELECT * FROM users WHERE email = %s AND user_id != %s", (email, user_id))
        if existing_user:
            return jsonify({'success': False, 'message': 'Email already registered to another user'})
        
        # Update user
        success = update_data(
            "UPDATE users SET name = %s, email = %s, contact_number = %s, address = %s, is_admin = %s WHERE user_id = %s",
            (name, email, contact, address, is_admin, user_id)
        )
        
        if success:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Failed to update user'})
    
    elif request.method == 'DELETE':
        user_id = request.json.get('user_id')
        
        # Don't allow deletion of own account
        if int(user_id) == session['user_id']:
            return jsonify({'success': False, 'message': 'Cannot delete your own account'})
        
        # Delete user
        success = delete_data("DELETE FROM users WHERE user_id = %s", (user_id,))
        
        if success:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Failed to delete user'})

# Room management routes
@app.route('/rooms')
@login_required
def rooms():
    user_id = session['user_id']
    is_admin = session.get('is_admin', False)
    
    if is_admin:
        rooms_list = fetch_all("SELECT * FROM rooms")
    else:
        rooms_list = fetch_all("SELECT * FROM rooms WHERE user_id = %s", (user_id,))
    
    users_list = fetch_all("SELECT user_id, name FROM users")
    
    return render_template('rooms.html', rooms=rooms_list, users=users_list, is_admin=is_admin)

@app.route('/api/rooms', methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required
def manage_rooms():
    user_id = session['user_id']
    is_admin = session.get('is_admin', False)
    
    if request.method == 'GET':
        if is_admin:
            rooms_list = fetch_all("""
                SELECT r.*, u.name as user_name 
                FROM rooms r 
                LEFT JOIN users u ON r.user_id = u.user_id
            """)
        else:
            rooms_list = fetch_all("""
                SELECT r.*, u.name as user_name 
                FROM rooms r 
                LEFT JOIN users u ON r.user_id = u.user_id
                WHERE r.user_id = %s
            """, (user_id,))
        
        # Get users assigned to each room
        for room in rooms_list:
            assigned_users = fetch_all("""
                SELECT u.user_id, u.name 
                FROM users u 
                JOIN user_room_mapping m ON u.user_id = m.user_id
                WHERE m.room_id = %s
            """, (room['room_id'],))
            room['assigned_users'] = assigned_users
        
        return jsonify(rooms_list)
    
    elif request.method == 'POST':
        data = request.json
        name = data.get('name')
        owner_id = data.get('user_id') if is_admin else user_id
        assigned_users = data.get('assigned_users', [])
        
        # Insert new room
        room_id = insert_data(
            "INSERT INTO rooms (name, user_id) VALUES (%s, %s)",
            (name, owner_id)
        )
        
        if room_id:
            # Add user-room mappings
            for assigned_user_id in assigned_users:
                insert_data(
                    "INSERT INTO user_room_mapping (user_id, room_id) VALUES (%s, %s)",
                    (assigned_user_id, room_id)
                )
            
            return jsonify({'success': True, 'room_id': room_id})
        else:
            return jsonify({'success': False, 'message': 'Failed to create room'})
    
    elif request.method == 'PUT':
        data = request.json
        room_id = data.get('room_id')
        name = data.get('name')
        owner_id = data.get('user_id') if is_admin else user_id
        assigned_users = data.get('assigned_users', [])
        
        # Verify access
        if not is_admin:
            room = fetch_one("SELECT * FROM rooms WHERE room_id = %s AND user_id = %s", (room_id, user_id))
            if not room:
                return jsonify({'success': False, 'message': 'Access denied'})
        
        # Update room
        success = update_data(
            "UPDATE rooms SET name = %s, user_id = %s WHERE room_id = %s",
            (name, owner_id, room_id)
        )
        
        if success:
            # Update user-room mappings
            delete_data("DELETE FROM user_room_mapping WHERE room_id = %s", (room_id,))
            
            for assigned_user_id in assigned_users:
                insert_data(
                    "INSERT INTO user_room_mapping (user_id, room_id) VALUES (%s, %s)",
                    (assigned_user_id, room_id)
                )
            
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Failed to update room'})
    
    elif request.method == 'DELETE':
        room_id = request.json.get('room_id')
        
        # Verify access
        if not is_admin:
            room = fetch_one("SELECT * FROM rooms WHERE room_id = %s AND user_id = %s", (room_id, user_id))
            if not room:
                return jsonify({'success': False, 'message': 'Access denied'})
        
        # Delete room
        success = delete_data("DELETE FROM rooms WHERE room_id = %s", (room_id,))
        
        if success:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Failed to delete room'})

# Device management routes
@app.route('/devices')
@login_required
def devices():
    user_id = session['user_id']
    is_admin = session.get('is_admin', False)
    
    if is_admin:
        devices_list = fetch_all("""
            SELECT d.*, r.name as room_name 
            FROM devices d 
            LEFT JOIN rooms r ON d.room_id = r.room_id
        """)
    else:
        devices_list = fetch_all("""
            SELECT d.*, r.name as room_name 
            FROM devices d 
            LEFT JOIN rooms r ON d.room_id = r.room_id
            WHERE d.user_id = %s
        """, (user_id,))
    
    rooms_list = fetch_all("SELECT room_id, name FROM rooms")
    
    return render_template('devices.html', devices=devices_list, rooms=rooms_list, is_admin=is_admin)

@app.route('/api/devices', methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required
def manage_devices():
    user_id = session['user_id']
    is_admin = session.get('is_admin', False)
    
    if request.method == 'GET':
        if is_admin:
            devices_list = fetch_all("""
                SELECT d.*, r.name as room_name, u.name as user_name
                FROM devices d 
                LEFT JOIN rooms r ON d.room_id = r.room_id
                LEFT JOIN users u ON d.user_id = u.user_id
            """)
        else:
            devices_list = fetch_all("""
                SELECT d.*, r.name as room_name, u.name as user_name
                FROM devices d 
                LEFT JOIN rooms r ON d.room_id = r.room_id
                LEFT JOIN users u ON d.user_id = u.user_id
                WHERE d.user_id = %s
            """, (user_id,))
        
        return jsonify(devices_list)
    
    elif request.method == 'POST':
        data = request.json
        name = data.get('name')
        device_type = data.get('type')
        status = data.get('status', False)
        power_consumption = data.get('power_consumption', 0)
        room_id = data.get('room_id')
        owner_id = data.get('user_id') if is_admin else user_id
        
        # Verify room access
        if not is_admin:
            room_access = fetch_one("""
                SELECT * FROM user_room_mapping 
                WHERE user_id = %s AND room_id = %s
            """, (user_id, room_id))
            
            if not room_access:
                return jsonify({'success': False, 'message': 'Access denied to this room'})
        
        # Insert new device
        device_id = insert_data(
            """INSERT INTO devices (name, type, status, power_consumption, user_id, room_id) 
               VALUES (%s, %s, %s, %s, %s, %s)""",
            (name, device_type, status, power_consumption, owner_id, room_id)
        )
        
        if device_id:
            return jsonify({'success': True, 'device_id': device_id})
        else:
            return jsonify({'success': False, 'message': 'Failed to create device'})
    
    elif request.method == 'PUT':
        data = request.json
        device_id = data.get('device_id')
        name = data.get('name')
        device_type = data.get('type')
        status = data.get('status', False)
        power_consumption = data.get('power_consumption', 0)
        room_id = data.get('room_id')
        owner_id = data.get('user_id') if is_admin else user_id
        
        # Verify access
        if not is_admin:
            device = fetch_one("SELECT * FROM devices WHERE device_id = %s AND user_id = %s", (device_id, user_id))
            if not device:
                return jsonify({'success': False, 'message': 'Access denied'})
        
        # Update device
        success = update_data(
            """UPDATE devices 
               SET name = %s, type = %s, status = %s, power_consumption = %s, user_id = %s, room_id = %s 
               WHERE device_id = %s""",
            (name, device_type, status, power_consumption, owner_id, room_id, device_id)
        )
        
        if success:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Failed to update device'})
    
    elif request.method == 'DELETE':
        device_id = request.json.get('device_id')
        
        # Verify access
        if not is_admin:
            device = fetch_one("SELECT * FROM devices WHERE device_id = %s AND user_id = %s", (device_id, user_id))
            if not device:
                return jsonify({'success': False, 'message': 'Access denied'})
        
        # Delete device
        success = delete_data("DELETE FROM devices WHERE device_id = %s", (device_id,))
        
        if success:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Failed to delete device'})

# Toggle device status
@app.route('/api/devices/toggle', methods=['POST'])
@login_required
def toggle_device():
    user_id = session['user_id']
    is_admin = session.get('is_admin', False)
    
    device_id = request.json.get('device_id')
    new_status = request.json.get('status')
    
    # Verify access
    if not is_admin:
        device = fetch_one("SELECT * FROM devices WHERE device_id = %s AND user_id = %s", (device_id, user_id))
        if not device:
            return jsonify({'success': False, 'message': 'Access denied'})
    
    # Update device status
    success = update_data(
        "UPDATE devices SET status = %s WHERE device_id = %s",
        (new_status, device_id)
    )
    
    if success:
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'message': 'Failed to update device status'})

# Sensor management routes
@app.route('/sensors')
@login_required
def sensors():
    user_id = session['user_id']
    is_admin = session.get('is_admin', False)
    
    if is_admin:
        sensors_list = fetch_all("""
            SELECT s.*, r.name as room_name 
            FROM sensors s 
            LEFT JOIN rooms r ON s.room_id = r.room_id
        """)
    else:
        sensors_list = fetch_all("""
            SELECT s.*, r.name as room_name 
            FROM sensors s 
            LEFT JOIN rooms r ON s.room_id = r.room_id
            LEFT JOIN user_room_mapping m ON r.room_id = m.room_id
            WHERE m.user_id = %s
        """, (user_id,))
    
    # Get rooms available to this user
    if is_admin:
        rooms_list = fetch_all("SELECT room_id, name FROM rooms")
    else:
        rooms_list = fetch_all("""
            SELECT r.room_id, r.name 
            FROM rooms r 
            JOIN user_room_mapping m ON r.room_id = m.room_id
            WHERE m.user_id = %s
        """, (user_id,))
    
    return render_template('sensors.html', sensors=sensors_list, rooms=rooms_list, is_admin=is_admin)

@app.route('/api/sensors', methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required
def manage_sensors():
    user_id = session['user_id']
    is_admin = session.get('is_admin', False)
    
    if request.method == 'GET':
        if is_admin:
            sensors_list = fetch_all("""
                SELECT s.*, r.name as room_name 
                FROM sensors s 
                LEFT JOIN rooms r ON s.room_id = r.room_id
            """)
        else:
            sensors_list = fetch_all("""
                SELECT s.*, r.name as room_name 
                FROM sensors s 
                LEFT JOIN rooms r ON s.room_id = r.room_id
                LEFT JOIN user_room_mapping m ON r.room_id = m.room_id
                WHERE m.user_id = %s
            """, (user_id,))
        
        return jsonify(sensors_list)
    
    elif request.method == 'POST':
        data = request.json
        sensor_type = data.get('type')
        status = data.get('status', False)
        room_id = data.get('room_id')
        
        # Verify room access
        if not is_admin:
            room_access = fetch_one("""
                SELECT * FROM user_room_mapping 
                WHERE user_id = %s AND room_id = %s
            """, (user_id, room_id))
            
            if not room_access:
                return jsonify({'success': False, 'message': 'Access denied to this room'})
        
        # Insert new sensor
        sensor_id = insert_data(
            "INSERT INTO sensors (type, status, room_id) VALUES (%s, %s, %s)",
            (sensor_type, status, room_id)
        )
        
        if sensor_id:
            return jsonify({'success': True, 'sensor_id': sensor_id})
        else:
            return jsonify({'success': False, 'message': 'Failed to create sensor'})
    
    elif request.method == 'PUT':
        data = request.json
        sensor_id = data.get('sensor_id')
        sensor_type = data.get('type')
        status = data.get('status', False)
        room_id = data.get('room_id')
        
        # Verify access
        if not is_admin:
            sensor = fetch_one("""
                SELECT s.* FROM sensors s
                JOIN rooms r ON s.room_id = r.room_id
                JOIN user_room_mapping m ON r.room_id = m.room_id
                WHERE s.sensor_id = %s AND m.user_id = %s
            """, (sensor_id, user_id))
            
            if not sensor:
                return jsonify({'success': False, 'message': 'Access denied'})
        
        # Update sensor
        success = update_data(
            "UPDATE sensors SET type = %s, status = %s, room_id = %s WHERE sensor_id = %s",
            (sensor_type, status, room_id, sensor_id)
        )
        
        if success:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Failed to update sensor'})
    
    elif request.method == 'DELETE':
        sensor_id = request.json.get('sensor_id')
        
        # Verify access
        if not is_admin:
            sensor = fetch_one("""
                SELECT s.* FROM sensors s
                JOIN rooms r ON s.room_id = r.room_id
                JOIN user_room_mapping m ON r.room_id = m.room_id
                WHERE s.sensor_id = %s AND m.user_id = %s
            """, (sensor_id, user_id))
            
            if not sensor:
                return jsonify({'success': False, 'message': 'Access denied'})
        
        # Delete sensor
        success = delete_data("DELETE FROM sensors WHERE sensor_id = %s", (sensor_id,))
        
        if success:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Failed to delete sensor'})

# Toggle sensor status
@app.route('/api/sensors/toggle', methods=['POST'])
@login_required
def toggle_sensor():
    user_id = session['user_id']
    is_admin = session.get('is_admin', False)
    
    sensor_id = request.json.get('sensor_id')
    new_status = request.json.get('status')
    
    # Verify access
    if not is_admin:
        sensor = fetch_one("""
            SELECT s.* FROM sensors s
            JOIN rooms r ON s.room_id = r.room_id
            JOIN user_room_mapping m ON r.room_id = m.room_id
            WHERE s.sensor_id = %s AND m.user_id = %s
        """, (sensor_id, user_id))
        
        if not sensor:
            return jsonify({'success': False, 'message': 'Access denied'})
    
    # Update sensor status
    success = update_data(
        "UPDATE sensors SET status = %s WHERE sensor_id = %s",
        (new_status, sensor_id)
    )
    
    if success:
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'message': 'Failed to update sensor status'})
    

    # Automation Rules management routes
@app.route('/automation')
@login_required
def automation():
    user_id = session['user_id']
    is_admin = session.get('is_admin', False)
    
    if is_admin:
        rules_list = fetch_all("""
            SELECT r.*, d.name as device_name 
            FROM automation_rules r 
            LEFT JOIN devices d ON r.device_id = d.device_id
        """)
    else:
        rules_list = fetch_all("""
            SELECT r.*, d.name as device_name 
            FROM automation_rules r 
            LEFT JOIN devices d ON r.device_id = d.device_id
            WHERE d.user_id = %s
        """, (user_id,))
    
    # Get devices available to this user
    if is_admin:
        devices_list = fetch_all("SELECT device_id, name FROM devices")
    else:
        devices_list = fetch_all("SELECT device_id, name FROM devices WHERE user_id = %s", (user_id,))
    
    return render_template('automation.html', rules=rules_list, devices=devices_list, is_admin=is_admin)

@app.route('/api/automation', methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required
def manage_automation():
    user_id = session['user_id']
    is_admin = session.get('is_admin', False)
    
    if request.method == 'GET':
        if is_admin:
            rules_list = fetch_all("""
                SELECT r.*, d.name as device_name, d.type as device_type
                FROM automation_rules r 
                LEFT JOIN devices d ON r.device_id = d.device_id
            """)
        else:
            rules_list = fetch_all("""
                SELECT r.*, d.name as device_name, d.type as device_type
                FROM automation_rules r 
                LEFT JOIN devices d ON r.device_id = d.device_id
                WHERE d.user_id = %s
            """, (user_id,))
        
        return jsonify(rules_list)
    
    elif request.method == 'POST':
        data = request.json
        description = data.get('description')
        device_id = data.get('device_id')
        schedule_time = data.get('schedule_time')
        action = data.get('action')
        
        # Verify device access
        if not is_admin:
            device = fetch_one("SELECT * FROM devices WHERE device_id = %s AND user_id = %s", (device_id, user_id))
            if not device:
                return jsonify({'success': False, 'message': 'Access denied to this device'})
        
        # Insert new automation rule
        rule_id = insert_data(
            "INSERT INTO automation_rules (description, device_id, schedule_time, action) VALUES (%s, %s, %s, %s)",
            (description, device_id, schedule_time, action)
        )
        
        if rule_id:
            return jsonify({'success': True, 'rule_id': rule_id})
        else:
            return jsonify({'success': False, 'message': 'Failed to create automation rule'})
    
    elif request.method == 'PUT':
        data = request.json
        rule_id = data.get('rule_id')
        description = data.get('description')
        device_id = data.get('device_id')
        schedule_time = data.get('schedule_time')
        action = data.get('action')
        
        # Verify access
        if not is_admin:
            rule = fetch_one("""
                SELECT r.* FROM automation_rules r
                JOIN devices d ON r.device_id = d.device_id
                WHERE r.rule_id = %s AND d.user_id = %s
            """, (rule_id, user_id))
            
            if not rule:
                return jsonify({'success': False, 'message': 'Access denied'})
        
        # Update automation rule
        success = update_data(
            "UPDATE automation_rules SET description = %s, device_id = %s, schedule_time = %s, action = %s WHERE rule_id = %s",
            (description, device_id, schedule_time, action, rule_id)
        )
        
        if success:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Failed to update automation rule'})
    
    elif request.method == 'DELETE':
        rule_id = request.json.get('rule_id')
        
        # Verify access
        if not is_admin:
            rule = fetch_one("""
                SELECT r.* FROM automation_rules r
                JOIN devices d ON r.device_id = d.device_id
                WHERE r.rule_id = %s AND d.user_id = %s
            """, (rule_id, user_id))
            
            if not rule:
                return jsonify({'success': False, 'message': 'Access denied'})
        
        # Delete automation rule
        success = delete_data("DELETE FROM automation_rules WHERE rule_id = %s", (rule_id,))
        
        if success:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Failed to delete automation rule'})

# Main entry point
if __name__ == '__main__':
    app.run(debug=Config.DEBUG)