-- Drop database if exists (for development purposes)
DROP DATABASE IF EXISTS smart_home_db;

-- Create database
CREATE DATABASE smart_home_db;
USE smart_home_db;

-- Create Users table
CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    contact_number VARCHAR(20),
    address TEXT,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create Rooms table
CREATE TABLE rooms (
    room_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    user_id INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Create user-room mapping (many-to-many relationship)
CREATE TABLE user_room_mapping (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    room_id INT,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (room_id) REFERENCES rooms(room_id) ON DELETE CASCADE,
    UNIQUE(user_id, room_id)
);

-- Create Devices table
CREATE TABLE devices (
    device_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    type VARCHAR(50) NOT NULL,
    status BOOLEAN DEFAULT FALSE,
    power_consumption FLOAT DEFAULT 0,
    user_id INT,
    room_id INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (room_id) REFERENCES rooms(room_id) ON DELETE CASCADE
);

-- Create Sensors table
CREATE TABLE sensors (
    sensor_id INT AUTO_INCREMENT PRIMARY KEY,
    type VARCHAR(50) NOT NULL,
    status BOOLEAN DEFAULT FALSE,
    room_id INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (room_id) REFERENCES rooms(room_id) ON DELETE CASCADE
);

-- Create Automation Rules table
CREATE TABLE automation_rules (
    rule_id INT AUTO_INCREMENT PRIMARY KEY,
    description TEXT NOT NULL,
    device_id INT,
    schedule_time TIME,
    action VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

-- Insert admin user
INSERT INTO users (name, email, password, is_admin) 
VALUES ('Admin', 'admin@smarthome.com', '$2b$12$LJ6v5cPJ7xS6SFZxJqFTVuZXpNQSuVmKg6w4NeEZ9o6CsJjnolRjW', TRUE);
-- Password is 'admin123' hashed with bcrypt