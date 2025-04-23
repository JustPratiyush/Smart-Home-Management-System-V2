# Project Tree

smart_home_management_system/
├── app.py # Main Flask application
├── config.py # Configuration file
├── database/
│ ├── db_config.py # Database configuration
│ ├── models.py # Database models
│ └── schema.sql # SQL schema for initialization
├── static/
│ ├── css/
│ │ ├── main.css # Main stylesheet
│ │ ├── login.css # Login page styles
│ │ └── dashboard.css # Dashboard styles
│ ├── js/
│ │ ├── main.js # Main JavaScript
│ │ ├── users.js # Users page functionality
│ │ ├── rooms.js # Rooms page functionality
│ │ ├── devices.js # Devices page functionality
│ │ ├── sensors.js # Sensors page functionality
│ │ └── automation.js # Automation rules functionality
│ └── images/
│ └── icons/ # UI icons
└── templates/
├── base.html # Base template
├── login.html # Login page
├── register.html # Registration page
├── dashboard.html # Main dashboard
├── users.html # Users management
├── rooms.html # Rooms management
├── devices.html # Devices management
├── sensors.html # Sensors management
└── automation.html # Automation rules management
