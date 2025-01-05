# extensions.py
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

# Initialize the extensions
db = SQLAlchemy()
migrate = Migrate()
