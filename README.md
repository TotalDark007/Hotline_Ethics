# Hotline_Ethics

A Flask-based ethics hotline reporting application.

## Running the App

### Option 1: Local Development
1. Install dependencies: `pip install -r requirements.txt`
2. Set up the database: `set FLASK_APP=app.py && flask db upgrade`
3. (Optional) Seed data: `python seed_data.py`
4. Run the app: `python app.py`
5. Open `http://localhost:5000`

### Option 2: Using Docker
1. Ensure Docker is installed.
2. Build and run with Docker Compose: `docker-compose up --build`
3. The app will be available at `http://localhost:5000`
4. Database and uploads are persisted in local `instance/` and `uploads/` folders.

### Option 3: Using Docker (Standalone)
1. Build the image: `docker build -t hotline-ethics .`
2. Run the container: `docker run -p 5000:5000 -v $(pwd)/instance:/app/instance -v $(pwd)/uploads:/app/uploads hotline-ethics`
3. Open `http://localhost:5000`" 
