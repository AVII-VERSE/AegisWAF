from flask import Flask
from src.aegis_waf.routes.main import main_bp
from src.aegis_waf.routes.api import api_bp
from src.aegis_waf.database import init_db

app = Flask(__name__)

# Initialize SQLite database schema and seed telemetry data if empty
init_db()

# Register Blueprints
app.register_blueprint(main_bp)
app.register_blueprint(api_bp)

if __name__ == '__main__':
    print("[INFO] AegisWAF Security Command Center active at http://127.0.0.1:5000")
    app.run(debug=False, host='127.0.0.1', port=5000)
