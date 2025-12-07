import os
from flask import Flask, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename
from forensic_engine import process_log_file

app = Flask(__name__)

# CONFIGURATION
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'log', 'txt', 'csv'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    """Checks if the file has a valid extension (security check)"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    """Renders the main upload page"""
    return render_template('dashboard.html', map_html=None, stats=None)

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handles the file upload and runs the forensic analysis"""
    if 'file' not in request.files:
        return redirect(request.url)
    
    file = request.files['file']
    
    if file.filename == '':
        return redirect(request.url)
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # --- THE FORENSIC ENGINE KICKS IN HERE ---
        print(f"Analyzing {filename}...")
        df, map_html, stats = process_log_file(filepath)
        
        # Send the results to the frontend
        return render_template('dashboard.html', map_html=map_html, stats=stats)
    
    return "Invalid file type. Please upload .log or .txt"

if __name__ == '__main__':
    app.run(debug=True, port=5000)
