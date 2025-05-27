from flask import Flask, render_template, send_from_directory, request, jsonify, redirect, url_for
import os
import uuid # For unique filenames
import json # For handling JSON data for coordinates
import fitz # PyMuPDF
from werkzeug.utils import secure_filename
from datetime import datetime # For uploaded_at timestamp
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24) # For session management
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['COVERS_FOLDER'] = os.path.join('uploads', 'covers') # Subdirectory for covers
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///../instance/database.sqlite3' # Path to the SQLite DB
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Ensure instance folder exists
try:
    os.makedirs(app.instance_path)
except OSError:
    pass # Already exists

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login_page' # Route that serves the login HTML

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256)) # Increased length for robust hashes
    is_admin = db.Column(db.Boolean, nullable=False, default=False) # New field
    books_uploaded = db.relationship('Book', backref='uploader', lazy='dynamic')
    annotations = db.relationship('Annotation', backref='annotator', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(200))
    filename = db.Column(db.String(256), nullable=False, unique=True) # Store unique filename
    cover_image_filename = db.Column(db.String(256), nullable=True, unique=True) # Store unique cover filename
    uploaded_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # Link to uploader
    annotations = db.relationship('Annotation', backref='annotated_book', lazy='dynamic')

class Annotation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # 'note', 'highlight'
    page_number = db.Column(db.Integer)
    coordinates = db.Column(db.Text) # Store as JSON string
    text_content = db.Column(db.Text)
    color = db.Column(db.String(20)) # e.g., 'yellow', '#FFD700'
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

# --- API Endpoints ---
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({'message': 'Missing username, email, or password'}), 400

    if User.query.filter_by(username=username).first() or \
       User.query.filter_by(email=email).first():
        return jsonify({'message': 'Username or email already exists'}), 409

    new_user = User(username=username, email=email)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    # Make the first user an admin
    if User.query.count() == 1:
        new_user.is_admin = True
        db.session.commit()
        return jsonify({'message': 'User created successfully. First user registered as admin.'}), 201
    
    return jsonify({'message': 'User created successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Missing email or password'}), 400

    user = User.query.filter_by(email=email).first()

    if user and user.check_password(password):
        login_user(user)
        return jsonify({'message': 'Logged in successfully', 'user': {'username': user.username, 'email': user.email}}), 200
    
    return jsonify({'message': 'Invalid email or password'}), 401

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/check_session', methods=['GET'])
@login_required # Or remove if you want to allow unauth access to see they are not logged in
def check_session():
    if current_user.is_authenticated:
        return jsonify({
            'logged_in': True, 
            'user': {
                'username': current_user.username, 
                'email': current_user.email,
                'id': current_user.id,
                'is_admin': current_user.is_admin # Added is_admin status
            }
        }), 200
    else:
        # This case might not be hit if @login_required redirects unauth users.
        # If login_required is removed, this part becomes relevant.
        return jsonify({'logged_in': False}), 200

@app.route('/login-page')
def login_page():
    return render_template('login.html')

@app.route('/signup-page')
def signup_page():
    return render_template('signup.html')

@app.route('/')
def index():
    return render_template('index.html')

# Route to serve uploaded files (e.g., PDFs) - will be used later
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    # Construct the absolute path to the UPLOAD_FOLDER
    # app.root_path is the path to the directory where the application file (app.py) is.
    directory = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'])
    return send_from_directory(directory, filename)

@app.route('/uploads/covers/<filename>')
def uploaded_cover_file(filename):
    # Construct the absolute path to the COVERS_FOLDER
    # app.config['COVERS_FOLDER'] should be 'uploads/covers'
    directory = os.path.join(app.root_path, app.config['COVERS_FOLDER'])
    return send_from_directory(directory, filename)

@app.route('/admin/upload_book', methods=['POST'])
@login_required
def upload_book():
    if not current_user.is_admin: # Changed to use is_admin
        return jsonify({'message': 'Admin access required'}), 403

    if 'book_file' not in request.files:
        return jsonify({'message': 'No book file part'}), 400

    file = request.files['book_file']
    title = request.form.get('title')
    author = request.form.get('author')

    if not title:
        return jsonify({'message': 'Title is required'}), 400
    
    if file.filename == '':
        return jsonify({'message': 'No selected file'}), 400

    if file: # Add check for allowed extensions if necessary
        original_filename = secure_filename(file.filename)
        # Create a unique filename to prevent overwrites and ensure security
        unique_filename = str(uuid.uuid4()) + "_" + original_filename
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)

        # Handle cover image: user-provided or generated
        cover_filename_to_save = None 

        covers_abs_path = os.path.join(app.root_path, app.config['COVERS_FOLDER'])
        if not os.path.exists(covers_abs_path):
            os.makedirs(covers_abs_path) # Ensure COVERS_FOLDER exists

        if 'cover_image_file' in request.files and request.files['cover_image_file'].filename != '':
            cover_file = request.files['cover_image_file']
            # User provided a cover image
            original_cover_filename = secure_filename(cover_file.filename)
            # Prefix to distinguish user-uploaded from generated, and add UUID
            unique_cover_filename = "user_" + str(uuid.uuid4()) + "_" + original_cover_filename
            
            cover_path = os.path.join(covers_abs_path, unique_cover_filename)
            cover_file.save(cover_path)
            cover_filename_to_save = unique_cover_filename
        else:
            # No cover image provided by user, try to generate from PDF's first page
            if file and file_path: # Ensure PDF was uploaded and its path is known
                try:
                    pdf_document = fitz.open(file_path) # file_path is absolute path to the saved PDF
                    if pdf_document.page_count > 0:
                        first_page = pdf_document.load_page(0) 
                        pix = first_page.get_pixmap(dpi=150) 
                        
                        generated_cover_filename = "generated_" + str(uuid.uuid4()) + ".png"
                        generated_cover_path = os.path.join(covers_abs_path, generated_cover_filename)
                        
                        pix.save(generated_cover_path) 
                        cover_filename_to_save = generated_cover_filename
                    pdf_document.close()
                except Exception as e:
                    print(f"Error generating cover from PDF: {e}")
                    # cover_filename_to_save remains None, or you could set a default placeholder filename

        new_book = Book(
            title=title,
            author=author, 
            filename=unique_filename, 
            cover_image_filename=cover_filename_to_save,
            user_id=current_user.id
        )
        db.session.add(new_book)
        db.session.commit()
        return jsonify({'message': 'Book uploaded successfully', 'book_id': new_book.id}), 201

    return jsonify({'message': 'File upload failed'}), 500

from sqlalchemy import or_

@app.route('/books', methods=['GET'])
@login_required
def get_books():
    search_term = request.args.get('q', None)
    
    if search_term:
        query_term = f"%{search_term}%"
        books_query = Book.query.filter(or_(Book.title.ilike(query_term), Book.author.ilike(query_term))).all()
    else:
        books_query = Book.query.all()
        
    books_list = []
    for book in books_query:
        cover_image_url = None
        if book.cover_image_filename:
            # Correctly construct the URL for cover images
            cover_image_url = url_for('uploaded_cover_file', filename=book.cover_image_filename, _external=False)
        
        book_file_url = url_for('uploaded_file', filename=book.filename, _external=False)

        books_list.append({
            'id': book.id,
            'title': book.title,
            'author': book.author,
            'filename': book.filename, # Keeping for potential direct use, though URL is primary
            'cover_image_url': cover_image_url,
            'book_file_url': book_file_url
        })
    return jsonify(books_list), 200

@app.route('/read')
@login_required
def read_book_page_route():
    # The book_id will be extracted from query parameters by JavaScript in read_book_page.html
    return render_template('read_book_page.html')

@app.route('/book_details/<int:book_id>', methods=['GET'])
@login_required
def get_book_details(book_id):
    book = Book.query.get(book_id)
    if not book:
        return jsonify({'message': 'Book not found'}), 404

    book_file_url = url_for('uploaded_file', filename=book.filename, _external=False)
    
    return jsonify({
        'id': book.id,
        'title': book.title,
        'author': book.author,
        'book_file_url': book_file_url
    }), 200

# --- Annotation Endpoints ---
@app.route('/book/<int:book_id>/annotations', methods=['POST'])
@login_required
def create_annotation(book_id):
    book = Book.query.get_or_404(book_id) # Ensure book exists
    data = request.get_json()

    if not data:
        return jsonify({'message': 'No input data provided'}), 400

    required_fields = ['type']
    if not all(field in data for field in required_fields):
        return jsonify({'message': 'Missing required fields (type)'}), 400
    
    if data['type'] not in ['note', 'highlight']:
        return jsonify({'message': 'Invalid annotation type'}), 400
    
    # Validate text_content for notes
    if data['type'] == 'note' and not data.get('text_content'):
        return jsonify({'message': 'text_content is required for notes'}), 400
        
    # Validate coordinates for highlights
    if data['type'] == 'highlight' and not data.get('coordinates'):
        return jsonify({'message': 'coordinates are required for highlights'}), 400


    new_annotation = Annotation(
        book_id=book_id,
        user_id=current_user.id,
        type=data['type'],
        page_number=data.get('page_number'),
        coordinates=json.dumps(data.get('coordinates')) if data.get('coordinates') else None,
        text_content=data.get('text_content'),
        color=data.get('color')
    )
    db.session.add(new_annotation)
    db.session.commit()
    
    return jsonify({
        'id': new_annotation.id,
        'book_id': new_annotation.book_id,
        'user_id': new_annotation.user_id,
        'type': new_annotation.type,
        'page_number': new_annotation.page_number,
        'coordinates': data.get('coordinates'), # Return as object, not JSON string
        'text_content': new_annotation.text_content,
        'color': new_annotation.color,
        'created_at': new_annotation.created_at.isoformat(),
        'updated_at': new_annotation.updated_at.isoformat()
    }), 201

@app.route('/book/<int:book_id>/annotations', methods=['GET'])
@login_required
def get_annotations(book_id):
    # Optionally, check if book exists, though annotations are user-specific for a book
    # Book.query.get_or_404(book_id) 
    
    annotations_query = Annotation.query.filter_by(book_id=book_id, user_id=current_user.id).all()
    annotations_list = []
    for ann in annotations_query:
        annotations_list.append({
            'id': ann.id,
            'book_id': ann.book_id,
            'user_id': ann.user_id,
            'type': ann.type,
            'page_number': ann.page_number,
            'coordinates': json.loads(ann.coordinates) if ann.coordinates else None,
            'text_content': ann.text_content,
            'color': ann.color,
            'created_at': ann.created_at.isoformat(),
            'updated_at': ann.updated_at.isoformat()
        })
    return jsonify(annotations_list), 200

@app.route('/annotations/<int:annotation_id>', methods=['PUT'])
@login_required
def update_annotation(annotation_id):
    annotation = Annotation.query.get_or_404(annotation_id)
    if annotation.user_id != current_user.id:
        return jsonify({'message': 'Unauthorized'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'message': 'No input data provided'}), 400

    # Update fields if provided
    if 'page_number' in data:
        annotation.page_number = data['page_number']
    if 'coordinates' in data: # Assuming coordinates can be updated
        annotation.coordinates = json.dumps(data.get('coordinates')) if data.get('coordinates') else None
    if 'text_content' in data:
        annotation.text_content = data['text_content']
    if 'color' in data:
        annotation.color = data['color']
    
    annotation.updated_at = datetime.utcnow() # Explicitly set, though onupdate should also work

    db.session.commit()
    
    return jsonify({
        'id': annotation.id,
        'book_id': annotation.book_id,
        'user_id': annotation.user_id,
        'type': annotation.type,
        'page_number': annotation.page_number,
        'coordinates': json.loads(annotation.coordinates) if annotation.coordinates else None,
        'text_content': annotation.text_content,
        'color': annotation.color,
        'created_at': annotation.created_at.isoformat(),
        'updated_at': annotation.updated_at.isoformat()
    }), 200

@app.route('/annotations/<int:annotation_id>', methods=['DELETE'])
@login_required
def delete_annotation(annotation_id):
    annotation = Annotation.query.get_or_404(annotation_id)
    if annotation.user_id != current_user.id:
        return jsonify({'message': 'Unauthorized'}), 403

    db.session.delete(annotation)
    db.session.commit()
    return jsonify({'message': 'Annotation deleted successfully'}), 200


@app.route('/admin/upload-page')
@login_required
def admin_upload_page():
    if not current_user.is_admin: # Changed to use is_admin
        return render_template('admin_upload.html') # Should be an error or redirect
    # Corrected: render admin_upload.html only if admin, else redirect.
    # The original logic was inverted.
    if current_user.is_admin:
        return render_template('admin_upload.html')
    else:
        return redirect(url_for('index'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Create tables
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    if not os.path.exists(app.config['COVERS_FOLDER']): # Ensure covers subfolder is created
        os.makedirs(app.config['COVERS_FOLDER'])
    app.run(debug=True)
