import unittest
import json
from app import app, db, User, Book # Import necessary models and app object

class AppTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['WTF_CSRF_ENABLED'] = False # Disable CSRF for tests if it's ever added
        app.config['LOGIN_DISABLED'] = False # Ensure login is not disabled for tests needing it
        
        self.app_context = app.app_context()
        self.app_context.push()
        db.create_all()
        self.client = app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    # --- Helper Methods ---
    def _signup_user(self, username, email, password):
        return self.client.post('/signup', json={
            'username': username,
            'email': email,
            'password': password
        })

    def _login_user(self, email, password):
        return self.client.post('/login', json={
            'email': email,
            'password': password
        })

    def _create_book_as_admin_and_login_user(self):
        # Create and login admin
        self._signup_user('adminuser', 'admin@example.com', 'adminpass') # First user becomes admin
        self._login_user('admin@example.com', 'adminpass')

        # Create a book (simplified, not using /admin/upload_book endpoint directly for this unit test)
        book = Book(title="Test Book for Annotations", author="Test Author", filename="test_book.pdf", user_id=1) # user_id 1 is admin
        db.session.add(book)
        db.session.commit()
        
        # Log out admin, sign up and log in a regular user
        self.client.post('/logout') # Logout admin
        self._signup_user('testuser', 'test@example.com', 'password123')
        login_resp = self._login_user('test@example.com', 'password123')
        return book.id, json.loads(login_resp.data)


    # --- Authentication Tests ---
    def test_signup_first_user_is_admin(self):
        response = self._signup_user('firstadmin', 'first@example.com', 'adminpass')
        self.assertEqual(response.status_code, 201)
        data = json.loads(response.data)
        self.assertIn('First user registered as admin', data['message'])
        
        user = User.query.filter_by(email='first@example.com').first()
        self.assertIsNotNone(user)
        self.assertTrue(user.is_admin)

    def test_signup_success_non_admin(self):
        # First user (admin)
        self._signup_user('adminuser', 'admin@example.com', 'adminpass') 
        # Second user (non-admin)
        response = self._signup_user('testuser', 'test@example.com', 'password123')
        self.assertEqual(response.status_code, 201)
        data = json.loads(response.data)
        self.assertEqual(data['message'], 'User created successfully')
        
        user = User.query.filter_by(email='test@example.com').first()
        self.assertIsNotNone(user)
        self.assertFalse(user.is_admin)

    def test_signup_duplicate_email(self):
        self._signup_user('testuser1', 'test@example.com', 'password123')
        response = self._signup_user('testuser2', 'test@example.com', 'password456')
        self.assertEqual(response.status_code, 409)
        data = json.loads(response.data)
        self.assertEqual(data['message'], 'Username or email already exists')

    def test_login_success(self):
        self._signup_user('testuser', 'test@example.com', 'password123')
        response = self._login_user('test@example.com', 'password123')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['message'], 'Logged in successfully')
        self.assertEqual(data['user']['email'], 'test@example.com')

    def test_login_failure_wrong_password(self):
        self._signup_user('testuser', 'test@example.com', 'password123')
        response = self._login_user('test@example.com', 'wrongpassword')
        self.assertEqual(response.status_code, 401)
        data = json.loads(response.data)
        self.assertEqual(data['message'], 'Invalid email or password')

    def test_login_failure_user_not_exist(self):
        response = self._login_user('nonexistent@example.com', 'password123')
        self.assertEqual(response.status_code, 401) # Or based on how your app handles it

    def test_logout(self):
        self._signup_user('testuser', 'test@example.com', 'password123')
        self._login_user('test@example.com', 'password123')
        
        logout_response = self.client.post('/logout')
        self.assertEqual(logout_response.status_code, 200)
        data = json.loads(logout_response.data)
        self.assertEqual(data['message'], 'Logged out successfully')

        # Verify session is cleared
        session_response = self.client.get('/check_session')
        self.assertEqual(session_response.status_code, 401) # @login_required redirects/401s

    # --- Book & Annotation Access Tests ---
    def test_get_books_empty_for_logged_in_user(self):
        self._signup_user('testuser', 'test@example.com', 'password123')
        self._login_user('test@example.com', 'password123')
        
        response = self.client.get('/books')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(len(data), 0) # Expecting an empty list

    def test_create_and_get_annotation(self):
        book_id, _ = self._create_book_as_admin_and_login_user()

        # Create annotation
        annotation_data = {
            'type': 'note',
            'page_number': 5,
            'text_content': 'This is a test note.',
            'color': 'blue' 
        }
        create_response = self.client.post(f'/book/{book_id}/annotations', json=annotation_data)
        self.assertEqual(create_response.status_code, 201)
        created_data = json.loads(create_response.data)
        self.assertEqual(created_data['text_content'], 'This is a test note.')

        # Get annotations for the book
        get_response = self.client.get(f'/book/{book_id}/annotations')
        self.assertEqual(get_response.status_code, 200)
        annotations_data = json.loads(get_response.data)
        self.assertEqual(len(annotations_data), 1)
        self.assertEqual(annotations_data[0]['text_content'], 'This is a test note.')
        self.assertEqual(annotations_data[0]['id'], created_data['id'])

    # --- Admin Access Tests ---
    def test_admin_upload_page_access_denied_for_non_admin(self):
        # First user (admin)
        self._signup_user('adminuser', 'admin@example.com', 'adminpass')
        # Second user (non-admin)
        self._signup_user('nonadmin', 'nonadmin@example.com', 'userpass')
        self._login_user('nonadmin@example.com', 'userpass')
        
        response = self.client.get('/admin/upload-page')
        self.assertEqual(response.status_code, 302) # Expecting redirect to index
        self.assertTrue('/' in response.location) # Check redirect location

    def test_admin_upload_page_access_granted_for_admin(self):
        self._signup_user('adminuser', 'admin@example.com', 'adminpass') # First user becomes admin
        self._login_user('admin@example.com', 'adminpass')
        
        response = self.client.get('/admin/upload-page')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Upload New Book', response.data) # Check for unique content from admin_upload.html

if __name__ == '__main__':
    unittest.main()
