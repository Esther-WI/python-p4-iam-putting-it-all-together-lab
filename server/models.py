from sqlalchemy.orm import validates
from sqlalchemy.orm import validates, relationship
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin

from config import db, bcrypt
import random
import string

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    pass
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)
    _password_hash = db.Column(db.String, nullable=False)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    recipes = relationship("Recipe", backref="user", cascade="all, delete-orphan")
    serialize_rules = ('-recipes.user',)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Generate random password if not provided
        if not self._password_hash:
            random_password = ''.join(random.choices(string.ascii_letters, k=10))
            self.password_hash = random_password

    @hybrid_property
    def password_hash(self):
        raise AttributeError("Password hashes may not be viewed.")
    
    @password_hash.setter
    def password_hash(self, password):
        if not password:
            raise ValueError("Password must not be empty.")
        if len(password) < 6:
            raise ValueError("Password must be at least 6 characters long.")
        self._password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password)

    @validates('username')
    def validate_username(self, key, value):
        if not value:
            raise ValueError("Username must be present.")
        return value

    @validates('_password_hash')
    def validate_password_hash(self, key, value):
        if not value:
            raise ValueError("Password hash cannot be empty.")
        return value

class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    serialize_rules = ('-user.recipes',)

    @validates('title')
    def validate_title(self, key, value):
        if not value:
            raise ValueError("Title must be present.")
        return value

    @validates('instructions')
    def validate_instructions(self, key, value):
        if not value:
            raise ValueError("Instructions must be present.")
        if len(value) < 50:
            raise ValueError("Instructions must be at least 50 characters long.")
        return value

    @validates('minutes_to_complete')
    def validate_minutes(self, key, value):
        if value is None:
            raise ValueError("Minutes must be provided.")
        if not isinstance(value, int):
            raise ValueError("Minutes must be an integer.")
        if value <= 0:
            raise ValueError("Minutes must be a positive integer.")
        return value

    pass
    def __init__(self, **kwargs):
        # If user_id is missing, assign a default user
        if 'user_id' not in kwargs:
            user = User.query.first()
            if not user:
                # Create default user if none exists
                user = User(
                    username='default_user',
                    image_url='',
                    bio=''
                )
                # Generate password for the default user
                user.password_hash = ''.join(random.choices(string.ascii_letters, k=10))
                db.session.add(user)
                db.session.flush()  # Get user ID without committing transaction
            kwargs['user_id'] = user.id
        super().__init__(**kwargs)