from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from flask_socketio import SocketIO, emit
from flask_migrate import Migrate
from datetime import datetime, timedelta  
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///neighborhood.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

socketio = SocketIO(app)


db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    neighborhood_id = db.Column(db.Integer, db.ForeignKey('neighborhood.id'), nullable=False)
    profile_pic = db.Column(db.String(200), default='default.jpg')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    
    posts = db.relationship('Post', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)
    incidents = db.relationship('Incident', backref='reporter', lazy=True)
    group_memberships = db.relationship('GroupMember', backref='user', lazy=True)

class Neighborhood(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(100), nullable=False)
    zip_code = db.Column(db.String(20), nullable=False)
    
    users = db.relationship('User', backref='neighborhood', lazy=True)
    posts = db.relationship('Post', backref='neighborhood', lazy=True)
    incidents = db.relationship('Incident', backref='neighborhood', lazy=True)
    groups = db.relationship('Group', backref='neighborhood', lazy=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    neighborhood_id = db.Column(db.Integer, db.ForeignKey('neighborhood.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)
    
    comments = db.relationship('Comment', backref='post', lazy=True, cascade="all, delete-orphan")

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    incident_type = db.Column(db.String(50), nullable=False)  # e.g., "suspicious activity", "crime", "safety"
    location = db.Column(db.String(200), nullable=False)
    image = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    neighborhood_id = db.Column(db.Integer, db.ForeignKey('neighborhood.id'), nullable=False)
    
    comments = db.relationship('IncidentComment', backref='incident', lazy=True, cascade="all, delete-orphan")

class IncidentComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    incident_id = db.Column(db.Integer, db.ForeignKey('incident.id'), nullable=False)
    
    author = db.relationship('User', backref='incident_comments', lazy=True)

class MarketItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(200))
    category = db.Column(db.String(50), nullable=False)  # e.g., "furniture", "electronics", "clothing"
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    neighborhood_id = db.Column(db.Integer, db.ForeignKey('neighborhood.id'), nullable=False)
    is_sold = db.Column(db.Boolean, default=False)
    
    user = db.relationship('User', backref='market_items')

# Add these new models
class GroupIncident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    incident_type = db.Column(db.String(50), nullable=False)
    location = db.Column(db.String(200), nullable=False)
    image = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    
    user = db.relationship('User', backref='group_incidents')
    group = db.relationship('Group', backref='group_incidents')  # This was missing
    
    comments = db.relationship('GroupIncidentComment', backref='incident', cascade="all, delete-orphan")

class GroupIncidentComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    incident_id = db.Column(db.Integer, db.ForeignKey('group_incident.id'), nullable=False)
    
    user = db.relationship('User', backref='group_incident_comments')

class Poll(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    
    options = db.relationship('PollOption', backref='poll', lazy=True, cascade="all, delete-orphan")
    user = db.relationship('User', backref='polls')

class PollOption(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(200), nullable=False)
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)
    
    votes = db.relationship('PollVote', backref='option', lazy=True, cascade="all, delete-orphan")

class PollVote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    option_id = db.Column(db.Integer, db.ForeignKey('poll_option.id'), nullable=False)
    voted_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('user_id', 'option_id', name='_user_option_uc'),)
    user = db.relationship('User', backref='poll_votes')

def redirect_back(default='dashboard', **kwargs):
    """Redirect back to previous page or default if no referrer"""
    for target in request.args.get('next'), request.referrer:
        if target:
            return redirect(target)
    return redirect(url_for(default, **kwargs))

# New Market Item
@app.route('/market/new', methods=['GET', 'POST'])
@login_required
def new_market_item():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        price = float(request.form.get('price'))
        category = request.form.get('category')
        
        image_filename = None
        if 'image' in request.files:
            file = request.files['image']
            if file.filename != '':
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                image_filename = filename
        
        new_item = MarketItem(
            title=title,
            description=description,
            price=price,
            image=image_filename,
            category=category,
            user_id=current_user.id,
            neighborhood_id=current_user.neighborhood_id
        )
        
        db.session.add(new_item)
        db.session.commit()
        flash('Item listed successfully!')
        return redirect(url_for('market'))
    
    return render_template('new_market_item.html')

# View Market Item
@app.route('/market/item/<int:item_id>')
@login_required
def view_market_item(item_id):
    item = MarketItem.query.get_or_404(item_id)
    
    # Ensure item is in user's neighborhood
    if item.neighborhood_id != current_user.neighborhood_id:
        abort(403)
    
    return render_template('view_market_item.html', item=item)

# Mark Item as Sold
@app.route('/market/item/<int:item_id>/sold', methods=['POST'])
@login_required
def mark_item_sold(item_id):
    item = MarketItem.query.get_or_404(item_id)
    
    # Only item owner can mark as sold
    if item.user_id != current_user.id:
        abort(403)
    
    item.is_sold = True
    db.session.commit()
    flash('Item marked as sold!')
    return redirect(url_for('view_market_item', item_id=item.id))

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)  # This is the critical column
    is_read = db.Column(db.Boolean, default=False)
    item_id = db.Column(db.Integer, db.ForeignKey('market_item.id'), nullable=True)

    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')
    item = db.relationship('MarketItem', backref='messages')

# Add this to your models section in app.py
class MarketRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    request_type = db.Column(db.String(20), nullable=False)  # 'buy' or 'rent'
    category = db.Column(db.String(50), nullable=False)
    max_price = db.Column(db.Float, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    neighborhood_id = db.Column(db.Integer, db.ForeignKey('neighborhood.id'), nullable=False)
    is_fulfilled = db.Column(db.Boolean, default=False)
    
    user = db.relationship('User', backref='market_requests')

# New Group Models
class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(200), default='group_default.jpg')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    neighborhood_id = db.Column(db.Integer, db.ForeignKey('neighborhood.id'), nullable=False)
    is_private = db.Column(db.Boolean, default=False)
    
    creator = db.relationship('User', backref='created_groups')
    members = db.relationship('GroupMember', backref='group', lazy=True, cascade="all, delete-orphan")
    posts = db.relationship('Post', backref='group', lazy=True)

class GroupJoinRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    requested_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'approved', 'rejected'
    
    user = db.relationship('User', backref='group_join_requests')
    group = db.relationship('Group', backref='join_requests')
    
    __table_args__ = (db.UniqueConstraint('user_id', 'group_id', name='_user_group_request_uc'),)

class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('user_id', 'group_id', name='_user_group_uc'),)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    neighborhoods = Neighborhood.query.all()
    
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        password = request.form.get('password')
        address = request.form.get('address')
        neighborhood_id = request.form.get('neighborhood_id')
        
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.')
            return redirect(url_for('register'))
        
        # Explicitly use scrypt for hashing
        hashed_password = generate_password_hash(
            password,
            method='scrypt',
            salt_length=16
        )
        new_user = User(
            email=email,
            name=name,
            password=hashed_password,
            address=address,
            neighborhood_id=neighborhood_id
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    
    return render_template('register.html', neighborhoods=neighborhoods)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        
        user = User.query.filter_by(email=email).first()
        
        if not user:
            flash('Email not found. Please check your email or register.')
            return redirect(url_for('login'))
        
        # Verify password with scrypt
        try:
            if check_password_hash(user.password, password):
                login_user(user, remember=remember)
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('dashboard'))
            else:
                flash('Incorrect password. Please try again.')
                return redirect(url_for('login'))
        except ValueError as e:
            print(f"Password check error: {e}")
            flash('Login error. Please try again.')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    posts = Post.query.filter_by(neighborhood_id=current_user.neighborhood_id, group_id=None).order_by(Post.created_at.desc()).all()
    incidents = Incident.query.filter_by(neighborhood_id=current_user.neighborhood_id).order_by(Incident.created_at.desc()).all()
    user_groups = [membership.group for membership in current_user.group_memberships]
    return render_template('dashboard.html', posts=posts, incidents=incidents, user_groups=user_groups)

@app.route('/profile')
@login_required
def profile():
    # Get user-specific data
    user_posts = Post.query.filter_by(user_id=current_user.id).order_by(Post.created_at.desc()).limit(5).all()
    user_groups = current_user.group_memberships
    market_items = MarketItem.query.filter_by(user_id=current_user.id).order_by(MarketItem.created_at.desc()).all()
    market_requests = MarketRequest.query.filter_by(user_id=current_user.id).order_by(MarketRequest.created_at.desc()).all()
    
    return render_template('profile.html', 
                         user=current_user,
                         user_posts=user_posts,
                         user_groups=user_groups,
                         market_items=market_items,
                         market_requests=market_requests)

@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        abort(403)
    
    users = User.query.filter_by(neighborhood_id=current_user.neighborhood_id).all()
    posts = Post.query.filter_by(neighborhood_id=current_user.neighborhood_id).all()
    incidents = Incident.query.filter_by(neighborhood_id=current_user.neighborhood_id).all()
    groups = Group.query.filter_by(neighborhood_id=current_user.neighborhood_id).all()
    
    return render_template('admin_dashboard.html', 
                         users=users, 
                         posts=posts, 
                         incidents=incidents, 
                         groups=groups)

# Add your other admin routes (toggle_admin, delete_user, delete_post, etc.)

from datetime import datetime

from flask import g

@app.before_request
def before_request():
    if current_user.is_authenticated:
        g.unread_count = Message.query.filter_by(
            receiver_id=current_user.id,
            is_read=False
        ).count()

@app.context_processor
def inject_unread_count():
    if current_user.is_authenticated:
        return {'unread_message_count': getattr(g, 'unread_count', 0)}
    return {}

@app.template_filter('time_ago')
def time_ago_filter(dt):
    now = datetime.utcnow()
    diff = now - dt
    
    if diff.days > 365:
        return f"{diff.days // 365} years ago"
    if diff.days > 30:
        return f"{diff.days // 30} months ago"
    if diff.days > 0:
        return f"{diff.days} days ago"
    if diff.seconds > 3600:
        return f"{diff.seconds // 3600} hours ago"
    if diff.seconds > 60:
        return f"{diff.seconds // 60} minutes ago"
    return "just now"

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        current_user.name = request.form.get('name')
        current_user.address = request.form.get('address')
        
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file.filename != '':
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                current_user.profile_pic = filename
        
        db.session.commit()
        flash('Profile updated successfully!')
        return redirect(url_for('profile'))
    
    return render_template('edit_profile.html', user=current_user)

@app.route('/admin/create_neighborhood', methods=['GET', 'POST'])
@login_required
def create_neighborhood():
    if not current_user.is_admin:
        abort(403)
    
    if request.method == 'POST':
        name = request.form.get('name')
        city = request.form.get('city')
        state = request.form.get('state')
        zip_code = request.form.get('zip_code')
        
        new_neighborhood = Neighborhood(
            name=name,
            city=city,
            state=state,
            zip_code=zip_code
        )
        
        db.session.add(new_neighborhood)
        db.session.commit()
        
        flash('Neighborhood created successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('create_neighborhood.html')  # This loads the template

@app.route('/post/new', methods=['GET', 'POST'])
@login_required
def new_post():
    group_id = request.args.get('group_id')
    
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        post_group_id = request.form.get('group_id')
        
        image_filename = None
        if 'image' in request.files:
            file = request.files['image']
            if file.filename != '':
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                image_filename = filename
        
        new_post = Post(
            title=title,
            content=content,
            image=image_filename,
            user_id=current_user.id,
            neighborhood_id=current_user.neighborhood_id,
            group_id=post_group_id if post_group_id else None
        )
        
        db.session.add(new_post)
        db.session.commit()
        flash('Post created successfully!')
        
        if post_group_id:
            return redirect(url_for('view_group', group_id=post_group_id))
        else:
            return redirect(url_for('dashboard'))
    
    # Get user's groups for the dropdown
    user_groups = [membership.group for membership in current_user.group_memberships]
    selected_group = None
    
    if group_id:
        selected_group = Group.query.get(group_id)
        # Check if user is a member of this group
        if not any(g.id == int(group_id) for g in user_groups):
            flash('You are not a member of this group.')
            return redirect(url_for('dashboard'))
    
    return render_template('new_post.html', user_groups=user_groups, selected_group=selected_group)

@app.route('/post/<int:post_id>')
@login_required
def view_post(post_id):
    post = Post.query.get_or_404(post_id)
    
    # Ensure user can only view posts from their neighborhood
    if post.neighborhood_id != current_user.neighborhood_id:
        abort(403)
    
    # If post is in a group, ensure user is a member
    if post.group_id:
        is_member = GroupMember.query.filter_by(
            user_id=current_user.id, 
            group_id=post.group_id
        ).first()
        
        if not is_member:
            flash('You must be a member of this group to view this post.')
            return redirect(url_for('dashboard'))
    
    return render_template('view_post.html', post=post)

@app.route('/post/<int:post_id>/comment', methods=['POST'])
@login_required
def add_comment(post_id):
    post = Post.query.get_or_404(post_id)
    
    # Ensure user can only comment on posts from their neighborhood
    if post.neighborhood_id != current_user.neighborhood_id:
        abort(403)
    
    # If post is in a group, ensure user is a member
    if post.group_id:
        is_member = GroupMember.query.filter_by(
            user_id=current_user.id, 
            group_id=post.group_id
        ).first()
        
        if not is_member:
            flash('You must be a member of this group to comment on this post.')
            return redirect(url_for('dashboard'))
    
    content = request.form.get('content')
    
    new_comment = Comment(
        content=content,
        user_id=current_user.id,
        post_id=post_id
    )
    
    db.session.add(new_comment)
    db.session.commit()
    flash('Comment added successfully!')
    return redirect(url_for('view_post', post_id=post_id))

@app.route('/incident/new', methods=['GET', 'POST'])
@login_required
def new_incident():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        incident_type = request.form.get('incident_type')
        location = request.form.get('location')
        
        image_filename = None
        if 'image' in request.files:
            file = request.files['image']
            if file.filename != '':
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                image_filename = filename
        
        new_incident = Incident(
            title=title,
            description=description,
            incident_type=incident_type,
            location=location,
            image=image_filename,
            user_id=current_user.id,
            neighborhood_id=current_user.neighborhood_id
        )
        
        db.session.add(new_incident)
        db.session.commit()
        flash('Incident reported successfully!')
        return redirect(url_for('dashboard'))
    
    return render_template('new_incident.html')

@app.route('/incident/<int:incident_id>')
@login_required
def view_incident(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    
    # Ensure user can only view incidents from their neighborhood
    if incident.neighborhood_id != current_user.neighborhood_id:
        abort(403)
    
    return render_template('view_incident.html', incident=incident) 

@app.route('/incident/<int:incident_id>/comment', methods=['POST'])
@login_required
def add_incident_comment(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    
    # Ensure user can only comment on incidents from their neighborhood
    if incident.neighborhood_id != current_user.neighborhood_id:
        abort(403)
    
    content = request.form.get('content')
    
    new_comment = IncidentComment(
        content=content,
        user_id=current_user.id,
        incident_id=incident_id
    )
    
    db.session.add(new_comment)
    db.session.commit()
    flash('Comment added successfully!')
    return redirect(url_for('view_incident', incident_id=incident_id))

# Market Route
@app.route('/market')
@login_required
def market():
    market_items = MarketItem.query.filter_by(
        neighborhood_id=current_user.neighborhood_id
    ).order_by(MarketItem.created_at.desc()).all()
    
    market_requests = MarketRequest.query.filter_by(
        neighborhood_id=current_user.neighborhood_id
    ).order_by(MarketRequest.created_at.desc()).all()
    
    return render_template('market.html', 
                         market_items=market_items,
                         market_requests=market_requests)

# Add this route in app.py with the other market routes
@app.route('/market/item/<int:item_id>/contact', methods=['GET', 'POST'])
@login_required
def contact_seller(item_id):
    item = MarketItem.query.get_or_404(item_id)
    seller = User.query.get_or_404(item.user_id)
    
    if item.neighborhood_id != current_user.neighborhood_id:
        abort(403)
    
    if item.user_id == current_user.id:
        flash("You can't contact yourself about your own item.")
        return redirect(url_for('view_market_item', item_id=item.id))
    
    if request.method == 'POST':
        message_content = request.form.get('message')
        if not message_content:
            flash('Message cannot be empty')
            return redirect(url_for('contact_seller', item_id=item.id))
        
        # Create the message
        new_message = Message(
            sender_id=current_user.id,
            receiver_id=seller.id,
            content=message_content,
            item_id=item.id
        )
        db.session.add(new_message)
        db.session.commit()
        
        flash('Message sent successfully!')
        return redirect(url_for('view_conversation', user_id=seller.id, item_id=item.id))
    
    return render_template('contact_seller.html', item=item, seller=seller)

# Add these routes to your app.py

# New Request
@app.route('/market/request/new', methods=['GET', 'POST'])
@login_required
def new_market_request():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        request_type = request.form.get('request_type')
        category = request.form.get('category')
        max_price = request.form.get('max_price')
        
        new_request = MarketRequest(
            title=title,
            description=description,
            request_type=request_type,
            category=category,
            max_price=float(max_price) if max_price else None,
            user_id=current_user.id,
            neighborhood_id=current_user.neighborhood_id
        )
        
        db.session.add(new_request)
        db.session.commit()
        flash('Request posted successfully!')
        return redirect(url_for('market_requests'))
    
    return render_template('new_market_request.html')

# View Requests
@app.route('/market/requests')
@login_required
def market_requests():
    requests = MarketRequest.query.filter_by(
        neighborhood_id=current_user.neighborhood_id
    ).order_by(MarketRequest.created_at.desc()).all()
    
    return render_template('market_requests.html', requests=requests)

# Mark Request as Fulfilled
@app.route('/market/request/<int:request_id>/fulfill', methods=['POST'])
@login_required
def fulfill_request(request_id):
    market_request = MarketRequest.query.get_or_404(request_id)
    
    # Only request owner can mark as fulfilled
    if market_request.user_id != current_user.id:
        abort(403)
    
    market_request.is_fulfilled = True
    db.session.commit()
    flash('Request marked as fulfilled!')
    return redirect(url_for('market_requests'))

@app.route('/messages')
@login_required
def messages():
    # Get all unique conversations
    sent = db.session.query(Message.receiver_id).filter_by(sender_id=current_user.id).distinct()
    received = db.session.query(Message.sender_id).filter_by(receiver_id=current_user.id).distinct()
    user_ids = {id for (id,) in sent.union_all(received)}
    
    conversations = []
    for user_id in user_ids:
        user = User.query.get(user_id)
        if not user:
            continue
            
        last_message = Message.query.filter(
            ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
            ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
        ).order_by(Message.timestamp.desc()).first()
        
        if not last_message:
            continue
            
        unread_count = Message.query.filter_by(
            sender_id=user_id,
            receiver_id=current_user.id,
            is_read=False
        ).count()
        
        conversations.append({
            'user': user,
            'last_message': last_message,
            'unread_count': unread_count
        })
    
    # Sort by most recent message
    conversations.sort(key=lambda x: x['last_message'].timestamp, reverse=True)
    
    return render_template('messages.html', conversations=conversations)

@app.route('/messages/<int:user_id>')
@login_required
def view_conversation(user_id):
    try:
        other_user = User.query.get_or_404(user_id)
        
        # Ensure users are in the same neighborhood
        if other_user.neighborhood_id != current_user.neighborhood_id:
            flash("You can only message users in your neighborhood.")
            return redirect(url_for('messages'))
        
        # Mark messages as read
        Message.query.filter_by(
            sender_id=user_id,
            receiver_id=current_user.id,
            is_read=False
        ).update({'is_read': True})
        db.session.commit()
        
        # Get the conversation
        messages = Message.query.filter(
            ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
            ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
        ).order_by(Message.timestamp.asc()).all()
        
        # Get the item if this conversation started from a market item
        item_id = request.args.get('item_id', type=int)
        item = MarketItem.query.get(item_id) if item_id else None
        
        return render_template('conversation.html', 
                            other_user=other_user, 
                            messages=messages,
                            item=item)
    
    except Exception as e:
        app.logger.error(f"Error in view_conversation: {str(e)}")
        flash("An error occurred while loading the conversation.")
        return redirect(url_for('messages'))
    
@app.route('/messages/<int:user_id>/send', methods=['POST'])
@login_required
def send_message(user_id):
    try:
        other_user = User.query.get_or_404(user_id)
        message_content = request.form.get('message')
        item_id = request.args.get('item_id', type=int)
        
        if not message_content:
            flash("Message cannot be empty.")
            return redirect(url_for('view_conversation', user_id=user_id))
        
        # Ensure users are in the same neighborhood
        if other_user.neighborhood_id != current_user.neighborhood_id:
            flash("You can only message users in your neighborhood.")
            return redirect(url_for('messages'))
        
        new_message = Message(
            sender_id=current_user.id,
            receiver_id=user_id,
            content=message_content,
            item_id=item_id
        )
        
        db.session.add(new_message)
        db.session.commit()
        
        return redirect(url_for('view_conversation', user_id=user_id, item_id=item_id))
    
    except Exception as e:
        app.logger.error(f"Error sending message: {str(e)}")
        flash("An error occurred while sending your message.")
        return redirect(url_for('messages'))

# Group Routes
@app.route('/groups')
@login_required
def groups():
    # Get all groups in the user's neighborhood
    neighborhood_groups = Group.query.filter_by(neighborhood_id=current_user.neighborhood_id).all()
    
    # Get groups the user is a member of
    user_groups = [membership.group for membership in current_user.group_memberships]
    
    return render_template('groups.html', neighborhood_groups=neighborhood_groups, user_groups=user_groups)

# New group creation
@app.route('/group/new', methods=['GET', 'POST'])
@login_required
def new_group():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        is_private = True if request.form.get('is_private') else False
        
        image_filename = 'group_default.jpg'
        if 'image' in request.files:
            file = request.files['image']
            if file.filename != '':
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                image_filename = filename
        
        new_group = Group(
            name=name,
            description=description,
            image=image_filename,
            creator_id=current_user.id,
            neighborhood_id=current_user.neighborhood_id,
            is_private=is_private
        )
        
        db.session.add(new_group)
        db.session.commit()
        
        # Add creator as admin member
        group_member = GroupMember(
            user_id=current_user.id,
            group_id=new_group.id,
            is_admin=True
        )
        db.session.add(group_member)
        db.session.commit()
        
        flash('Group created successfully!')
        return redirect(url_for('view_group', group_id=new_group.id))
    
    return render_template('new_group.html')

# Request to join private group
@app.route('/group/<int:group_id>/request_join', methods=['POST'])
@login_required
def request_join_group(group_id):
    group = Group.query.get_or_404(group_id)
    
    if group.neighborhood_id != current_user.neighborhood_id:
        abort(403)
    
    # Check if already a member
    if GroupMember.query.filter_by(user_id=current_user.id, group_id=group.id).first():
        flash('You are already a member of this group.')
        return redirect(url_for('view_group', group_id=group.id))
    
    # Check for existing request
    existing_request = GroupJoinRequest.query.filter_by(
        user_id=current_user.id,
        group_id=group.id,
        status='pending'
    ).first()
    
    if existing_request:
        flash('You already have a pending request to join this group.')
    else:
        join_request = GroupJoinRequest(
            user_id=current_user.id,
            group_id=group.id,
            status='pending'
        )
        db.session.add(join_request)
        db.session.commit()
        flash('Your request to join has been submitted to the group admins.')
    
    return redirect(url_for('view_group', group_id=group.id))

# Approve join request
@app.route('/group/request/<int:request_id>/approve', methods=['POST'])
@login_required
def approve_join_request(request_id):
    request = GroupJoinRequest.query.get_or_404(request_id)
    group = request.group
    
    # Verify admin status
    membership = GroupMember.query.filter_by(
        user_id=current_user.id,
        group_id=group.id,
        is_admin=True
    ).first()
    
    if not membership:
        abort(403)
    
    # Add user to group
    group_member = GroupMember(
        user_id=request.user_id,
        group_id=group.id,
        is_admin=False
    )
    db.session.add(group_member)
    
    # Update request status
    request.status = 'approved'
    db.session.commit()
    
    flash(f"{request.user.name}'s join request has been approved.")
    return redirect(url_for('manage_join_requests', group_id=group.id))

# Reject join request
@app.route('/group/request/<int:request_id>/reject', methods=['POST'])
@login_required
def reject_join_request(request_id):
    request = GroupJoinRequest.query.get_or_404(request_id)
    group = request.group
    
    # Verify admin status
    membership = GroupMember.query.filter_by(
        user_id=current_user.id,
        group_id=group.id,
        is_admin=True
    ).first()
    
    if not membership:
        abort(403)
    
    # Update request status
    request.status = 'rejected'
    db.session.commit()
    
    flash(f"{request.user.name}'s join request has been rejected.")
    return redirect(url_for('manage_join_requests', group_id=group.id))

@app.route('/group/<int:group_id>')
@login_required
def view_group(group_id):
    group = Group.query.get_or_404(group_id)
    
    # Check if group is in user's neighborhood
    if group.neighborhood_id != current_user.neighborhood_id:
        abort(403)
    
    # Check if user is a member
    is_member = GroupMember.query.filter_by(
        user_id=current_user.id, 
        group_id=group.id
    ).first()
    
    # Get group posts
    posts = Post.query.filter_by(group_id=group.id).order_by(Post.created_at.desc()).all()
    
    # Get group incidents
    group_incidents = GroupIncident.query.filter_by(group_id=group.id).order_by(GroupIncident.created_at.desc()).all()
    
    # Get group polls
    polls = Poll.query.filter_by(group_id=group.id).order_by(Poll.created_at.desc()).all()
    
    # Get group members
    members = GroupMember.query.filter_by(group_id=group.id).all()

    # Calculate vote percentages for each poll
    for poll in polls:
        total_votes = sum(len(option.votes) for option in poll.options)
        for option in poll.options:
            option.percentage = round((len(option.votes) / (total_votes or 1)) * 100, 2)
        poll.user_vote = next(
            (option for option in poll.options
             if any(vote.user_id == current_user.id for vote in option.votes)),
            None
        )
    
    return render_template('view_group.html', 
                         group=group, 
                         is_member=is_member, 
                         posts=posts,
                         group_incidents=group_incidents,
                         polls=polls,
                         members=members,
                         datetime=datetime)

@app.route('/group/<int:group_id>/join', methods=['POST'])
@login_required
def join_group(group_id):
    group = Group.query.get_or_404(group_id)
    
    # Ensure group is in user's neighborhood
    if group.neighborhood_id != current_user.neighborhood_id:
        abort(403)
    
    # Check if user is already a member
    existing_member = GroupMember.query.filter_by(
        user_id=current_user.id, 
        group_id=group.id
    ).first()
    
    if existing_member:
        flash('You are already a member of this group.')
        return redirect(url_for('view_group', group_id=group.id))
    
    # Add user as a member
    group_member = GroupMember(
        user_id=current_user.id,
        group_id=group.id,
        is_admin=False
    )
    
    db.session.add(group_member)
    db.session.commit()
    
    flash('You have joined the group successfully!')
    return redirect(url_for('view_group', group_id=group.id))



@app.route('/group/<int:group_id>/leave', methods=['POST'])
@login_required
def leave_group(group_id):
    group = Group.query.get_or_404(group_id)
    
    # Find the membership
    membership = GroupMember.query.filter_by(
        user_id=current_user.id, 
        group_id=group.id
    ).first()
    
    if not membership:
        flash('You are not a member of this group.')
        return redirect(url_for('view_group', group_id=group.id))
    
    # Check if user is the creator/only admin
    if group.creator_id == current_user.id:
        # Count other admins
        other_admins = GroupMember.query.filter(
            GroupMember.group_id == group.id,
            GroupMember.is_admin == True,
            GroupMember.user_id != current_user.id
        ).count()
        
        if other_admins == 0:
            flash('You cannot leave the group as you are the only admin. Make someone else an admin first or delete the group.')
            return redirect(url_for('view_group', group_id=group.id))
    
    # Remove membership
    db.session.delete(membership)
    db.session.commit()
    
    flash('You have left the group successfully.')
    return redirect(url_for('groups'))

# Group Incidents
@app.route('/group/<int:group_id>/incident/new', methods=['GET', 'POST'])
@login_required
def new_group_incident(group_id):
    group = Group.query.get_or_404(group_id)
    # Check if user is member
    if not GroupMember.query.filter_by(user_id=current_user.id, group_id=group.id).first():
        abort(403)
    
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        incident_type = request.form.get('incident_type')
        location = request.form.get('location')
        
        image_filename = None
        if 'image' in request.files:
            file = request.files['image']
            if file.filename != '':
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                image_filename = filename
        
        new_incident = GroupIncident(
            title=title,
            description=description,
            incident_type=incident_type,
            location=location,
            image=image_filename,
            user_id=current_user.id,
            group_id=group.id
        )
        
        db.session.add(new_incident)
        db.session.commit()
        flash('Incident reported to group successfully!')
        return redirect(url_for('view_group', group_id=group.id))
    
    return render_template('new_group_incident.html', group=group)

@app.route('/group/<int:group_id>/incident/<int:incident_id>')
@login_required
def view_group_incident(group_id, incident_id):
    group = Group.query.get_or_404(group_id)
    incident = GroupIncident.query.get_or_404(incident_id)
    
    # Verify incident belongs to group
    if incident.group_id != group.id:
        abort(404)
    
    # Check if user is member
    if not GroupMember.query.filter_by(user_id=current_user.id, group_id=group.id).first():
        abort(403)
    
    return render_template('view_group_incident.html', 
                         group=group,
                         incident=incident)

@app.route('/group/incident/<int:incident_id>/comment', methods=['POST'])
@login_required
def add_group_incident_comment(incident_id):
    incident = GroupIncident.query.get_or_404(incident_id)
    group = incident.group
    
    # Check if user is member
    if not GroupMember.query.filter_by(user_id=current_user.id, group_id=group.id).first():
        abort(403)
    
    content = request.form.get('content')
    if not content:
        flash('Comment cannot be empty')
        return redirect(url_for('view_group_incident', group_id=group.id, incident_id=incident.id))
    
    comment = GroupIncidentComment(
        content=content,
        user_id=current_user.id,
        incident_id=incident.id
    )
    
    db.session.add(comment)
    db.session.commit()
    
    flash('Comment added successfully')
    return redirect(url_for('view_group_incident', group_id=group.id, incident_id=incident.id))

# Polls
@app.route('/group/<int:group_id>/poll/new', methods=['GET', 'POST'])
@login_required
def new_poll(group_id):
    group = Group.query.get_or_404(group_id)
    # Check if user is member
    if not GroupMember.query.filter_by(user_id=current_user.id, group_id=group.id).first():
        abort(403)
    
    if request.method == 'POST':
        question = request.form.get('question')
        days = int(request.form.get('days', 7))
        options = [opt.strip() for opt in request.form.get('options').split('\n') if opt.strip()]
        
        if len(options) < 2:
            flash('Please provide at least 2 options')
            return redirect(url_for('new_poll', group_id=group.id))
        
        expires_at = datetime.utcnow() + timedelta(days=days)
        new_poll = Poll(
            question=question,
            expires_at=expires_at,
            user_id=current_user.id,
            group_id=group.id
        )
        db.session.add(new_poll)
        
        for option_text in options:
            option = PollOption(text=option_text, poll=new_poll)
            db.session.add(option)
        
        db.session.commit()
        flash('Poll created successfully!')
        return redirect(url_for('view_group', group_id=group.id))
    
    return render_template('new_poll.html', group=group)

@app.route('/poll/<int:poll_id>/vote', methods=['POST'])
@login_required
def vote_poll(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    option_id = request.form.get('option_id')
    
    # Check if user is member
    if not GroupMember.query.filter_by(user_id=current_user.id, group_id=poll.group_id).first():
        abort(403)
    
    # Check if poll is still open
    if poll.expires_at and poll.expires_at < datetime.utcnow():
        flash('This poll has closed')
        return redirect(url_for('view_group', group_id=poll.group_id))
    
    # Check if user already voted
    existing_vote = PollVote.query.filter_by(user_id=current_user.id).join(PollOption).filter_by(poll_id=poll.id).first()
    if existing_vote:
        flash('You have already voted in this poll')
        return redirect(url_for('view_group', group_id=poll.group_id))
    
    # Record vote
    new_vote = PollVote(
        user_id=current_user.id,
        option_id=option_id
    )
    db.session.add(new_vote)
    db.session.commit()
    
    flash('Your vote has been recorded')
    return redirect(url_for('view_group', group_id=poll.group_id))

@app.route('/group/<int:group_id>/manage_requests')
@login_required
def manage_join_requests(group_id):
    group = Group.query.get_or_404(group_id)
    
    # Verify admin status
    membership = GroupMember.query.filter_by(
        user_id=current_user.id,
        group_id=group.id,
        is_admin=True
    ).first()
    
    if not membership:
        abort(403)
    
    requests = GroupJoinRequest.query.filter_by(
        group_id=group.id,
        status='pending'
    ).order_by(GroupJoinRequest.requested_at.desc()).all()
    
    return render_template('manage_requests.html', group=group, requests=requests)


@app.route('/group/<int:group_id>/make_admin/<int:user_id>', methods=['POST'])
@login_required
def make_group_admin(group_id, user_id):
    group = Group.query.get_or_404(group_id)
    
    # Check if current user is an admin
    current_user_membership = GroupMember.query.filter_by(
        user_id=current_user.id, 
        group_id=group.id,
        is_admin=True
    ).first()
    
    if not current_user_membership:
        flash('You do not have permission to make users admins.')
        return redirect(url_for('view_group', group_id=group.id))
    
    # Find the target user's membership
    target_membership = GroupMember.query.filter_by(
        user_id=user_id, 
        group_id=group.id
    ).first()
    
    if not target_membership:
        flash('User is not a member of this group.')
        return redirect(url_for('view_group', group_id=group.id))
    
    # Make user an admin
    target_membership.is_admin = True
    db.session.commit()
    
    flash('User has been made an admin successfully.')
    return redirect(url_for('view_group', group_id=group.id))

@app.route('/group/<int:group_id>/remove_admin/<int:user_id>', methods=['POST'])
@login_required
def remove_group_admin(group_id, user_id):
    group = Group.query.get_or_404(group_id)
    
    # Check if current user is an admin
    current_user_membership = GroupMember.query.filter_by(
        user_id=current_user.id, 
        group_id=group.id,
        is_admin=True
    ).first()
    
    if not current_user_membership:
        flash('You do not have permission to remove admin status.')
        return redirect(url_for('view_group', group_id=group.id))
    
    # Cannot remove creator's admin status
    if user_id == group.creator_id:
        flash('Cannot remove admin status from the group creator.')
        return redirect(url_for('view_group', group_id=group.id))
    
    # Find the target user's membership
    target_membership = GroupMember.query.filter_by(
        user_id=user_id, 
        group_id=group.id
    ).first()
    
    if not target_membership:
        flash('User is not a member of this group.')
        return redirect(url_for('view_group', group_id=group.id))
    
    # Remove admin status
    target_membership.is_admin = False
    db.session.commit()
    
    flash('Admin status has been removed successfully.')
    return redirect(url_for('view_group', group_id=group.id))

@app.route('/group/<int:group_id>/remove_member/<int:user_id>', methods=['POST'])
@login_required
def remove_group_member(group_id, user_id):
    group = Group.query.get_or_404(group_id)
    
    # Check if current user is an admin
    current_user_membership = GroupMember.query.filter_by(
        user_id=current_user.id, 
        group_id=group.id,
        is_admin=True
    ).first()
    
    if not current_user_membership:
        flash('You do not have permission to remove members.')
        return redirect(url_for('view_group', group_id=group.id))
    
    # Cannot remove the creator
    if user_id == group.creator_id and current_user.id != group.creator_id:
        flash('Cannot remove the group creator.')
        return redirect(url_for('view_group', group_id=group.id))
    
    # Find the target user's membership
    target_membership = GroupMember.query.filter_by(
        user_id=user_id, 
        group_id=group.id
    ).first()
    
    if not target_membership:
        flash('User is not a member of this group.')
        return redirect(url_for('view_group', group_id=group.id))
    
    # Remove membership
    db.session.delete(target_membership)
    db.session.commit()
    
    flash('Member has been removed successfully.')
    return redirect(url_for('view_group', group_id=group.id))

@app.route('/group/<int:group_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_group(group_id):
    group = Group.query.get_or_404(group_id)
    
    # Check if current user is an admin
    current_user_membership = GroupMember.query.filter_by(
        user_id=current_user.id, 
        group_id=group.id,
        is_admin=True
    ).first()
    
    if not current_user_membership:
        flash('You do not have permission to edit this group.')
        return redirect(url_for('view_group', group_id=group.id))
    
    if request.method == 'POST':
        group.name = request.form.get('name')
        group.description = request.form.get('description')
        group.is_private = 'is_private' in request.form
        
        if 'image' in request.files:
            file = request.files['image']
            if file.filename != '':
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                group.image = filename
        
        db.session.commit()
        flash('Group updated successfully!')
        return redirect(url_for('view_group', group_id=group.id))
    
    return render_template('edit_group.html', group=group)

@app.route('/group/incident/<int:incident_id>/delete', methods=['POST'])
@login_required
def delete_group_incident(incident_id):
    incident = GroupIncident.query.get_or_404(incident_id)
    group = incident.group
    
    # Check if user is member and has permission (creator or admin)
    membership = GroupMember.query.filter_by(
        user_id=current_user.id,
        group_id=group.id
    ).first()
    
    if not membership or (incident.user_id != current_user.id and not membership.is_admin):
        abort(403)
    
    db.session.delete(incident)
    db.session.commit()
    flash('Incident deleted successfully!')
    return redirect(url_for('view_group', group_id=group.id))

@app.route('/group/<int:group_id>/delete', methods=['POST'])
@login_required
def delete_group(group_id):
    group = Group.query.get_or_404(group_id)
    
    # Authorization checks:
    # 1. Must be either:
    #    - The group creator, OR
    #    - An admin from the same neighborhood, OR
    #    - A group admin (if group admins should have this power)
    is_creator = (group.creator_id == current_user.id)
    is_neighborhood_admin = (current_user.is_admin and 
                           group.neighborhood_id == current_user.neighborhood_id)
    is_group_admin = GroupMember.query.filter_by(
        user_id=current_user.id,
        group_id=group.id,
        is_admin=True
    ).first() is not None
    
    if not (is_creator or is_neighborhood_admin or is_group_admin):
        abort(403)
    
    # Clean up all related data
    # 1. Delete all posts in the group
    Post.query.filter_by(group_id=group.id).delete()
    
    # 2. Delete all group memberships
    GroupMember.query.filter_by(group_id=group.id).delete()
    
    # 3. Delete all group incidents and their comments
    for incident in group.group_incidents:
        GroupIncidentComment.query.filter_by(incident_id=incident.id).delete()
    GroupIncident.query.filter_by(group_id=group.id).delete()
    
    # 4. Delete all polls and related data
    for poll in group.polls:
        for option in poll.options:
            PollVote.query.filter_by(option_id=option.id).delete()
        PollOption.query.filter_by(poll_id=poll.id).delete()
    Poll.query.filter_by(group_id=group.id).delete()
    
    # Finally delete the group itself
    db.session.delete(group)
    db.session.commit()
    
    flash('Group and all its content have been deleted successfully!')
    
    # Smart redirect based on who deleted it
    if is_neighborhood_admin:
        return redirect(url_for('admin'))
    else:
        return redirect(url_for('groups'))
@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        abort(403)
    
    users = User.query.filter_by(neighborhood_id=current_user.neighborhood_id).all()
    posts = Post.query.filter_by(neighborhood_id=current_user.neighborhood_id).all()
    incidents = Incident.query.filter_by(neighborhood_id=current_user.neighborhood_id).all()
    groups = Group.query.filter_by(neighborhood_id=current_user.neighborhood_id).all()
    
    return render_template('admin.html', users=users, posts=posts, incidents=incidents, groups=groups)

def check_admin_or_owner(item):
    """Check if current user is admin or owner of the item"""
    if not current_user.is_admin and item.user_id != current_user.id:
        abort(403)


@app.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    check_admin_or_owner(post)  # This will handle the permission check
    
    db.session.delete(post)
    db.session.commit()
    flash('Post deleted!')
    return redirect_back()  # Or specific redirect

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if not current_user.is_admin:
        abort(403)
    
    user = User.query.get_or_404(user_id)
    if user == current_user:
        flash("Cannot delete yourself!", "danger")
    else:
        # Delete user's content first (optional)
        Post.query.filter_by(user_id=user.id).delete()
        # Then delete user
        db.session.delete(user)
        db.session.commit()
        flash('User deleted!')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/purge_inactive', methods=['POST'])
@login_required
def purge_inactive():
    if not current_user.is_admin:
        abort(403)
    
    # Example: Delete users inactive for 1 year
    one_year_ago = datetime.utcnow() - timedelta(days=365)
    inactive_users = User.query.filter(
        User.last_seen < one_year_ago,
        User.is_admin == False  # Don't delete admins
    ).all()
    
    for user in inactive_users:
        db.session.delete(user)
    
    db.session.commit()
    flash(f'Deleted {len(inactive_users)} inactive users!')
    return redirect(url_for('admin_dashboard'))

# Example for groups

    
@app.route('/poll/<int:poll_id>/delete', methods=['POST'])
@login_required
def delete_poll(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    
    # Check permissions - creator or group admin can delete
    if poll.user_id != current_user.id:
        # Check if user is group admin
        group_member = GroupMember.query.filter_by(
            user_id=current_user.id,
            group_id=poll.group_id,
            is_admin=True
        ).first()
        if not group_member:
            abort(403)
    
    db.session.delete(poll)
    db.session.commit()
    
    flash('Poll deleted successfully!')
    return redirect(url_for('view_group', group_id=poll.group_id))

@app.route('/admin/user/<int:user_id>/toggle_admin', methods=['POST'])
@login_required
def toggle_admin(user_id):
    if not current_user.is_admin:
        abort(403)
    
    user = User.query.get_or_404(user_id)
    
    # Ensure admin can only modify users from their neighborhood
    if user.neighborhood_id != current_user.neighborhood_id:
        abort(403)
    
    user.is_admin = not user.is_admin
    db.session.commit()
    flash(f'Admin status for {user.name} updated successfully!')
    return redirect(url_for('admin'))



@app.route('/admin/make_admin/<int:user_id>', methods=['POST'])
@login_required
def make_admin(user_id):
    if not current_user.is_admin:
        abort(403)
    
    user = User.query.get_or_404(user_id)
    user.is_admin = True
    db.session.commit()
    
    flash(f'{user.name} is now an admin!')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        abort(403)
    
    user = User.query.get_or_404(user_id)
    if user == current_user:
        flash("You cannot delete yourself!", "danger")
    else:
        db.session.delete(user)
        db.session.commit()
        flash(f'User {user.name} deleted successfully!')
    
    return redirect(url_for('admin_dashboard'))


# For group incidents


# Similar for regular incidents
@app.route('/incident/<int:incident_id>/delete', methods=['POST'])
@login_required
def delete_incident(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    
    if incident.user_id != current_user.id and not current_user.is_admin:
        abort(403)
    
    db.session.delete(incident)
    db.session.commit()
    flash('Incident deleted successfully!')
    return redirect(url_for('dashboard'))

# At the bottom of your app.py, before the if __name__ == '__main__' block
def reset_database():
    with app.app_context():
        # Drop all tables
        db.drop_all()
        
        # Create all tables with current schema
        db.create_all()
        
        # Create default neighborhood
        default_neighborhood = Neighborhood(
            name="Sample Neighborhood",
            city="Sample City",
            state="Sample State",
            zip_code="12345"
        )
        db.session.add(default_neighborhood)
        db.session.commit()
        
        # Create admin user
        admin_user = User(
            email="admin@example.com",
            name="Admin User",
            password=generate_password_hash("admin123", method='scrypt'),
            address="123 Admin St",
            neighborhood_id=default_neighborhood.id,
            is_admin=True
        )
        db.session.add(admin_user)
        
        # Create a test user
        test_user = User(
            email="user@example.com",
            name="Test User",
            password=generate_password_hash("user123", method='scrypt'),
            address="456 User Ave",
            neighborhood_id=default_neighborhood.id
        )
        db.session.add(test_user)
        db.session.commit()
        
        print("Database has been reset with the current schema")
#reset_database()


if __name__ == '__main__':
    socketio.run(app, debug=True)
    with app.app_context():
        db.create_all()
        
        # Create default neighborhood if none exists
        if not Neighborhood.query.first():
            default_neighborhood = Neighborhood(
                name="Sample Neighborhood",
                city="Sample City",
                state="Sample State",
                zip_code="12345"
            )
            db.session.add(default_neighborhood)
            db.session.commit()
            
            # Create admin user
            if not User.query.first():
                admin_user = User(
                    email="admin@example.com",
                    name="Admin User",
                    password=generate_password_hash("admin123", method='sha256'),
                    address="123 Admin St",
                    neighborhood_id=default_neighborhood.id,
                    is_admin=True
                )
                db.session.add(admin_user)
                db.session.commit()
    
    app.run(debug=True)