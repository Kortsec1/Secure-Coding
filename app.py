import sqlite3
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send, join_room, leave_room, emit
from flask_wtf import CSRFProtect
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
DATABASE = 'market.db'
socketio = SocketIO(app)
csrf = CSRFProtect()
csrf.init_app(app)
app.secret_key = 'super-secret-key'

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,      # JavaScript에서 쿠키 접근 차단
    SESSION_COOKIE_SECURE=True,        # HTTPS 환경에서만 전송
    SESSION_COOKIE_SAMESITE='Lax'      # 크로스 사이트 요청 제한
)
if os.environ.get("FLASK_ENV") == "development":
    app.config['SESSION_COOKIE_SECURE'] = False

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL
            )
        """)
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)
        db.commit()

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        # 중복 사용자 체크
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
        user_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)", (user_id, username, password))
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()
        if user and user['is_suspended'] == 1:
            flash('정지된 사용자입니다.')
            return redirect(url_for('login'))
        if user:
            session['user_id'] = user['id']
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
    return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    # 모든 상품 조회
    cursor.execute("SELECT * FROM product")
    all_products = cursor.fetchall()
    return render_template('dashboard.html', products=all_products, user=current_user)

# 사용자 검색 페이지
@app.route('/user_search', methods=['GET', 'POST'])
def user_search():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    query = None
    results = []
    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        query = request.form.get('query')
        cursor.execute("SELECT * FROM user WHERE username LIKE ?", ('%' + query + '%',))
        results = cursor.fetchall()

    current_user = None
    if 'user_id' in session:
        cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        current_user = cursor.fetchone()
    return render_template('user_search.html', query=query, results=results, current_user=current_user)

# 악성 유저 휴면
@app.route('/admin/suspend/<user_id>', methods=['POST'])
def suspend_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    if not current_user or int(current_user['is_admin'] if 'is_admin' in current_user.keys() else 0) != 1:
        flash("관리자만 접근할 수 있습니다.")
        return redirect(url_for('dashboard'))

    if current_user['id'] == user_id:
        flash("자기 자신은 정지할 수 없습니다.")
        return redirect(url_for('user_search'))

    cursor.execute("UPDATE user SET is_suspended = 1 WHERE id = ?", (user_id,))
    db.commit()
    flash("사용자를 정지시켰습니다.")
    return redirect(url_for('user_search'))

# 악성 유저 휴면 해제
@app.route('/admin/unsuspend/<user_id>', methods=['POST'])
def unsuspend_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    is_admin = int(current_user['is_admin']) if 'is_admin' in current_user.keys() else 0
    if not current_user or is_admin != 1:
        flash("관리자만 접근할 수 있습니다.")
        return redirect(url_for('dashboard'))

    if current_user['id'] == user_id:
        flash("자기 자신은 해제할 수 없습니다.")
        return redirect(url_for('user_search'))

    cursor.execute("UPDATE user SET is_suspended = 0 WHERE id = ?", (user_id,))
    db.commit()
    flash("사용자 정지가 해제되었습니다.")
    return redirect(url_for('user_search'))

# 프로필 페이지: bio 업데이트 가능, 비밀번호 변경 기능
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_password':
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            
            # 현재 비밀번호 확인
            cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
            user = cursor.fetchone()
            if user and user['password'] == current_password:
                cursor.execute("UPDATE user SET password = ? WHERE id = ?", (new_password, session['user_id']))
                db.commit()
                flash('비밀번호가 성공적으로 변경되었습니다.')
            else:
                flash('현재 비밀번호가 일치하지 않습니다.')
            return redirect(url_for('profile'))

        bio = request.form.get('bio', '')
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))

    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    return render_template('profile.html', user=current_user)

# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'])
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')

# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()

    current_user = None
    if 'user_id' in session:
        cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        current_user = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller, current_user=current_user)

# 상품 수정하기
@app.route('/product/edit/<product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if not product or product['seller_id'] != session['user_id']:
        flash('수정 권한이 없습니다.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        cursor.execute("UPDATE product SET title = ?, description = ?, price = ? WHERE id = ?",
                       (title, description, price, product_id))
        db.commit()
        flash('상품 정보가 수정되었습니다.')
        return redirect(url_for('view_product', product_id=product_id))

    return render_template('edit_product.html', product=product)

# 상품 삭제하기
@app.route('/product/delete/<product_id>', methods=['POST'])
def delete_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if not product:
        flash("상품을 찾을 수 없습니다.")
        return redirect(url_for('dashboard'))

    if product['seller_id'] == current_user['id'] or current_user['is_admin'] == 1:
        cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
        db.commit()
        flash("상품이 삭제되었습니다.")
    else:
        flash("삭제 권한이 없습니다.")

    return redirect(url_for('dashboard'))

# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        target_id = request.form['target_id']
        reason = request.form['reason']
        db = get_db()
        cursor = db.cursor()
        report_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, reason)
        )
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('report.html')

# 유저간 1대1 채팅
@app.route('/chat/<target_user_id>')
def private_chat(target_user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    my_id = session['user_id']
    if my_id == target_user_id:
        flash('자기 자신과 채팅할 수 없습니다.')
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (target_user_id,))
    target_user = cursor.fetchone()
    if not target_user:
        flash('사용자를 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    room_id = "-".join(sorted([my_id, target_user_id]))
    return render_template('chat.html', room_id=room_id, target_user=target_user)

# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

# 유저간 1대1 채팅 방 생성
@socketio.on('join')
def on_join(data):
    room = data['room']
    print(f"[JOIN] user joined room: {room}")
    join_room(room)

# 유저간 1대1 채팅
@socketio.on('private_message')
def handle_private_message(data):
    room = data['room']
    sender_id = data.get('sender_id')
    emit('chat_message', {'message': data['message'], 'sender_id': sender_id}, to=data['room'])

if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app, debug=True)
