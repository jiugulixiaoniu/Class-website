# app.py
from flask import Flask, request, jsonify
import jwt
import datetime
import pandas as pd
from flask_cors import CORS
import os
import sys
import logging
import sqlite3
import markdown

# 初始化Flask应用
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev_secret_key_here')
CORS(app,
     resources={
         r"/api/*": {
             "origins": ["http://localhost:63342", "http://localhost:5000"],
             "supports_credentials": True,
             "allow_headers": ["Authorization", "Content-Type"],
             "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
         }
     }
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

# 常量定义
EXCEL_PATH = os.path.join(os.path.dirname(__file__), 'Password', 'information.xlsx')
DB_PATH = os.path.join(os.path.dirname(__file__), 'Password', 'class_website.db')
ARTICLE_DIR = os.path.join(os.path.dirname(__file__), '../Article')
REQUIRED_COLUMNS = ['Name', 'display_name', 'password', 'permission', 'banned', 'last_login', 'register_time']


def load_user_data():
    """从 SQLite 加载用户数据"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users')
        rows = cursor.fetchall()
        users = {}
        for row in rows:
            users[row[0]] = {
                'display_name': row[1],
                'password': row[2],
                'permission': row[3],
                'banned': row[4],
                'last_login': row[5],
                'register_time': row[6]
            }
        conn.close()
        return users
    except Exception as e:
        logging.error(f"加载用户数据失败: {e}")
        return {}


def save_user_to_excel(users):
    """将用户数据保存到 Excel"""
    try:
        df = pd.DataFrame.from_dict(users, orient='index')
        df.to_excel(EXCEL_PATH, index_label='Name')
    except Exception as e:
        logging.error(f"保存用户数据到 Excel 失败: {e}")


def save_user_to_db(users):
    """将用户数据保存到 SQLite"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('DROP TABLE IF EXISTS users')
        cursor.execute('''
            CREATE TABLE users (
                Name TEXT PRIMARY KEY,
                display_name TEXT,
                password TEXT,
                permission INTEGER,
                banned BOOLEAN DEFAULT FALSE,
                last_login TEXT,
                register_time TEXT
            )
        ''')
        for username, user in users.items():
            cursor.execute('''
                INSERT INTO users (Name, display_name, password, permission, banned, last_login, register_time)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (username, user['display_name'], user['password'], user['permission'], user['banned'], user['last_login'], user['register_time']))
        conn.commit()
        conn.close()
    except Exception as e:
        logging.error(f"保存用户数据到 SQLite 失败: {e}")


@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'  # 允许所有域名（开发环境）
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'
    response.headers['Access-Control-Max-Age'] = '86400'  # 预检缓存时间
    return response


@app.route('/api/login', methods=['POST'])
def handle_login():
    """处理用户登录请求"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        users = load_user_data()
        user = users.get(username)
        if not user or user['password'] != password or user['banned']:
            return jsonify({"error": "用户名或密码错误，或用户已被封禁"}), 401
        payload = {
            'username': username,
            'permission': user['permission'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=168)
        }
        token = jwt.encode(payload, app.secret_key, algorithm='HS256')
        # 更新最后登录时间
        user['last_login'] = datetime.datetime.now().isoformat()
        save_user_to_excel(users)
        save_user_to_db(users)
        return jsonify({"token": token, "permission": user['permission'], "display_name": user['display_name']})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/validate', methods=['GET'])
def validate_jwt_token():
    """验证 JWT 令牌有效性"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Unauthorized"}), 401
        token = auth_header.split(' ')[1]
        payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        return jsonify({"status": "success", "payload": payload})
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token已过期"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "无效的Token"}), 401


@app.route('/api/users', methods=['GET'])
def get_all_users():
    """获取所有用户信息"""
    try:
        users = load_user_data()
        return jsonify(list(users.values()))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def _build_cors_preflight_response():
    response = jsonify({"status": "preflight"})
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'
    return response
@app.route('/api/users/update', methods=['POST', 'OPTIONS'])
def update_user():
    """更新用户信息"""
    if request.method == 'OPTIONS':
        return _build_cors_preflight_response()  # 专门处理OPTIONS请求
    try:

        data = request.get_json()
        if 'display_name' not in data or 'field' not in data or 'value' not in data:
            return jsonify({"error": "缺少必要字段: display_name, field, value"}), 400

        # 检查字段是否允许修改
        allowed_fields = ['permission', 'banned', 'display_name']
        if data['field'] not in allowed_fields:
            return jsonify({"error": f"禁止修改字段: {data['field']}"}), 403

        users = load_user_data()

        # 权限验证
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(' ')[1]
        payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])

        # 获取目标用户
        display_name = data['display_name']
        target_user = next((user for user in users.values() if user['display_name'] == display_name), None)
        if not target_user:
            return jsonify({"error": "用户不存在"}), 404

        # 获取当前用户权限
        current_permission = payload['permission']

        # 双重权限验证
        if target_user['permission'] >= 5 and payload['permission'] < 5:
            return jsonify({"error": "禁止操作5级用户"}), 403
        if payload['permission'] <= target_user['permission']:
            return jsonify({"error": "权限不足"}), 403
        if data['field'] == 'permission' and data['value'] >= current_permission:
            return jsonify({"error": "不能设置等于或高于自己权限的等级"}), 403

        # 更新用户数据
        for username, user in users.items():
            if user['display_name'] == display_name:
                users[username][data['field']] = data['value']
                break

        # 保存到 Excel 和 SQLite
        save_user_to_excel(users)
        save_user_to_db(users)

        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/access-logs', methods=['GET'])
def get_access_logs():
    """获取访问日志"""
    try:
        # 这里可以添加获取访问日志的逻辑
        # 示例：假设访问日志存储在一个列表中
        access_logs = []
        return jsonify(access_logs)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/users/register', methods=['POST'])
def register_user():
    """注册新用户"""
    try:
        data = request.get_json()
        users = load_user_data()

        # 权限验证
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Unauthorized"}), 401

        token = auth_header.split(' ')[1]
        payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])

        if payload['permission'] < 4:
            return jsonify({"error": "权限不足，需要4级以上管理员"}), 403

        # 字段验证
        required_fields = ['username', 'display_name', 'password', 'permission']
        if not all(field in data for field in required_fields):
            return jsonify({"error": "缺少必要字段"}), 400

        # 用户名唯一性验证
        if data['username'] in users:
            return jsonify({"error": "用户名已存在"}), 400

        # 添加新用户
        users[data['username']] = {
            'display_name': data['display_name'],
            'password': data['password'],
            'permission': int(data['permission']),
            'banned': False,
            'last_login': datetime.datetime.now().isoformat(),
            'register_time': datetime.datetime.now().isoformat()
        }

        # 保存到 Excel 和 SQLite
        save_user_to_excel(users)
        save_user_to_db(users)

        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.before_request
def log_access():
    """记录访问日志"""
    try:
        # 这里可以添加记录访问日志的逻辑
        pass
    except Exception as e:
        logging.error(f"记录访问日志失败: {e}")


def get_ip_location(ip):
    """获取 IP 地址的地理位置"""
    try:
        # 这里可以添加获取 IP 地址地理位置的逻辑
        pass
    except Exception as e:
        logging.error(f"获取 IP 地址地理位置失败: {e}")


@app.errorhandler(404)
def handle_404(e):
    return jsonify({"error": "未找到该资源"}), 404


@app.errorhandler(Exception)
def handle_exception(e):
    # 确保返回 JSON 格式
    return jsonify({"error": str(e)}), 500


@app.route('/api/articles/publish', methods=['POST'])
def publish_article():
    """发布文章"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Unauthorized"}), 401
        token = auth_header.split(' ')[1]
        payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        if payload['permission'] < 4:
            return jsonify({"error": "只有4级及以上用户可以发布文章"}), 403
        data = request.get_json()
        title = data.get('title')
        category = data.get('category')
        content = data.get('content')
        if not title or not category or not content:
            return jsonify({"error": "缺少必要字段: title, category, content"}), 400
        # 生成HTML文件
        html_content = markdown.markdown(
            content,
            extensions=['extra', 'codehilite', 'toc'],
            extension_configs={
                'codehilite': {
                    'css_class': 'codehilite',
                    'linenums': False
                }
            }
        )
        html_content = f"""
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link rel="stylesheet" href="../../style/article.css">
        <title>{title} - 八年级二班</title>
    </head>
    <body>
        <nav class="navbar">
                <h2>南平市建阳第二中学 | 八年级二班</h2>
                <div class="nav-links">
                    <a href="../../main.html" class="nav-home">首页</a>
                    <a href="../../main.html#about">关于</a>
                    <a href="../../CopyRight.html">联系</a>
                </div>
        </nav>
        <div class="article-container">
            <h1 class="article-title">{title}</h1>
            <div class="article-content markdown-body">  <!-- 关键修改：添加markdown-body类 -->
                {html_content}
            </div>
        </div>
        <div class="footer">
            <p>© 2025 八年级二班 - 南平市建阳第二中学</p>
        </div>
    </body>
    </html>
    """
        category_dir = os.path.join(ARTICLE_DIR, category)
        if not os.path.exists(category_dir):
            os.makedirs(category_dir)
        article_path = os.path.join(category_dir, f"{title}.html")
        with open(article_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
@app.route('/api/articles/list', methods=['GET'])
def get_article_list():
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Unauthorized"}), 401
        token = auth_header.split(' ')[1]
        payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])

        articles = []
        for category in os.listdir(ARTICLE_DIR):
            category_dir = os.path.join(ARTICLE_DIR, category)
            if os.path.isdir(category_dir):
                for filename in os.listdir(category_dir):
                    if filename.endswith('.html'):  # 确保是HTML文件
                        title = os.path.splitext(filename)[0]
                        articles.append({
                            'title': title,
                            'category': category,
                            'path': os.path.join(category, filename)
                        })

        return jsonify(articles)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
@app.route('/api/users/delete', methods=['POST', 'OPTIONS'])
def delete_user():
    if request.method == 'OPTIONS':
        return _build_cors_preflight_response()  # 专门处理OPTIONS请求
    try:
        data = request.get_json()
        if 'display_name' not in data:
            return jsonify({"error": "缺少必要字段: display_name"}), 400

        users = load_user_data()

        # 权限验证
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(' ')[1]
        payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])

        # 获取目标用户
        display_name = data['display_name']
        target_user = next((user for user in users.values() if user['display_name'] == display_name), None)
        if not target_user:
            return jsonify({"error": "用户不存在"}), 404

        # 获取当前用户权限
        current_permission = payload['permission']

        # 双重权限验证
        if target_user['permission'] >= 5 and payload['permission'] < 5:
            return jsonify({"error": "禁止操作5级用户"}), 403
        if payload['permission'] <= target_user['permission']:
            return jsonify({"error": "权限不足"}), 403

        # 删除用户数据
        for username, user in users.items():
            if user['display_name'] == display_name:
                del users[username]
                break

        # 保存到 Excel 和 SQLite
        save_user_to_excel(users)
        save_user_to_db(users)

        return jsonify({"status": "success"})
    except Exception as e:
        import logging
        logging.error(f"删除用户时出错: {e}")
        return jsonify({"error": str(e)}), 500
@app.route('/api/articles/<path:article_path>', methods=['GET'])
def get_article(article_path):
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Unauthorized"}), 401
        token = auth_header.split(' ')[1]
        payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])

        article_path = os.path.join(ARTICLE_DIR, article_path)
        if not os.path.exists(article_path):
            return jsonify({"error": "文章不存在"}), 404

        with open(article_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # 将 Markdown 转换为 HTML
        html_content = markdown.markdown(content)

        return html_content
    except Exception as e:
        return jsonify({"error": str(e)}), 500
if __name__ == '__main__':
    print("Registered routes:")
    for rule in app.url_map.iter_rules():
        print(f"{rule.rule} -> {rule.endpoint}")
    # 初始化用户数据
    if not load_user_data():
        logging.error("初始化用户数据失败")
        sys.exit(1)

    # 运行配置
    debug_mode = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(
        host=os.getenv('FLASK_HOST', '0.0.0.0'),
        port=int(os.getenv('FLASK_PORT', 5000)),
        debug=debug_mode,
        use_reloader=False if debug_mode else True
    )