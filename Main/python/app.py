# app.py
from flask import Flask, request, jsonify
import jwt
import datetime
import pandas as pd
from flask_cors import CORS
import os
import sys
import logging
import json
import requests
# 初始化Flask应用

app = Flask(__name__)
app.secret_key = 'your_secure_key_here'
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
REQUIRED_COLUMNS = ['Name', 'display_name', 'password','permission', 'banned', 'last_login','register_time'  # 新增字段
]


def load_user_data():
    """从Excel加载并验证用户数据"""
    try:
        # 读取Excel文件
        df = pd.read_excel(
            EXCEL_PATH,
            sheet_name='Sheet1',
            usecols=REQUIRED_COLUMNS,
            dtype={
                'Name': 'string',
                'display_name': 'string',
                'password': 'string',
                'permission': 'int32',
                'banned': 'object',  # 明确指定为布尔类型
                'last_login': 'string',
                'register_time': 'string',
        # 强制转为字符串
            },
            engine='openpyxl'
        )

        # 处理空值
        df['banned'] = df['banned'].astype(bool)
        df['banned'] = df['banned'].fillna(False)  # 空值设为False
        df['banned'] = df['banned'].apply(
            lambda x: str(x).lower() in ['true', '1', '是', 'yes']
        )

        # 数据清洗
        df = df.dropna(subset=['Name', 'password'])
        df['Name'] = df['Name'].str.strip()
        df['password'] = df['password'].str.strip()

        # 验证必要列存在
        if not all(col in df.columns for col in REQUIRED_COLUMNS):
            missing = [col for col in REQUIRED_COLUMNS if col not in df.columns]
            raise ValueError(f"Excel文件中缺少必要列: {missing}")

        # 转换数据结构
        users = df.set_index('Name').to_dict('index')

        logging.info(f"成功加载 {len(users)} 条用户记录")
        return users

    except pd.errors.EmptyDataError:
        logging.error("Excel文件为空或格式不正确")
        return {}
    except Exception as e:
        logging.error(f"加载用户数据时发生错误: {str(e)}")
        return {}

@app.route('/api/login', methods=['POST'])
def handle_login():
    """处理用户登录请求"""
    try:
        # 动态加载最新数据
        users = load_user_data()
        if not users:
            return jsonify({"status": "error", "message": "用户系统暂时不可用"}), 503

        # 获取请求数据
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "无效的请求格式"}), 400

        username = str(data.get('username', '')).strip()
        password = str(data.get('password', '')).strip()

        # 参数验证
        if not username:
            return jsonify({"status": "error", "message": "用户名不能为空"}), 400
        if not password:
            return jsonify({"status": "error", "message": "密码不能为空"}), 400

        # 用户验证
        user = users.get(username)
        if not user:
            logging.warning(f"登录尝试 - 不存在的用户: {username}")
            return jsonify({"status": "error", "message": "用户不存在"}), 404

        if password != user['password']:
            logging.warning(f"登录尝试 - 密码错误: {username}")
            return jsonify({"status": "error", "message": "密码错误"}), 401

        # 生成JWT令牌
        token_payload = {
            'username': username,
            'permission': int(user['permission']),
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)
        }
        token = jwt.encode(token_payload, app.secret_key, algorithm='HS256')

        logging.info(f"用户 {username} 登录成功")
        return jsonify({
            "status": "success",
            "username": username,
            "display_name": user.get('display_name', username),
            "permission": user['permission'],
            "token": token
        })

    except jwt.PyJWTError as e:
        logging.error(f"JWT生成失败: {str(e)}")
        return jsonify({"status": "error", "message": "令牌生成失败"}), 500
    except Exception as e:
        logging.error(f"处理登录请求时发生意外错误: {str(e)}")
        return jsonify({"status": "error", "message": "服务器内部错误"}), 500

@app.route('/api/validate', methods=['GET'])
def validate_jwt_token():
    """验证JWT令牌有效性"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"valid": False, "message": "授权头格式错误"}), 401

        token = auth_header.split(' ')[1]
        payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        return jsonify({"valid": True, **payload})

    except jwt.ExpiredSignatureError:
        return jsonify({"valid": False, "message": "令牌已过期"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"valid": False, "message": "无效令牌"}), 401
    except Exception as e:
        logging.error(f"令牌验证失败: {str(e)}")
        return jsonify({"valid": False, "message": "令牌处理错误"}), 500

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'  # 允许所有域名（开发环境）
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'
    return response

@app.route('/api/users', methods=['GET'])
def get_all_users():
    """获取所有用户信息"""
    try:
        users = load_user_data()
        return jsonify([{
            "Name": k,
            "display_name": v.get('display_name', ''),
            "permission": v.get('permission', 1),
            "banned": v.get('banned', False),
            "last_login": v.get('last_login', '')
        } for k, v in users.items()])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/users/update', methods=['POST'])
def update_user():
    """更新用户信息"""
    try:
        data = request.get_json()
        if 'username' not in data or 'field' not in data or 'value' not in data:
            return jsonify({"error": "缺少必要字段: username, field, value"}), 400

            # 检查字段是否允许修改
        allowed_fields = ['permission', 'banned', 'display_name']
        if data['field'] not in allowed_fields:
            return jsonify({"error": f"禁止修改字段: {data['field']}"}), 403
        # 新增字段验证
        required_fields = ['username', 'field', 'value']
        if not all(field in data for field in required_fields):
            return jsonify({"error": "缺少必要字段"}), 400

        # 允许修改的字段白名单

        users = load_user_data()

        # 权限验证
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(' ')[1]
        payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])

        # 获取目标用户
        username = data['username']  # 必须先获取username
        target_user = users.get(username)
        if not target_user:
            return jsonify({"error": "用户不存在"}), 404

            # 获取当前用户权限
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(' ')[1]
        payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        current_permission = payload['permission']

        # 双重权限验证
        if target_user['permission'] >= 5 and payload['permission'] < 5:
            return jsonify({"error": "禁止操作5级用户"}), 403
        if payload['permission'] <= target_user['permission']:
            return jsonify({"error": "权限不足"}), 403
        # 更新用户数据
        username = data['username']
        if username not in users:
            return jsonify({"error": "用户不存在"}), 404

        users[username][data['field']] = data['value']

        # 保存到Excel
        df = pd.DataFrame.from_dict(users, orient='index')
        with pd.ExcelWriter(EXCEL_PATH, engine='openpyxl', mode='w') as writer:
            df.to_excel(writer, index_label='Name')

        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/access-logs', methods=['GET'])
def get_access_logs():
    """获取访问日志"""
    try:
        log_path = os.path.join(os.path.dirname(__file__), 'access.log')
        if not os.path.exists(log_path):
            return jsonify([])

        with open(log_path, 'r') as f:
            logs = [json.loads(line) for line in f.readlines()]

        return jsonify(logs[-100:])  # 返回最近100条日志

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/users/register', methods=['POST'])
def register_user():
    """注册新用户"""
    try:
        data = request.get_json()
        users = load_user_data()

        # 权限验证（移动到最前面）
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

        # 添加新用户（删除之前的错误添加操作）
        users[data['username']] = {
            'display_name': data['display_name'],
            'password': data['password'],
            'permission': int(data['permission']),
            'banned': False,
            'last_login': datetime.datetime.now().isoformat(),
            'register_time': datetime.datetime.now().isoformat()
        }

        # 保存到Excel
        df = pd.DataFrame.from_dict(users, orient='index')
        df.to_excel(EXCEL_PATH, index_label='Name')

        return jsonify({"status": "success"})

    except Exception as e:
        return jsonify({"error": str(e)}), 500
@app.before_request
def log_access():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    real_ip = client_ip.split(',')[0].strip() if client_ip else ''

    log_entry = json.dumps({
        'timestamp': datetime.datetime.now().isoformat(),
        'ip': client_ip,
        'location': get_ip_location(real_ip),  # 正确调用
        'method': request.method,
        'path': request.path
    })

    log_path = os.path.join(os.path.dirname(__file__), 'access.log')
    with open(log_path, 'a') as f:
        f.write(log_entry + '\n')
def get_ip_location(ip):
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}?fields=country,city', timeout=2)
        data = response.json()
        return f"{data.get('country', '未知')}/{data.get('city', '未知')}"
    except Exception as e:
        logging.error(f"IP定位失败: {str(e)}")
        return "未知地区"

@app.errorhandler(404)
def handle_404(e):
    return jsonify({"error": "Endpoint not found"}), 404
@app.errorhandler(Exception)
def handle_exception(e):
    # 确保返回 JSON 格式
    return jsonify({
        "error": str(e),
        "type": e.__class__.__name__
    }), 500

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'
    return response
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