import time
import threading
import queue
import hashlib
import base64
import jwt
import os
import string
import secrets
import psycopg2
from urllib.parse import urlparse
from collections import defaultdict
from flask import Flask, request, jsonify, make_response, redirect, render_template
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Load secret key from environment or generate one
SECRET_KEY = os.environ.get('SECRET_KEY', base64.b64encode(os.urandom(32)).decode())

# Rate limiting setup
req_count = defaultdict(int)
block_list = defaultdict(float)
q = queue.Queue()
THRESHOLD = 20
TIME_WINDOW = 60
BLOCK_TIME = 1800
DIFFICULTY = 4
INVALID_DOMAIN = "127.0.0.1:9999"

# --- Database Connection ---
def get_db_connection():
    """Create a connection to the PostgreSQL database."""
    database_url = os.environ.get('DATABASE_URL')
    if not database_url:
        raise Exception("DATABASE_URL environment variable not set")
    
    # Handle Heroku/Render PostgreSQL URL (uses SSL)
    result = urlparse(database_url)
    conn = psycopg2.connect(
        host=result.hostname,
        port=result.port,
        database=result.path[1:],
        user=result.username,
        password=result.password,
        sslmode='require'  # Recommended for security on Render
    )
    return conn


def init_db():
    """Initialize the api_keys table if it doesn't exist."""
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS api_keys (
                        key TEXT PRIMARY KEY,
                        created DOUBLE PRECISION NOT NULL
                    )
                ''')
            conn.commit()
    except Exception as e:
        print(f"Error initializing database: {e}")
        raise


def save_api_key(api_key):
    """Save a new API key to the database."""
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute('INSERT INTO api_keys (key, created) VALUES (%s, %s)', 
                           (api_key, time.time()))
            conn.commit()
    except Exception as e:
        print(f"Error saving API key: {e}")
        raise


def is_valid_api_key(api_key):
    """Check if the given API key exists in the database."""
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT 1 FROM api_keys WHERE key = %s', (api_key,))
                return cur.fetchone() is not None
    except Exception as e:
        print(f"Error validating API key: {e}")
        return False


# --- Utility Functions ---
def generate_api_key():
    """Generate a secure 32-character alphanumeric API key."""
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))


def generate_challenge():
    """Generate a random base64-encoded challenge."""
    return base64.b64encode(os.urandom(16)).decode()


def verify_solution(challenge, nonce):
    """Verify that MD5(challenge + nonce) starts with '0000'."""
    try:
        nonce = int(nonce)
        hash_val = hashlib.md5((challenge + str(nonce)).encode()).hexdigest()
        return hash_val.startswith('0' * DIFFICULTY)
    except:
        return False


def rate_limit(ip):
    """Simple rate limiter using sliding window via queue."""
    current_time = time.time()
    req_count[ip] += 1
    q.put((ip, current_time))

    # Check if IP is blocked
    if block_list.get(ip, 0) > current_time:
        return True

    # Check threshold
    if req_count[ip] > THRESHOLD:
        block_list[ip] = current_time + BLOCK_TIME
        return True

    return False


def clean_old_requests():
    """Remove outdated requests from the queue."""
    while True:
        try:
            ip, timestamp = q.get_nowait()
            if time.time() - timestamp > TIME_WINDOW:
                req_count[ip] = max(0, req_count[ip] - 1)
                if req_count[ip] == 0:
                    del req_count[ip]
            else:
                q.put((ip, timestamp))
        except queue.Empty:
            break
        time.sleep(0.1)


def maintenance():
    """Background thread to clean old rate-limit data and unblock IPs."""
    while True:
        clean_old_requests()
        current_time = time.time()
        for ip in list(block_list.keys()):
            if block_list[ip] < current_time:
                del block_list[ip]
        time.sleep(1)


# Start maintenance thread
threading.Thread(target=maintenance, daemon=True).start()


# --- Routes ---
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if request.method == 'POST':
        api_key = generate_api_key()
        save_api_key(api_key)
        return render_template('dashboard.html', api_key=api_key)
    return render_template('dashboard.html', api_key=None)


@app.route('/docs')
def docs():
    return render_template('docs.html')


@app.route('/api/client_script/<api_key>')
def client_script(api_key):
    if not is_valid_api_key(api_key):
        return jsonify({'error': 'Invalid API Key'}), 401

    script = f"""
    <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js"></script>
    <script>
      function initDDoSProtection() {{
        var apiKey = '{api_key}';
        var xhr = new XMLHttpRequest();
        xhr.open('GET', '/api/challenge', true);
        xhr.setRequestHeader('X-API-KEY', apiKey);
        xhr.onreadystatechange = function() {{
          if (xhr.readyState === 4 && xhr.status === 200) {{
            var parser = new DOMParser();
            var doc = parser.parseFromString(xhr.responseText, 'text/html');
            var script = doc.querySelector('script:not([src])').innerText;
            eval(script);
          }}
        }};
        xhr.send();
        var footer = document.createElement('footer');
        footer.style = 'text-align: center; padding: 10px; background: #f8f8f8;';
        footer.innerHTML = 'Protected And Supported By <a href="https://yourdomain.com">SolDev Security</a>';
        document.body.appendChild(footer);
      }}
      window.onload = initDDoSProtection;
    </script>
    """
    return make_response(script, 200, {'Content-Type': 'text/javascript'})


@app.route('/api/challenge', methods=['GET'])
def gen_challenge():
    if rate_limit(request.remote_addr):
        return redirect(f"http://{INVALID_DOMAIN}"), 301

    api_key = request.headers.get('X-API-KEY')
    if not is_valid_api_key(api_key):
        return jsonify({'error': 'Invalid API Key'}), 401

    challenge = generate_challenge()
    html = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Verifying...</title></head>
    <body>
    <h1>Verifying...</h1>
    <script>
    function solveChallenge(challenge) {{
        var nonce = 0;
        var prefix = '{'0' * DIFFICULTY}';
        while (true) {{
            var hash = CryptoJS.MD5(challenge + nonce).toString();
            if (hash.substring(0, {DIFFICULTY}) === prefix) {{
                fetch('/api/verify', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json', 'X-API-KEY': '{api_key}' }},
                    body: JSON.stringify({{ challenge: challenge, nonce: nonce }})
                }}).then(res => res.json()).then(data => {{
                    if (data.token) localStorage.setItem('ddos_token', data.token);
                }});
                break;
            }}
            nonce++;
        }}
    }}
    solveChallenge('{challenge}');
    </script>
    </body>
    </html>
    """
    resp = make_response(html)
    resp.headers['Content-Type'] = 'text/html'
    return resp


@app.route('/api/verify', methods=['POST'])
def verify():
    api_key = request.headers.get('X-API-KEY')
    if not is_valid_api_key(api_key):
        return jsonify({'error': 'Invalid API Key'}), 401

    data = request.json
    challenge = data.get('challenge')
    nonce = data.get('nonce')

    if verify_solution(challenge, nonce):
        token = jwt.encode(
            {'ip': request.remote_addr, 'exp': time.time() + 3600},
            SECRET_KEY,
            algorithm='HS256'
        )
        return jsonify({'token': token}), 200
    else:
        block_list[request.remote_addr] = time.time() + BLOCK_TIME
        return jsonify({'error': 'Invalid solution'}), 403


@app.route('/api/protected', methods=['GET'])
def protected():
    api_key = request.headers.get('X-API-KEY')
    if not is_valid_api_key(api_key):
        return jsonify({'error': 'Invalid API Key'}), 401

    auth = request.headers.get('Authorization')
    if auth:
        try:
            token = auth.split()[1]
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            if payload['ip'] == request.remote_addr:
                return jsonify({'message': 'Access granted - Protected content'}), 200
        except Exception as e:
            pass

    return jsonify({'error': 'Unauthorized'}), 401


# --- App Startup ---
if __name__ == '__main__':
    # Initialize the database on startup
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, threaded=True)
