import time, threading, queue, random, hashlib, base64, jwt, os, string, secrets
from collections import defaultdict
from flask import Flask, request, jsonify, make_response, redirect, render_template
from werkzeug.middleware.proxy_fix import ProxyFix
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
SECRET_KEY = os.environ.get('SECRET_KEY', base64.b64encode(os.urandom(32)).decode())
req_count = defaultdict(int)
block_list = defaultdict(float)
q = queue.Queue()
THRESHOLD = 20
TIME_WINDOW = 60
BLOCK_TIME = 1800
DIFFICULTY = 4
INVALID_DOMAIN = "127.0.0.1:9999"
api_keys = {}
def generate_api_key():
 return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
def generate_challenge():
 return base64.b64encode(os.urandom(16)).decode()
def verify_solution(challenge, nonce):
 try:
  nonce = int(nonce)
  hash_val = hashlib.md5((challenge + str(nonce)).encode()).hexdigest()
  return hash_val.startswith('0' * DIFFICULTY)
 except:
  return False
def rate_limit(ip):
 current_time = time.time()
 req_count[ip] += 1
 q.put((ip, current_time))
 if block_list.get(ip, 0) > current_time:
  return True
 if req_count[ip] > THRESHOLD:
  block_list[ip] = current_time + BLOCK_TIME
  return True
 return False
def clean_old_requests():
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
 while True:
  clean_old_requests()
  current_time = time.time()
  for ip in list(block_list.keys()):
   if block_list[ip] < current_time:
    del block_list[ip]
  time.sleep(1)
threading.Thread(target=maintenance, daemon=True).start()
@app.route('/')
def index():
 return render_template('index.html')
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
 if request.method == 'POST':
  api_key = generate_api_key()
  api_keys[api_key] = {'created': time.time()}
  return render_template('dashboard.html', api_key=api_key)
 return render_template('dashboard.html', api_key=None)
@app.route('/docs')
def docs():
 return render_template('docs.html')
@app.route('/api/client_script/<api_key>')
def client_script(api_key):
 if api_key not in api_keys:
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
 if api_key not in api_keys:
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
 if api_key not in api_keys:
  return jsonify({'error': 'Invalid API Key'}), 401
 data = request.json
 challenge = data.get('challenge')
 nonce = data.get('nonce')
 if verify_solution(challenge, nonce):
  token = jwt.encode({'ip': request.remote_addr, 'exp': time.time() + 3600}, SECRET_KEY, algorithm='HS256')
  return jsonify({'token': token}), 200
 else:
  block_list[request.remote_addr] = time.time() + BLOCK_TIME
  return jsonify({'error': 'Invalid solution'}), 403
@app.route('/api/protected', methods=['GET'])
def protected():
 api_key = request.headers.get('X-API-KEY')
 if api_key not in api_keys:
  return jsonify({'error': 'Invalid API Key'}), 401
 auth = request.headers.get('Authorization')
 if auth:
  try:
   token = auth.split()[1]
   payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
   if payload['ip'] == request.remote_addr:
    return jsonify({'message': 'Access granted - Protected content'}), 200
  except:
   pass
 return jsonify({'error': 'Unauthorized'}), 401
if __name__ == '__main__':
 app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), threaded=True)
