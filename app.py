from flask import Flask, request, jsonify, render_template_string, make_response
import hashlib
import hmac
import json
import time
import random
import base64
from functools import wraps
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = 'orange_army_never_dies_2016'

sessions = {}
war_room_access = {}
rate_limits = {}

def check_rate_limit(ip):
    current_time = time.time()
    if ip not in rate_limits:
        rate_limits[ip] = []
    rate_limits[ip] = [t for t in rate_limits[ip] if current_time - t < 60]
    if len(rate_limits[ip]) >= 10:
        return False
    rate_limits[ip].append(current_time)
    return True

@app.route('/')
def index():
    return render_template_string('''<!DOCTYPE html>
<html>
<head>
    <title>SRH War Room</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Arial', sans-serif;
            background: linear-gradient(135deg, #ff6600 0%, #000000 100%);
            color: white;
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 900px;
            margin: 50px auto;
            background: rgba(0, 0, 0, 0.9);
            border: 3px solid #ff6600;
            border-radius: 15px;
            padding: 40px;
            box-shadow: 0 0 50px rgba(255, 102, 0, 0.5);
        }
        h1 {
            text-align: center;
            color: #ff6600;
            font-size: 2.5em;
            text-shadow: 0 0 20px #ff6600;
            margin-bottom: 10px;
        }
        .subtitle {
            text-align: center;
            color: #ffaa00;
            margin-bottom: 30px;
        }
        .intel-box {
            background: rgba(255, 102, 0, 0.1);
            border: 2px solid #ff6600;
            padding: 20px;
            margin: 20px 0;
            border-radius: 10px;
        }
        .intel-box h3 {
            color: #ff6600;
            margin-bottom: 15px;
        }
        .clue {
            background: rgba(0, 0, 0, 0.5);
            padding: 15px;
            margin: 10px 0;
            border-left: 4px solid #ffaa00;
            font-size: 0.95em;
        }
        .warning {
            background: rgba(255, 0, 0, 0.2);
            border: 2px solid #ff0000;
            padding: 15px;
            margin: 20px 0;
            border-radius: 8px;
        }
        button {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #ff6600, #ffaa00);
            border: none;
            border-radius: 8px;
            color: white;
            font-weight: bold;
            font-size: 16px;
            cursor: pointer;
            margin-top: 20px;
        }
        button:hover {
            transform: scale(1.02);
            box-shadow: 0 5px 20px rgba(255, 102, 0, 0.6);
        }
        code {
            background: rgba(255, 255, 255, 0.1);
            padding: 2px 8px;
            border-radius: 4px;
            color: #ffaa00;
        }
    </style>
</head>
<body>
    <!-- Hint: Not everything authenticates at the gate — try knocking on the real door behind it. /api/auth might listen better-->
    <div class="container">
        <h1>🧡 SRH WAR ROOM</h1>
        <div class="subtitle">Operation Orange Army - Access Control System</div>
        
        <div class="intel-box">
            <h3>📡 System Status</h3>
            <div class="clue">
                ✅ Multi-layer authentication active<br>
                ✅ WAF protection enabled<br>
                ✅ Custom request validation implemented<br>
                ⚠️ Standard HTTP methods restricted
            </div>
        </div>


        <div class="warning">
            <strong>⚠️ SECURITY NOTICE</strong><br>
            This system only responds to authenticated requests with proper headers.<br>
            Standard browser requests will be rejected.<br>
            
        </div>

        <button onclick="testAccess()">TEST ACCESS</button>
        
        <div id="response" style="margin-top: 20px; padding: 15px; background: rgba(255, 102, 0, 0.1); border-radius: 8px; display: none;">
            <pre id="responseText" style="color: #ffaa00; white-space: pre-wrap;"></pre>
        </div>

        
    </div>

    <script>
        async function testAccess() {
            const responseDiv = document.getElementById('response');
            const responseText = document.getElementById('responseText');
            
            responseDiv.style.display = 'block';
            responseText.textContent = 'Sending request...';
            
            try {
                const response = await fetch('/api/auth', {
                    method: 'GET'
                });
                
                const data = await response.json();
                responseText.textContent = JSON.stringify(data, null, 2);
            } catch (error) {
                responseText.textContent = 'Error: ' + error.message;
            }
        }
    </script>
</body>
</html>''')

@app.route('/api/auth', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'TRACE'])
def api_auth():
    ip = request.remote_addr
    if not check_rate_limit(ip):
        return jsonify({
            'error': 'Rate limit exceeded',
            'message': 'Too many requests. Wait 60 seconds.'
        }), 429
    time.sleep(random.uniform(0.05, 0.15))
    if request.method in ['PUT', 'DELETE', 'PATCH']:
        return jsonify({
            'error': 'Method not allowed',
            'fake_flag': 'flag{wr0ng_m3th0d_keep_trying}',
            'hint': 'This method is close, but not quite right...'
        }), 405
    year_header = request.headers.get('X-SRH-Year')
    if not year_header or year_header != '2012':
        response = make_response(jsonify({
            'error': 'Layer 1 failed',
            'message': 'Establishment year verification required',
            'hint': 'Send X-SRH-Year header with the franchise founding year'
        }), 401)
        response.headers['X-SRH-Hint'] = 'When was SRH established?'
        return response
    session_token = secrets.token_hex(16)
    sessions[session_token] = {'layer': 1, 'timestamp': time.time()}
    response = make_response(jsonify({
        'success': True,
        'message': 'Layer 1 passed! Establishment verified.',
        'session_token': session_token,
        'next_layer': 'Leadership validation required',
        'hint': 'Use this X-Session-Token and send X-Beauty with X-SRH-Captain header to /api/validate '
    }))
    response.headers['X-Next-Endpoint'] = '/api/validate'
    response.headers['X-SRH-Hint'] = 'Think of SRH Beauty and The captain who brought glory'
    return response

@app.route('/api/validate', methods=['POST'])
def api_validate():
    ip = request.remote_addr
    if not check_rate_limit(ip):
        return jsonify({'error': 'Rate limit exceeded'}), 429
    token = request.headers.get('X-Session-Token')
    if not token or token not in sessions:
        return jsonify({
            'error': 'Invalid or missing session token',
            'hint': 'Complete Layer 1 first at /api/auth'
        }), 401
    beauty = request.headers.get('X-Beauty')
    if not beauty or beauty.lower() != 'kavya':
        return jsonify({
            'error': 'Layer 2 failed',
            'message': 'Special header required',
            'hint': 'Send X-Beauty: Beauty of SRH as head',
            'fake_flag': 'flag{st4nd4rd_m3th0ds_do_work_h3r3}'
        }), 405
    captain = request.headers.get('X-SRH-Captain')
    if not captain or captain.lower() != 'warner':
        return jsonify({
            'error': 'Layer 2 failed',
            'message': 'Captain verification required',
            'hint': 'Who led SRH to their first title? First name only.'
        }), 401
    sessions[token]['layer'] = 2
    response = make_response(jsonify({
        'success': True,
        'message': 'Layer 2 passed! Leadership verified.',
        'next_layer': 'Icon authentication required',
        'hint': 'Use the token to send X-Beauty along with X-SRH-Jersey and the token to /api/icon',
        'fake_flag': 'flag{w4rn3r_is_c0rr3ct_but_n0t_th3_fl4g}'
    }))
    response.headers['X-Next-Endpoint'] = '/api/icon'
    response.headers['X-SRH-Hint'] = 'Jersey number of buttabomma dancer'
    return response

@app.route('/api/icon', methods=['POST'])
def api_icon():
    ip = request.remote_addr
    if not check_rate_limit(ip):
        return jsonify({'error': 'Rate limit exceeded'}), 429
    token = request.headers.get('X-Session-Token')
    if not token or token not in sessions or sessions[token]['layer'] < 2:
        return jsonify({
            'error': 'Access denied',
            'hint': 'Complete previous layers first'
        }), 401
    beauty = request.headers.get('X-Beauty')
    if not beauty or beauty.lower() != 'kavya':
        return jsonify({
            'error': 'Layer 3 failed',
            'message': 'Special header required',
            'hint': 'Send X-Beauty: KAVYA as header',
            'fake_flag': 'flag{cl0s3_but_wr0ng_j3rs3y_numb3r}'
        }), 405
    jersey = request.headers.get('X-SRH-Jersey')
    if not jersey or jersey != '31':
        return jsonify({
            'error': 'Layer 3 failed',
            'message': 'Jersey number verification required',
            'hint': 'Warner\'s iconic jersey number',
            'fake_flag': 'flag{cl0s3_but_wr0ng_j3rs3y_numb3r}'
        }), 401
    sessions[token]['layer'] = 3
    response = make_response(jsonify({
        'success': True,
        'message': 'Layer 3 passed! Icon verified.',
        'next_layer': 'Victory protocol required',
        'hint': 'Use Token to Send X-Beauty along with X-SRH-Victory to /api/protocol',
        'fake_flag': 'flag{31_is_c0rr3ct_but_st1ll_n0t_th3_r34l_fl4g}'
    }))
    response.headers['X-Next-Endpoint'] = '/api/protocol'
    response.headers['X-SRH-Hint'] = 'How many runs did SRH win by in 2016?'
    return response

@app.route('/api/protocol', methods=['POST'])
def api_protocol():
    ip = request.remote_addr
    if not check_rate_limit(ip):
        return jsonify({'error': 'Rate limit exceeded'}), 429
    token = request.headers.get('X-Session-Token')
    if not token or token not in sessions or sessions[token]['layer'] < 3:
        return jsonify({
            'error': 'Access denied',
            'hint': 'Complete previous layers first'
        }), 401
    beauty = request.headers.get('X-Beauty')
    if not beauty or beauty.lower() != 'kavya':
        return jsonify({
            'error': 'Layer 4 failed',
            'message': 'Special header required',
            'hint': 'Send X-Beauty: KAVYA as header',
            'fake_flag': 'flag{v1ct0ry_m3th0d_wr0ng_try_4g41n}'
        }), 405
    victory = request.headers.get('X-SRH-Victory')
    if not victory or victory != '8':
        return jsonify({
            'error': 'Layer 4 failed',
            'message': 'Victory method verification required',
            'hint': 'How many runs did SRH win by in IPL 2016?',
            'fake_flag': 'flag{v1ct0ry_m3th0d_wr0ng_try_4g41n}'
        }), 401
    sessions[token]['layer'] = 4
    access_code = base64.b64encode(f"SRH2016{token}".encode()).decode()
    response = make_response(jsonify({
        'success': True,
        'message': 'Layer 4 passed! All layers completed!',
        'access_code': access_code,
        'next_step': 'Use this access code in Cookie header as war_room_access',
        'endpoint': '/warroom/dashboard',
        'hint': 'Set Cookie: war_room_access=<access_code> and visit /warroom/dashboard',
        'fake_flag': 'flag{4ll_l4y3rs_p4ss3d_but_n0t_d0n3_y3t}'
    }))
    response.headers['X-Final-Endpoint'] = '/warroom/dashboard'
    response.headers['X-SRH-Hint'] = 'Use the access_code as a cookie value'
    return response

@app.route('/warroom/dashboard')
def warroom_dashboard():
    access_code = request.cookies.get('war_room_access')
    if not access_code:
        return jsonify({
            'error': 'Access denied',
            'message': 'war_room_access cookie required',
            'hint': 'Complete all authentication layers first'
        }), 401
    try:
        decoded = base64.b64decode(access_code).decode()
        if not decoded.startswith('SRH2016'):
            raise ValueError("Invalid code")
        token = decoded.replace('SRH2016', '')
        if token not in sessions or sessions[token]['layer'] < 4:
            raise ValueError("Invalid session")
    except:
        return jsonify({
            'error': 'Invalid access code',
            'fake_flag': 'flag{1nv4l1d_c00k13_try_4g41n}'
        }), 401
    secret_param = request.args.get('query')
    if not secret_param:
        return jsonify({
            'success': True,
            'message': 'Welcome to War Room Dashboard',
            'status': 'Authenticated',
            'fake_flag': 'flag{y0u_r34ch3d_d4shb04rd_but_n0_fl4g_h3r3}',
            'hint': 'The dashboard is just the entry point...',
            'hidden_hint': 'Try adding query. Maybe something orange? Dont forget the Cookie',
            'endpoints': {
                '/warroom/data': 'Match data (requires authentication)',
                '/warroom/predictions': 'Prediction algorithms (requires special access)',
                '/warroom/admin': 'Admin panel (disabled)',
                '/warroom/secret': 'Unknown endpoint'
            }
        })
    if secret_param != 'orange':
        return jsonify({
            'error': 'Invalid secret parameter',
            'hint': 'The color of glory...',
            'fake_flag': 'flag{wr0ng_s3cr3t_p4r4m3t3r}'
        }), 401
    response = make_response(jsonify({
        'success': True,
        'message': 'Secret parameter accepted!',
        'final_hint': 'The real treasure is in /warroom/vault',
        'requirement': 'But you need a special POST parameter: prediction_key',
        'clue': 'The prediction_key is the MD5 hash of "SRH2016Warner31"',
        'fake_flag': 'flag{s0_cl0s3_but_n0t_th3r3_y3t}'
    }))
    response.headers['X-Vault-Hint'] = 'dont forget to include cookie, content-type, content-length'
    return response

@app.route('/warroom/vault', methods=['GET', 'POST'])
def warroom_vault():
    access_code = request.cookies.get('war_room_access')
    if not access_code:
        return jsonify({'error': 'Access denied'}), 401
    if request.method != 'POST':
        return jsonify({
            'error': 'Method not allowed',
            'hint': 'POST request required with prediction_key parameter'
        }), 405
    if request.is_json:
        prediction_key = request.json.get('prediction_key')
    else:
        prediction_key = request.form.get('prediction_key')
    if not prediction_key:
        return jsonify({
            'error': 'prediction_key required',
            'hint': 'POST parameter: prediction_key = MD5("SRH2016Warner31")',
            'fake_flag': 'flag{n0_pr3d1ct10n_k3y_pr0v1d3d}'
        }), 400
    correct_key = '9ef53a8ed91c3c0f6c9aa58206e9b3bb'
    if prediction_key != correct_key:
        return jsonify({
            'error': 'Invalid prediction key',
            'hint': 'MD5 hash of "SRH2016Warner31"',
            'your_key': prediction_key,
            'fake_flag': 'flag{wr0ng_h4sh_try_c4lcul4t1ng_MD5}'
        }), 401
    try:
        with open('flag.txt', 'r') as f:
            flag = f.read().strip()
        return jsonify({
            'success': True,
            'message': '🎉 CONGRATULATIONS! War Room Access Granted!',
            'flag': flag,
            'achievement': 'You have successfully penetrated all layers of SRH War Room security!',
            'layers_completed': [
                'Layer 1: Establishment Year (2012)',
                'Layer 2: Captain Validation (Warner) + X-Beauty: KAVYA header',
                'Layer 3: Jersey Number (31)',
                'Layer 4: Victory Method (8 runs)',
                'Layer 5: Cookie Authentication + Secret Parameter (query=orange) + MD5 Hash'
            ]
        })
    except FileNotFoundError:
        return jsonify({
            'success': True,
            'message': 'FLAG CAPTURED (flag.txt not found in demo)',
            'flag': 'flag{0r4ng3_4rmy_m4st3r_burp_su1t3_ch4mp10n_SRH_2016}',
            'note': 'Create flag.txt file for production'
        })

@app.route('/warroom/data')
def warroom_data():
    return jsonify({
        'error': 'Access denied',
        'fake_flag': 'flag{wr0ng_3ndp01nt_n0_d4t4_h3r3}'
    }), 403

@app.route('/warroom/predictions')
def warroom_predictions():
    return jsonify({
        'error': 'Special access required',
        'fake_flag': 'flag{pr3d1ct10ns_4r3_n0t_h3r3}'
    }), 403

@app.route('/warroom/admin')
def warroom_admin():
    return jsonify({
        'error': 'Admin panel disabled',
        'fake_flag': 'flag{4dm1n_p4n3l_is_4_tr4p}'
    }), 403

@app.route('/warroom/secret')
def warroom_secret():
    return jsonify({
        'message': 'You found a secret endpoint!',
        'fake_flag': 'flag{s3cr3t_3ndp01nt_but_n0_fl4g}',
        'hint': 'The real secret is in the vault...'
    })

@app.route('/robots.txt')
def robots():
    return '''User-agent: *
Disallow: /warroom/
Disallow: /api/
Disallow: /admin/

# flag{r0b0ts_txt_f4k3_fl4g_lol}
# Hint: The war room endpoints are protected
'''

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)