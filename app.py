"""
app.py  —  APT Detection System Backend
Flask + Flask-SocketIO
Routes: auth, dashboard API, alerts API, real-time capture
"""

import os, sys
sys.path.insert(0, os.path.dirname(__file__))

from flask import (
    Flask, render_template, request, jsonify,
    session, redirect, url_for
)
from flask_socketio import SocketIO, emit
from functools import wraps
from datetime import datetime

from database.db   import (
    init_db, verify_admin, insert_log, insert_alert,
    get_recent_logs, get_stats, get_threat_distribution,
    get_alerts, resolve_alert, save_model_metrics, get_latest_metrics
)
from ml.model        import predict, train_model, get_feature_importances
from ml.capture      import LiveCapture
from ml.email_alert  import (
    save_config, load_config, delete_config,
    send_alert_async, send_test_email
)

# ── App setup ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = 'apt-shield-secret-key-2024'
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='eventlet')

# ── Globals ───────────────────────────────────────────────────────────────────
capture = None


# ── Auth decorator ────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'admin' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated


# ── Flow callback (called by LiveCapture) ─────────────────────────────────────
def on_flow_ready(features: dict):
    """Called for every completed network flow. Predict and store."""
    try:
        result = predict(features)

        row = {**features, **result}
        row.setdefault('src_ip',   '0.0.0.0')
        row.setdefault('dst_ip',   '0.0.0.0')
        row.setdefault('src_port', 0)
        row.setdefault('dst_port', 0)
        row.setdefault('protocol', 'TCP')

        log_id = insert_log(row)

        if result['is_threat']:
            insert_alert(
                log_id       = log_id,
                threat_type  = result['predicted_class'],
                src_ip       = row['src_ip'],
                predicted_label = result['predicted_label'],
                mitre_id     = result['mitre_technique'] or '',
                description  = f"{result['predicted_class']} detected from {row['src_ip']} "
                               f"with {round(result['confidence']*100)}% confidence"
            )
            # Send email alert in background (non-blocking)
            send_alert_async({**row, **result})

        # Push to connected dashboards via WebSocket
        socketio.emit('new_flow', {
            'timestamp':       datetime.now().strftime('%H:%M:%S'),
            'src_ip':          row['src_ip'],
            'dst_ip':          row['dst_ip'],
            'protocol':        row['protocol'],
            'predicted_class': result['predicted_class'],
            'predicted_label': result['predicted_label'],
            'confidence':      round(result['confidence'] * 100, 1),
            'is_threat':       result['is_threat'],
            'mitre':           result['mitre_technique'],
            'byte_count':      row.get('byte_count', 0),
        })

    except Exception as e:
        print(f"[Flow Error] {e}")


# ══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════════════════════════

# ── Pages ─────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login')
def login_page():
    if 'admin' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'admin' not in session:
        return redirect(url_for('index'))
    return render_template('dashboard.html', admin=session['admin'])


# ── Auth API ──────────────────────────────────────────────────────────────────
@app.route('/api/login', methods=['POST'])
def api_login():
    data     = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'success': False, 'message': 'Fields required'}), 400

    if verify_admin(username, password):
        session['admin'] = username
        return jsonify({'success': True, 'redirect': '/dashboard'})
    return jsonify({'success': False, 'message': 'Invalid credentials'}), 401


@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.pop('admin', None)
    return jsonify({'success': True})


# ── Dashboard Stats ───────────────────────────────────────────────────────────
@app.route('/api/stats')
@login_required
def api_stats():
    return jsonify(get_stats())


@app.route('/api/logs')
@login_required
def api_logs():
    limit = int(request.args.get('limit', 50))
    return jsonify(get_recent_logs(limit))


@app.route('/api/distribution')
@login_required
def api_distribution():
    return jsonify(get_threat_distribution())


@app.route('/api/alerts')
@login_required
def api_alerts():
    return jsonify(get_alerts())


@app.route('/api/alerts/<int:alert_id>/resolve', methods=['POST'])
@login_required
def api_resolve(alert_id):
    resolve_alert(alert_id, session['admin'])
    return jsonify({'success': True})


# ── ML ────────────────────────────────────────────────────────────────────────
@app.route('/api/predict', methods=['POST'])
@login_required
def api_predict():
    """Manual single-flow prediction from dashboard form."""
    features = request.get_json()
    result   = predict(features)

    row = {**features, **result}
    row.setdefault('src_ip', request.remote_addr)
    row.setdefault('dst_ip', '0.0.0.0')
    row.setdefault('src_port', 0)
    row.setdefault('dst_port', 0)
    row.setdefault('protocol', 'MANUAL')
    insert_log(row)

    if result['is_threat']:
        log_id = get_recent_logs(1)[0]['id']
        insert_alert(
            log_id=log_id, threat_type=result['predicted_class'],
            src_ip=row['src_ip'], predicted_label=result['predicted_label'],
            mitre_id=result['mitre_technique'] or '',
            description=f"Manual analysis: {result['predicted_class']} "
                        f"({round(result['confidence']*100)}% confidence)"
        )

    return jsonify(result)


@app.route('/api/model/retrain', methods=['POST'])
@login_required
def api_retrain():
    metrics = train_model(save=True)
    save_model_metrics({
        'accuracy':    metrics['accuracy'],
        'precision':   metrics['precision'],
        'recall':      metrics['recall'],
        'f1_score':    metrics['f1_score'],
        'n_estimators': 100,
        'n_samples':   metrics['n_samples'],
        'model_file':  'ml/rf_apt_model.pkl'
    })
    return jsonify({
        'success': True,
        'accuracy': metrics['accuracy'],
        'f1_score': metrics['f1_score']
    })


@app.route('/api/model/metrics')
@login_required
def api_model_metrics():
    metrics = get_latest_metrics()
    importances = get_feature_importances()
    return jsonify({'metrics': metrics, 'importances': importances})


# ── Capture control ───────────────────────────────────────────────────────────
@app.route('/api/capture/start', methods=['POST'])
@login_required
def api_capture_start():
    global capture
    if capture and capture.running:
        return jsonify({'status': 'already_running'})
    capture = LiveCapture(on_flow_ready)
    capture.start()
    return jsonify({'status': 'started'})


@app.route('/api/capture/stop', methods=['POST'])
@login_required
def api_capture_stop():
    global capture
    if capture:
        capture.stop()
    return jsonify({'status': 'stopped'})


@app.route('/api/capture/status')
@login_required
def api_capture_status():
    running = capture.running if capture else False
    return jsonify({'running': running})


# ── Email Alert Config ────────────────────────────────────────────────────────
@app.route('/api/email/config', methods=['GET'])
@login_required
def api_email_get():
    config = load_config()
    if config:
        # Mask the app password before sending to frontend
        safe = {**config, 'app_password': '••••••••••••••••'}
        return jsonify({'configured': True, 'config': safe})
    return jsonify({'configured': False})


@app.route('/api/email/config', methods=['POST'])
@login_required
def api_email_save():
    data = request.get_json()
    sender     = data.get('sender_email', '').strip()
    password   = data.get('app_password', '').strip()
    recipients = [r.strip() for r in data.get('recipient_emails', '').split(',') if r.strip()]
    enabled    = data.get('enabled', True)

    if not sender or not password or not recipients:
        return jsonify({'success': False, 'message': 'All fields are required'}), 400

    save_config(sender, password, recipients, enabled)
    return jsonify({'success': True, 'message': 'Email config saved!'})


@app.route('/api/email/config', methods=['DELETE'])
@login_required
def api_email_delete():
    delete_config()
    return jsonify({'success': True, 'message': 'Email config removed'})


@app.route('/api/email/test', methods=['POST'])
@login_required
def api_email_test():
    result = send_test_email()
    return jsonify(result)


# ── SocketIO ──────────────────────────────────────────────────────────────────
@socketio.on('connect')
def on_connect():
    if 'admin' not in session:
        return False   # reject unauthenticated WS
    emit('connected', {'msg': 'WebSocket authenticated'})


# ── Boot ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    init_db()
    # Train model if not exists
    from ml.model import MODEL_PATH
    if not os.path.exists(MODEL_PATH):
        metrics = train_model()
        save_model_metrics({
            'accuracy': metrics['accuracy'], 'precision': metrics['precision'],
            'recall':   metrics['recall'],   'f1_score':  metrics['f1_score'],
            'n_estimators': 100, 'n_samples': metrics['n_samples'],
            'model_file': 'ml/rf_apt_model.pkl'
        })
    print("\n" + "="*55)
    print("  🛡  APT SHIELD — Detection System")
    print("  URL : http://127.0.0.1:5000")
    print("  Login: admin / apt@1234")
    print("="*55 + "\n")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
