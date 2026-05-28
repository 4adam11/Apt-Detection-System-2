# -*- coding: utf-8 -*-
"""
ml/email_alert.py - APT Shield Gmail Alert System
Uses STARTTLS port 587 with explicit UTF-8 safe login
"""

import smtplib
import json
import os
import threading
import base64
from datetime import datetime

CONFIG_PATH = os.path.join(os.path.dirname(__file__), '..', 'email_config.json')

CLASS_NAMES  = {
    0: 'Normal',
    1: 'Reconnaissance',
    2: 'Initial Compromise',
    3: 'Lateral Movement',
    4: 'Data Exfiltration'
}
SEVERITY_MAP = {2: 'HIGH', 3: 'HIGH', 4: 'CRITICAL'}
MITRE_MAP    = {
    2: 'T1078 - Valid Accounts',
    3: 'T1021 - Remote Services',
    4: 'T1041 - Exfiltration Over C2'
}


# ── Config ─────────────────────────────────────────────────────────────────

def save_config(sender_email, app_password, recipient_emails, enabled=True):
    config = {
        'sender_email':     sender_email,
        'app_password':     app_password,
        'recipient_emails': recipient_emails,
        'enabled':          enabled,
        'min_label':        2,
    }
    with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=True)
    return config


def load_config():
    if not os.path.exists(CONFIG_PATH):
        return {}
    with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
        return json.load(f)


def delete_config():
    if os.path.exists(CONFIG_PATH):
        os.remove(CONFIG_PATH)


# ── Safe string helper ─────────────────────────────────────────────────────

def safe(val):
    """Convert any value to a plain ASCII-safe string."""
    return str(val).encode('ascii', errors='replace').decode('ascii')


# ── Send ───────────────────────────────────────────────────────────────────

def send_alert_email(threat_data):
    config = load_config()
    if not config:
        return {'success': False, 'message': 'Email not configured'}
    if not config.get('enabled', True):
        return {'success': False, 'message': 'Email alerts disabled'}

    label = threat_data.get('predicted_label', 0)
    if label < config.get('min_label', 2):
        return {'success': False, 'message': 'Below alert threshold'}

    try:
        # ── Sanitize all values to pure ASCII ──────────────────────────────
        sender     = safe(config['sender_email'])
        password   = safe(config['app_password'])
        recipients = [safe(r) for r in config['recipient_emails']]
        cls_name   = safe(CLASS_NAMES.get(label, 'Threat'))
        src_ip     = safe(threat_data.get('src_ip',  'Unknown'))
        dst_ip     = safe(threat_data.get('dst_ip',  'Unknown'))
        protocol   = safe(threat_data.get('protocol','TCP'))
        conf       = safe(round(float(threat_data.get('confidence', 0)) * 100, 1)) + '%'
        severity   = safe(SEVERITY_MAP.get(label, 'HIGH'))
        mitre      = safe(MITRE_MAP.get(label, 'N/A'))
        ts         = safe(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        to_header  = ', '.join(recipients)

        # ── Build raw email as pure ASCII bytes ────────────────────────────
        subject = 'APT ALERT: ' + cls_name + ' Detected - ' + src_ip
        body = '\r\n'.join([
            'APT SHIELD - SECURITY ALERT',
            '=' * 40,
            '',
            'THREAT    : ' + cls_name,
            'SEVERITY  : ' + severity,
            'CONFIDENCE: ' + conf,
            'SOURCE IP : ' + src_ip,
            'DEST IP   : ' + dst_ip,
            'PROTOCOL  : ' + protocol,
            'MITRE     : ' + mitre,
            'TIME      : ' + ts,
            '',
            'Open dashboard: http://127.0.0.1:5000',
            '',
            '-- APT Shield v2.1.0 --',
        ])

        raw_msg = '\r\n'.join([
            'From: ' + sender,
            'To: '   + to_header,
            'Subject: ' + subject,
            'MIME-Version: 1.0',
            'Content-Type: text/plain; charset=us-ascii',
            'Content-Transfer-Encoding: 7bit',
            '',
            body
        ])

        # Final safety: encode everything as ASCII bytes
        msg_bytes = raw_msg.encode('ascii', errors='replace')

        # ── Connect via STARTTLS port 587 ──────────────────────────────────
        server = smtplib.SMTP('smtp.gmail.com', 587, timeout=15)
        server.ehlo()
        server.starttls()
        server.ehlo()

        # ── Login via AUTH PLAIN (base64 encoded - always ASCII safe) ──────
        auth_bytes = ('\x00' + sender + '\x00' + password).encode('utf-8')
        auth_b64   = base64.b64encode(auth_bytes).decode('ascii')
        code, resp = server.docmd('AUTH PLAIN', auth_b64)

        if code != 235:
            server.quit()
            return {
                'success': False,
                'message': 'Gmail login failed (code ' + str(code) + '). Check App Password.'
            }

        # ── Send ───────────────────────────────────────────────────────────
        server.sendmail(sender, recipients, msg_bytes)
        server.quit()

        print('[Email] Sent to ' + to_header)
        return {'success': True, 'message': 'Email sent to ' + to_header}

    except smtplib.SMTPAuthenticationError:
        return {'success': False,
                'message': 'Gmail auth failed. Make sure you are using an App Password.'}
    except smtplib.SMTPException as e:
        return {'success': False, 'message': 'SMTP error: ' + safe(str(e))}
    except OSError as e:
        return {'success': False, 'message': 'Network error: ' + safe(str(e))}
    except Exception as e:
        return {'success': False, 'message': 'Error: ' + safe(str(e))}


def send_alert_async(threat_data):
    """Non-blocking background email."""
    t = threading.Thread(target=send_alert_email, args=(threat_data,), daemon=True)
    t.start()


def send_test_email():
    return send_alert_email({
        'predicted_label': 4,
        'confidence':       0.97,
        'src_ip':          '192.168.1.100',
        'dst_ip':          '45.33.32.156',
        'protocol':        'TCP',
        'byte_count':       524288,
    })
