from flask import Flask, request, jsonify, make_response
import requests
import time
from collections import defaultdict
import random
import hashlib
import re
import uuid
from datetime import datetime

app = Flask(__name__)

# Güvenlik Konfigürasyonları
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX_REQUESTS = 8
RATE_LIMIT_BLOCK_DURATION = 3600

# IP bazlı rate limiting
request_log = defaultdict(list)
blocked_ips = {}
user_sessions = {}

# VPN/Proxy IP listeleri
VPN_IP_RANGES = [
    '185.159.131.', '45.137.21.', '193.29.13.', '91.199.117.',
    '45.95.147.', '185.220.101.', '185.165.190.', '45.142.214.'
]

# Şüpheli User Agent'lar
SUSPICIOUS_USER_AGENTS = [
    'python', 'requests', 'curl', 'wget', 'scrapy', 'bot', 'crawler', 
    'spider', 'monitor', 'headless', 'phantom', 'selenium', 'automation'
]

# Geçerli User Agent'lar
VALID_USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
    'Mozilla/5.0 (Android 10; Mobile) AppleWebKit/537.36'
]

# API Endpoint'leri - DOMAIN DEĞİŞTİRİLDİ
API_ENDPOINTS = {
    'tc': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/tc?tc={tc}', 'method': 'GET', 'desc': 'TC kimlik numarası ile temel bilgi sorgulama'},
    'tc2': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/tc2?tc={tc}', 'method': 'GET', 'desc': 'TC kimlik numarası ile detaylı bilgi sorgulama'},
    'yas': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/yas?tc={tc}', 'method': 'GET', 'desc': 'TC kimlik numarası ile yaş hesaplama'},
    'burc': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/burc?tc={tc}', 'method': 'GET', 'desc': 'TC kimlik numarası ile burç bilgisi sorgulama'},
    'iban': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/iban?iban={iban}', 'method': 'GET', 'desc': 'IBAN numarası ile banka bilgisi sorgulama'},
    'aile': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/aile?tc={tc}', 'method': 'GET', 'desc': 'TC kimlik numarası ile aile bilgisi sorgulama'},
    'es': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/es?tc={tc}', 'method': 'GET', 'desc': 'TC kimlik numarası ile eş bilgisi sorgulama'},
    'cocuk': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/cocuk?tc={tc}', 'method': 'GET', 'desc': 'TC kimlik numarası ile çocuk bilgisi sorgulama'},
    'erkekcocuk': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/erkekcocuk?tc={tc}', 'method': 'GET', 'desc': 'TC kimlik numarası ile erkek çocuk bilgisi sorgulama'},
    'kizcocuk': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/kizcocuk?tc={tc}', 'method': 'GET', 'desc': 'TC kimlik numarası ile kız çocuk bilgisi sorgulama'},
    'kardes': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/kardes?tc={tc}', 'method': 'GET', 'desc': 'TC kimlik numarası ile kardeş bilgisi sorgulama'},
    'anne': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/anne?tc={tc}', 'method': 'GET', 'desc': 'TC kimlik numarası ile anne bilgisi sorgulama'},
    'baba': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/baba?tc={tc}', 'method': 'GET', 'desc': 'TC kimlik numarası ile baba bilgisi sorgulama'},
    'ded': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/ded?tc={tc}', 'method': 'GET', 'desc': 'TC kimlik numarası ile dede bilgisi sorgulama'},
    'nine': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/nine?tc={tc}', 'method': 'GET', 'desc': 'TC kimlik numarası ile nine bilgisi sorgulama'},
    'sulale': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/sulale?tc={tc}', 'method': 'GET', 'desc': 'TC kimlik numarası ile sülale bilgisi sorgulama'},
    'soyagaci': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/soyagaci?tc={tc}', 'method': 'GET', 'desc': 'TC kimlik numarası ile soy ağacı bilgisi sorgulama'},
    'sulaledenhalasorgu': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/sulaledenhalasorgu?tc={tc}', 'method': 'GET', 'desc': 'TC kimlik numarası ile sülaleden hala sorgulama'},
    'sulaledenamcasorgu': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/sulaledenamcasorgu?tc={tc}', 'method': 'GET', 'desc': 'TC kimlik numarası ile sülaleden amca sorgulama'},
    'sulaledendayisorgu': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/sulaledendayisorgu?tc={tc}', 'method': 'GET', 'desc': 'TC kimlik numarası ile sülaleden dayı sorgulama'},
    'sulaledenteyzesorgu': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/sulaledenteyzesorgu?tc={tc}', 'method': 'GET', 'desc': 'TC kimlik numarası ile sülaleden teyze sorgulama'},
    'kuzen': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/kuzen?tc={tc}', 'method': 'GET', 'desc': 'TC kimlik numarası ile kuzen bilgisi sorgulama'},
    'yegen': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/yegen?tc={tc}', 'method': 'GET', 'desc': 'TC kimlik numarası ile yeğen bilgisi sorgulama'},
    'adres': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/adres?tc={tc}', 'method': 'GET', 'desc': 'TC kimlik numarası ile adres bilgisi sorgulama'},
    'haneadres': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/haneadres?tc={tc}', 'method': 'GET', 'desc': 'TC kimlik numarası ile hane adres bilgisi sorgulama'},
    'tcgsm': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/tcgsm?tc={tc}', 'method': 'GET', 'desc': 'TC kimlik numarası ile GSM numarası sorgulama'},
    'gsmtc': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/gsmtc?gsm={gsm}', 'method': 'GET', 'desc': 'GSM numarası ile TC kimlik numarası sorgulama'},
    'operator': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/operator?numara={numara}', 'method': 'GET', 'desc': 'Telefon numarası ile operatör bilgisi sorgulama'},
    'adsoyad': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/adsoyad?ad={ad}&soyad={soyad}&il={il}&ilce={ilce}', 'method': 'GET', 'desc': 'Ad, soyad, il ve ilçe ile kişi sorgulama'},
    'adsoyadpro': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/adsoyadpro?ad={ad}&soyad={soyad}', 'method': 'GET', 'desc': 'Ad ve soyad ile detaylı kişi sorgulama'},
    'profil': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/profil?tc={tc}', 'method': 'GET', 'desc': 'TC kimlik numarası ile profil bilgisi sorgulama'},
    'tamamileagaci': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/tamamileagaci?tc={tc}', 'method': 'GET', 'desc': 'TC kimlik numarası ile tam aile ağacı sorgulama'},
    'tcvegsm': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/tcvegsm?tc={tc}', 'method': 'GET', 'desc': 'TC kimlik numarası ile TC ve GSM bilgisi sorgulama'},
    'adresvegsm': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/adresvegsm?tc={tc}', 'method': 'GET', 'desc': 'TC kimlik numarası ile adres ve GSM bilgisi sorgulama'},
    'tumiletisim': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/tumiletisim?tc={tc}', 'method': 'GET', 'desc': 'TC kimlik numarası ile tüm iletişim bilgisi sorgulama'},
    'cocuksayisi': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/cocuksayisi?tc={tc}', 'method': 'GET', 'desc': 'TC kimlik numarası ile çocuk sayısı sorgulama'},
    'kardessayisi': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/kardessayisi?tc={tc}', 'method': 'GET', 'desc': 'TC kimlik numarası ile kardeş sayısı sorgulama'},
    'ailebuyuklugu': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/ailebuyuklugu?tc={tc}', 'method': 'GET', 'desc': 'TC kimlik numarası ile aile büyüklüğü sorgulama'},
    'log': {'url': 'https://api.nabisystem.sorgu.tr.org.totalh.net/api/log?site={site}', 'method': 'GET', 'desc': 'Site adı ile log bilgisi sorgulama'}
}

# API Kategorileri
API_CATEGORIES = {
    'tc': ['tc', 'tc2', 'yas', 'burc', 'profil'],
    'aile': ['aile', 'es', 'cocuk', 'erkekcocuk', 'kizcocuk', 'kardes', 'anne', 'baba', 'ded', 'nine', 'sulale', 'soyagaci', 'sulaledenhalasorgu', 'sulaledenamcasorgu', 'sulaledendayisorgu', 'sulaledenteyzesorgu', 'kuzen', 'yegen', 'tamamileagaci', 'cocuksayisi', 'kardessayisi', 'ailebuyuklugu'],
    'gsm': ['adres', 'haneadres', 'tcgsm', 'gsmtc', 'operator', 'tcvegsm', 'adresvegsm', 'tumiletisim'],
    'other': ['iban', 'adsoyad', 'adsoyadpro', 'log']
}

def generate_user_fingerprint(request):
    """Kullanıcı fingerprint oluşturma"""
    components = [
        request.headers.get('User-Agent', ''),
        request.headers.get('Accept-Language', ''),
        request.headers.get('Accept-Encoding', ''),
        request.headers.get('Accept', ''),
        request.remote_addr
    ]
    fingerprint_string = '|'.join(components)
    return hashlib.sha256(fingerprint_string.encode()).hexdigest()

def check_vpn_proxy(ip):
    """VPN/Proxy kontrolü"""
    for vpn_range in VPN_IP_RANGES:
        if ip.startswith(vpn_range):
            return True
    return False

def check_suspicious_headers(headers):
    """Şüpheli header kontrolü"""
    suspicious_headers = [
        'X-Forwarded-For', 'X-Real-IP', 'CF-Connecting-IP',
        'X-Originating-IP', 'X-Remote-IP', 'X-Remote-Addr'
    ]
    
    for header in suspicious_headers:
        if header in headers:
            return True
    return False

def check_user_agent(user_agent):
    """User Agent kontrolü"""
    if not user_agent:
        return False, "User Agent bulunamadı"
    
    user_agent_lower = user_agent.lower()
    
    for suspicious in SUSPICIOUS_USER_AGENTS:
        if suspicious in user_agent_lower:
            return False, f"Şüpheli User Agent: {suspicious}"
    
    is_valid = any(valid_ua in user_agent for valid_ua in VALID_USER_AGENTS)
    if not is_valid:
        return False, "Geçersiz User Agent"
    
    return True, "OK"

def check_rate_limit(ip, session_id):
    """Rate limiting kontrolü"""
    now = time.time()
    
    if ip in blocked_ips:
        if now < blocked_ips[ip]:
            return False, "IP adresiniz 1 saat süreyle bloklanmıştır."
        else:
            del blocked_ips[ip]
    
    window_start = now - RATE_LIMIT_WINDOW
    request_log[session_id] = [timestamp for timestamp in request_log.get(session_id, []) if timestamp > window_start]
    
    if len(request_log[session_id]) >= RATE_LIMIT_MAX_REQUESTS:
        blocked_ips[ip] = now + RATE_LIMIT_BLOCK_DURATION
        return False, "Rate limit aşıldı. IP adresiniz 1 saat süreyle bloklanmıştır."
    
    request_log[session_id].append(now)
    return True, "OK"

def create_user_session(request):
    """Kullanıcı session'ı oluşturma"""
    session_id = str(uuid.uuid4())
    fingerprint = generate_user_fingerprint(request)
    
    user_sessions[session_id] = {
        'fingerprint': fingerprint,
        'ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent'),
        'created_at': time.time(),
        'request_count': 0
    }
    
    return session_id

def validate_session(session_id, request):
    """Session doğrulama"""
    if session_id not in user_sessions:
        return False, "Geçersiz session"
    
    session = user_sessions[session_id]
    current_fingerprint = generate_user_fingerprint(request)
    
    if session['fingerprint'] != current_fingerprint:
        return False, "Session fingerprint uyuşmuyor"
    
    if time.time() - session['created_at'] > 3600:
        del user_sessions[session_id]
        return False, "Session süresi dolmuş"
    
    return True, "OK"

def generate_api_card(api_name, api_data):
    """API kartı HTML oluşturma"""
    return f'''
    <div class="api-card">
        <div class="api-card-header">
            <h3>{api_name.upper()}</h3>
            <span class="api-method">{api_data['method']}</span>
        </div>
        <p class="api-description">{api_data['desc']}</p>
        <div class="api-url">{api_data['url']}</div>
        <div class="api-buttons">
            <button class="api-btn copy" data-url="{api_data['url']}">
                <i class="fas fa-copy"></i> Kopyala
            </button>
            <a href="/api/{api_name}" target="_blank" class="api-btn">
                <i class="fas fa-external-link-alt"></i> Test Et
            </a>
        </div>
    </div>
    '''

def generate_api_section(category_name, api_list):
    """API bölümü HTML oluşturma"""
    api_cards = ''
    for api_name in api_list:
        if api_name in API_ENDPOINTS:
            api_cards += generate_api_card(api_name, API_ENDPOINTS[api_name])
    
    return f'''
    <div class="api-category">
        <h3 class="category-title">{category_name.upper()} API'leri</h3>
        <div class="api-grid">
            {api_cards}
        </div>
    </div>
    '''

# TAM HTML TEMPLATE (ORJİNALİNE SADIK)
HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nabi System - API Servis ve Racon</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Orbitron:wght@400;700;900&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary: #FF2E2E;
            --primary-dark: #CC0000;
            --secondary: #FF6B6B;
            --dark: #0F0F1A;
            --darker: #0A0A12;
            --light: #F0F0F0;
            --gray: #8B8BAA;
            --card-bg: rgba(30, 25, 35, 0.85);
            --card-border: rgba(255, 46, 46, 0.4);
            --success: #10B981;
            --warning: #F59E0B;
            --danger: #EF4444;
            --dragon-red: #FF2E2E;
            --dragon-orange: #FF6B35;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', sans-serif;
            background: linear-gradient(135deg, var(--darker) 0%, var(--dark) 100%);
            color: var(--light);
            min-height: 100vh;
            line-height: 1.6;
            overflow-x: hidden;
            position: relative;
        }

        .dragon-bg {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -2;
            opacity: 0.08;
            overflow: hidden;
        }

        .dragon-gif {
            width: 100%;
            height: 100%;
            object-fit: cover;
            filter: brightness(0.8) contrast(1.2);
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 0 20px;
            position: relative;
            z-index: 1;
        }

        .header {
            text-align: center;
            padding: 60px 0 40px;
            position: relative;
            overflow: hidden;
        }

        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: radial-gradient(circle at top right, rgba(255, 46, 46, 0.15), transparent 70%);
            z-index: -1;
        }

        .logo-container {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 15px;
            margin-bottom: 30px;
        }

        .logo-icon {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, var(--dragon-red), var(--dragon-orange));
            border-radius: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 36px;
            box-shadow: 0 10px 25px rgba(255, 46, 46, 0.5);
            transform: rotate(0deg);
            transition: transform 0.5s ease;
        }

        .logo-icon:hover {
            transform: rotate(360deg);
        }

        .logo-text {
            font-family: 'Orbitron', sans-serif;
            font-size: 4rem;
            font-weight: 900;
            background: linear-gradient(135deg, var(--dragon-red), var(--dragon-orange), #FF8C42);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-shadow: 0 5px 15px rgba(255, 46, 46, 0.5);
            letter-spacing: 2px;
            position: relative;
            display: inline-block;
        }

        .logo-text::after {
            content: '';
            position: absolute;
            bottom: -10px;
            left: 0;
            width: 100%;
            height: 3px;
            background: linear-gradient(90deg, transparent, var(--dragon-red), transparent);
        }

        .nabi-system {
            font-family: 'Orbitron', sans-serif;
            font-size: 1.8rem;
            color: var(--dragon-red);
            margin-top: -10px;
            text-shadow: 0 0 10px rgba(255, 46, 46, 0.7);
            animation: dragonGlow 2s infinite alternate;
        }

        @keyframes dragonGlow {
            from { text-shadow: 0 0 10px rgba(255, 46, 46, 0.7); }
            to { text-shadow: 0 0 20px rgba(255, 46, 46, 1), 0 0 30px rgba(255, 107, 53, 0.5); }
        }

        .tagline {
            font-size: 1.3rem;
            color: var(--gray);
            max-width: 600px;
            margin: 0 auto 30px;
            position: relative;
        }

        .tagline::before, .tagline::after {
            content: '🔥';
            color: var(--dragon-red);
            margin: 0 10px;
        }

        .stats {
            display: flex;
            justify-content: center;
            gap: 30px;
            margin-top: 30px;
            flex-wrap: wrap;
        }

        .stat-item {
            background: var(--card-bg);
            backdrop-filter: blur(10px);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            padding: 15px 25px;
            text-align: center;
            min-width: 150px;
            transform: translateY(0);
            transition: transform 0.3s ease;
        }

        .stat-item:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(255, 46, 46, 0.2);
        }

        .stat-number {
            font-size: 2rem;
            font-weight: 700;
            color: var(--dragon-red);
            margin-bottom: 5px;
        }

        .stat-label {
            font-size: 0.9rem;
            color: var(--gray);
        }

        .nav-tabs {
            display: flex;
            justify-content: center;
            gap: 10px;
            margin: 30px 0;
            flex-wrap: wrap;
        }

        .nav-tab {
            padding: 12px 25px;
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 10px;
            color: var(--light);
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .nav-tab::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 46, 46, 0.2), transparent);
            transition: left 0.5s;
        }

        .nav-tab:hover::before {
            left: 100%;
        }

        .nav-tab.active {
            background: linear-gradient(135deg, var(--dragon-red), var(--dragon-orange));
            box-shadow: 0 5px 15px rgba(255, 46, 46, 0.4);
        }

        .nav-tab:hover:not(.active) {
            background: rgba(255, 46, 46, 0.1);
            border-color: var(--dragon-red);
        }

        .section {
            margin-bottom: 50px;
            display: none;
        }

        .section.active {
            display: block;
            animation: fadeIn 0.5s ease;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .section-title {
            font-size: 2rem;
            font-weight: 700;
            margin: 0 0 25px;
            padding-bottom: 15px;
            border-bottom: 2px solid var(--dragon-red);
            display: flex;
            align-items: center;
            gap: 15px;
            font-family: 'Orbitron', sans-serif;
        }

        .section-title i {
            color: var(--dragon-red);
        }

        .api-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 25px;
            margin-bottom: 40px;
        }

        .api-card {
            background: var(--card-bg);
            backdrop-filter: blur(10px);
            border: 1px solid var(--card-border);
            border-radius: 15px;
            padding: 25px;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
            transform-style: preserve-3d;
            perspective: 1000px;
        }

        .api-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--dragon-red), var(--dragon-orange));
        }

        .api-card:hover {
            transform: translateY(-8px) rotateX(5deg);
            box-shadow: 0 15px 30px rgba(0, 0, 0, 0.5);
            border-color: var(--dragon-red);
        }

        .api-card-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 15px;
        }

        .api-card h3 {
            font-size: 1.3rem;
            margin-bottom: 5px;
            color: var(--light);
        }

        .api-method {
            background: rgba(255, 107, 53, 0.2);
            color: var(--dragon-orange);
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
        }

        .api-description {
            color: var(--gray);
            font-size: 0.95rem;
            margin-bottom: 20px;
            min-height: 40px;
        }

        .api-url {
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 15px;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            color: var(--light);
            word-break: break-all;
            position: relative;
        }

        .api-buttons {
            display: flex;
            gap: 10px;
        }

        .api-btn {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            flex: 1;
            padding: 10px;
            background: linear-gradient(135deg, var(--dragon-red), var(--dragon-orange));
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            transition: all 0.3s ease;
            border: none;
            cursor: pointer;
            font-size: 0.9rem;
        }

        .api-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 7px 15px rgba(255, 46, 46, 0.4);
        }

        .api-btn.copy {
            background: linear-gradient(135deg, #10B981, #059669);
        }

        .api-btn.copy:hover {
            box-shadow: 0 7px 15px rgba(16, 185, 129, 0.4);
        }

        .terminal {
            background: rgba(0, 0, 0, 0.8);
            border: 1px solid var(--dragon-red);
            border-radius: 10px;
            padding: 20px;
            margin: 30px 0;
            font-family: 'Courier New', monospace;
            color: var(--dragon-red);
            position: relative;
            overflow: hidden;
        }

        .terminal::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(transparent 90%, rgba(255, 46, 46, 0.1) 100%);
            pointer-events: none;
        }

        .terminal-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 15px;
            border-bottom: 1px solid var(--dragon-orange);
            padding-bottom: 10px;
        }

        .terminal-title {
            font-weight: bold;
        }

        .terminal-content {
            line-height: 1.5;
        }

        .terminal-line {
            margin-bottom: 5px;
        }

        .terminal-prompt {
            color: var(--dragon-orange);
        }

        .footer {
            text-align: center;
            padding: 40px 0;
            margin-top: 50px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            color: var(--gray);
            position: relative;
        }

        .footer::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(90deg, transparent, var(--dragon-red), transparent);
        }

        .footer-links {
            display: flex;
            justify-content: center;
            gap: 30px;
            margin: 20px 0;
            flex-wrap: wrap;
        }

        .footer-link {
            color: var(--gray);
            text-decoration: none;
            transition: color 0.3s ease;
        }

        .footer-link:hover {
            color: var(--dragon-red);
        }

        @media (max-width: 768px) {
            .api-grid {
                grid-template-columns: 1fr;
            }

            .logo-text {
                font-size: 2.5rem;
            }

            .section-title {
                font-size: 1.7rem;
            }

            .stats {
                gap: 15px;
            }

            .stat-item {
                min-width: 120px;
                padding: 12px 15px;
            }

            .stat-number {
                font-size: 1.7rem;
            }
            
            .nav-tabs {
                flex-direction: column;
                align-items: center;
            }
            
            .nav-tab {
                width: 80%;
                text-align: center;
            }
            
            .api-buttons {
                flex-direction: column;
            }
        }
        
        .star {
            position: absolute;
            background-color: white;
            border-radius: 50%;
            animation: twinkle 3s infinite;
            z-index: -1;
        }
        
        @keyframes twinkle {
            0% { opacity: 0.2; }
            50% { opacity: 1; }
            100% { opacity: 0.2; }
        }
        
        .api-category {
            margin-bottom: 40px;
        }
        
        .category-title {
            font-size: 1.5rem;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid rgba(255, 46, 46, 0.3);
            color: var(--dragon-red);
            font-family: 'Orbitron', sans-serif;
        }

        .status-badge {
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--success);
            color: white;
            padding: 10px 15px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            z-index: 1000;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        }
    </style>
</head>
<body>
    <div class="dragon-bg">
        <img src="https://i.ibb.co/hw1yWdL/red-dragon-yt.gif" alt="Red Dragon" class="dragon-gif">
    </div>
    
    <div id="stars"></div>

    <div class="status-badge">
        <i class="fas fa-shield-alt"></i> GÜVENLİK AKTİF
    </div>
    
    <div class="container">
        <div class="header">
            <div class="logo-container">
                <div class="logo-icon">
                    <i class="fas fa-dragon"></i>
                </div>
                <h1 class="logo-text">NABI SYSTEM</h1>
                <div class="nabi-system">API SERVİS VE RACON SÖZÜ</div>
            </div>
            <p class="tagline">Ejderha gücünde API servisleri - Sadece gerçekler için</p>
            
            <div class="terminal">
                <div class="terminal-header">
                    <div class="terminal-title">root@nabiapi:~</div>
                    <div class="terminal-status">DRAGON MODE: ACTIVE</div>
                </div>
                <div class="terminal-content">
                    <div class="terminal-line"><span class="terminal-prompt">$</span> system_status --api</div>
                    <div class="terminal-line">> API_STATUS: <span style="color: var(--dragon-red)">DRAGON POWERED</span></div>
                    <div class="terminal-line">> ENDPOINTS_AVAILABLE: <span style="color: var(--dragon-red)">''' + str(len(API_ENDPOINTS)) + '''</span></div>
                    <div class="terminal-line">> RESPONSE_TIME: <span style="color: var(--dragon-red)">DRAGON FIRE SPEED</span></div>
                    <div class="terminal-line">> SECURITY_LEVEL: <span style="color: var(--dragon-red)">MAXIMUM</span></div>
                    <div class="terminal-line"><span class="terminal-prompt">$</span> _</div>
                </div>
            </div>
            
            <div class="stats">
                <div class="stat-item">
                    <div class="stat-number">''' + str(len(API_ENDPOINTS)) + '''+</div>
                    <div class="stat-label">API Endpoint</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number">99.9%</div>
                    <div class="stat-label">Uptime</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number">24/7</div>
                    <div class="stat-label">Aktif Sistem</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number">100%</div>
                    <div class="stat-label">Güvenli Erişim</div>
                </div>
            </div>
        </div>

        <div class="nav-tabs">
            <div class="nav-tab active" data-tab="all">Tüm API'ler</div>
            <div class="nav-tab" data-tab="tc">TC API'leri</div>
            <div class="nav-tab" data-tab="aile">Aile API'leri</div>
            <div class="nav-tab" data-tab="gsm">GSM API'leri</div>
            <div class="nav-tab" data-tab="other">Diğer API'ler</div>
        </div>

        <div class="section active" id="all">
            <h2 class="section-title">
                <i class="fas fa-code"></i>
                Tüm API Endpoint'leri
            </h2>
            ''' + generate_api_section('TC Kimlik', API_CATEGORIES['tc']) + '''
            ''' + generate_api_section('Aile', API_CATEGORIES['aile']) + '''
            ''' + generate_api_section('GSM ve İletişim', API_CATEGORIES['gsm']) + '''
            ''' + generate_api_section('Diğer', API_CATEGORIES['other']) + '''
        </div>

        <div class="section" id="tc">
            <h2 class="section-title">
                <i class="fas fa-id-card"></i>
                TC API'leri
            </h2>
            ''' + generate_api_section('TC Kimlik', API_CATEGORIES['tc']) + '''
        </div>

        <div class="section" id="aile">
            <h2 class="section-title">
                <i class="fas fa-users"></i>
                Aile API'leri
            </h2>
            ''' + generate_api_section('Aile', API_CATEGORIES['aile']) + '''
        </div>

        <div class="section" id="gsm">
            <h2 class="section-title">
                <i class="fas fa-mobile-alt"></i>
                GSM API'leri
            </h2>
            ''' + generate_api_section('GSM ve İletişim', API_CATEGORIES['gsm']) + '''
        </div>

        <div class="section" id="other">
            <h2 class="section-title">
                <i class="fas fa-cogs"></i>
                Diğer API'ler
            </h2>
            ''' + generate_api_section('Diğer', API_CATEGORIES['other']) + '''
        </div>

        <div class="footer">
            <div class="footer-links">
                <a href="#" class="footer-link">Gizlilik Politikası</a>
                <a href="#" class="footer-link">Kullanım Şartları</a>
                <a href="#" class="footer-link">İletişim</a>
                <a href="#" class="footer-link">SSS</a>
            </div>
            <p>© 2024 Nabi System - API Servis ve Racon Sözü. Tüm hakları saklıdır.</p>
            <p style="margin-top: 10px; font-size: 0.9rem; color: #94A3B8;">Ejderha gücünde API erişimi - Sadece seçilmişler için</p>
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const tabs = document.querySelectorAll('.nav-tab');
            const sections = document.querySelectorAll('.section');
            
            tabs.forEach(tab => {
                tab.addEventListener('click', function() {
                    const targetTab = this.getAttribute('data-tab');
                    
                    tabs.forEach(t => t.classList.remove('active'));
                    sections.forEach(s => s.classList.remove('active'));
                    
                    this.classList.add('active');
                    document.getElementById(targetTab).classList.add('active');
                });
            });
            
            const apiCards = document.querySelectorAll('.api-card');
            apiCards.forEach(card => {
                card.addEventListener('mouseenter', function() {
                    this.style.transform = 'translateY(-8px) rotateX(5deg)';
                });
                
                card.addEventListener('mouseleave', function() {
                    this.style.transform = 'translateY(0) rotateX(0)';
                });
            });
            
            const copyButtons = document.querySelectorAll('.api-btn.copy');
            copyButtons.forEach(button => {
                button.addEventListener('click', function() {
                    const url = this.getAttribute('data-url');
                    navigator.clipboard.writeText(url).then(() => {
                        const originalText = this.innerHTML;
                        this.innerHTML = '<i class="fas fa-check"></i> Kopyalandı!';
                        setTimeout(() => {
                            this.innerHTML = originalText;
                        }, 2000);
                    });
                });
            });
            
            function createStars() {
                const starsContainer = document.getElementById('stars');
                const starCount = 100;
                
                for (let i = 0; i < starCount; i++) {
                    const star = document.createElement('div');
                    star.classList.add('star');
                    
                    const size = Math.random() * 3;
                    const left = Math.random() * 100;
                    const top = Math.random() * 100;
                    const delay = Math.random() * 5;
                    
                    star.style.width = `${size}px`;
                    star.style.height = `${size}px`;
                    star.style.left = `${left}%`;
                    star.style.top = `${top}%`;
                    star.style.animationDelay = `${delay}s`;
                    
                    starsContainer.appendChild(star);
                }
            }
            
            createStars();
        });
    </script>
</body>
</html>'''

@app.before_request
def before_request():
    """Her istekten önce güvenlik kontrolleri"""
    if request.endpoint in ['home', 'static']:
        return
    
    client_ip = request.remote_addr
    
    # VPN/Proxy kontrolü
    if check_vpn_proxy(client_ip):
        return jsonify({'error': 'VPN/Proxy tespit edildi. Erişim engellendi.'}), 403
    
    # Şüpheli header kontrolü
    if check_suspicious_headers(request.headers):
        return jsonify({'error': 'Şüpheli header tespit edildi. Erişim engellendi.'}), 403
    
    # User Agent kontrolü
    user_agent_ok, user_agent_msg = check_user_agent(request.headers.get('User-Agent'))
    if not user_agent_ok:
        return jsonify({'error': user_agent_msg}), 403
    
    # Session kontrolü
    session_id = request.cookies.get('session_id')
    if not session_id:
        session_id = create_user_session(request)
        response = make_response(jsonify({'error': 'Session oluşturuldu, lütfen tekrar deneyin.'}))
        response.set_cookie('session_id', session_id, httponly=True, max_age=3600)
        return response
    
    # Session doğrulama
    session_ok, session_msg = validate_session(session_id, request)
    if not session_ok:
        response = make_response(jsonify({'error': session_msg}))
        response.set_cookie('session_id', '', expires=0)
        return response
    
    # Rate limiting
    rate_ok, rate_msg = check_rate_limit(client_ip, session_id)
    if not rate_ok:
        return jsonify({'error': rate_msg}), 429
    
    user_sessions[session_id]['request_count'] += 1

@app.route('/')
def home():
    """Ana sayfa"""
    session_id = create_user_session(request)
    response = make_response(HTML_TEMPLATE)
    response.set_cookie('session_id', session_id, httponly=True, max_age=3600)
    return response

@app.route('/api/<endpoint>')
def api_proxy(endpoint):
    """API proxy endpoint"""
    if endpoint not in API_ENDPOINTS:
        return jsonify({'error': 'Geçersiz endpoint'}), 404
    
    params = request.args.to_dict()
    
    try:
        api_url = API_ENDPOINTS[endpoint]['url'].format(**params)
        
        time.sleep(random.uniform(0.2, 0.5))
        
        response = requests.get(
            api_url,
            headers={
                'User-Agent': random.choice(VALID_USER_AGENTS),
                'Accept': 'application/json'
            },
            timeout=10
        )
        
        return jsonify(response.json()), response.status_code
        
    except requests.exceptions.Timeout:
        return jsonify({'error': 'Backend timeout'}), 504
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'Backend error: {str(e)}'}), 502
    except Exception as e:
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
