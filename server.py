from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import secrets
import string
from datetime import datetime, timedelta
import os
import sys

app = Flask(__name__)
CORS(app, origins='*')

# ====== DỮ LIỆU LƯU TRỮ ======
licenses = {}
banned_hwids = []
# Nếu muốn lưu database SQLite, thay phần này

# ====== HÀM TẠO KEY ======
def generate_key():
    chars = string.ascii_uppercase + string.digits
    raw = ''.join(secrets.choice(chars) for _ in range(20))
    return '-'.join(raw[i:i+5] for i in range(0, 20, 5))

# ====== ENDPOINT TẠO KEY ======
@app.route('/api/create', methods=['POST'])
def create_license():
    try:
        data = request.json
        key_type = data.get('type', 'monthly')
        custom_name = data.get('custom_name', '').strip()
        expires_at_str = data.get('expires_at', '').strip()
        max_activations = data.get('max_activations', 1)
        
        if custom_name:
            key = custom_name
        else:
            key = generate_key()
        
        now = datetime.now()
        
        if expires_at_str:
            try:
                expires = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
                if expires.tzinfo:
                    expires = expires.replace(tzinfo=None)
                expires_str = expires.isoformat()
            except:
                return jsonify({'error': 'Invalid date format'}), 400
        else:
            if key_type == 'trial':
                expires = now + timedelta(days=3)
            elif key_type == 'monthly':
                expires = now + timedelta(days=30)
            elif key_type == 'yearly':
                expires = now + timedelta(days=365)
            elif key_type == 'lifetime':
                expires = None
            else:
                expires = now + timedelta(days=30)
            expires_str = expires.isoformat() if expires else None
        
        licenses[key] = {
            'key': key,
            'type': key_type,
            'created_at': now.isoformat(),
            'expires_at': expires_str if expires_str else 'Lifetime',
            'active': True,
            'banned': False,
            'hwid': None,
            'max_activations': max_activations,
            'current_activations': 0
        }
        
        return jsonify({
            'success': True,
            'license_key': key,
            'expires_at': expires_str if expires_str else 'Lifetime'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ====== ENDPOINT XÁC THỰC ======
@app.route('/api/validate', methods=['POST'])
def validate_license():
    try:
        data = request.json
        key = data.get('key', '').strip()
        hwid = data.get('hwid', '').strip()
        
        if not key:
            return jsonify({'valid': False, 'error': 'Key is required'}), 400
        
        if key not in licenses:
            return jsonify({'valid': False, 'error': 'Key not found'}), 404
        
        license_data = licenses[key]
        
        if license_data['banned']:
            return jsonify({'valid': False, 'error': 'Key is banned'}), 403
        
        if not license_data['active']:
            return jsonify({'valid': False, 'error': 'Key is inactive'}), 403
        
        if license_data['expires_at'] != 'Lifetime':
            expires = datetime.fromisoformat(license_data['expires_at'])
            if datetime.now() > expires:
                return jsonify({'valid': False, 'error': 'Key expired'}), 403
        
        if hwid and hwid in banned_hwids:
            return jsonify({'valid': False, 'error': 'HWID is banned'}), 403
        
        if license_data['hwid'] and license_data['hwid'] != hwid:
            return jsonify({'valid': False, 'error': 'HWID mismatch'}), 403
        
        if not license_data['hwid'] and hwid:
            license_data['hwid'] = hwid
            license_data['current_activations'] = 1
        
        return jsonify({
            'valid': True,
            'license_type': license_data['type'],
            'expires_at': license_data['expires_at']
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ====== DANH SÁCH KEY ======
@app.route('/api/list', methods=['GET'])
def list_licenses():
    try:
        result = []
        for key, data in licenses.items():
            result.append({
                'license_key': key,
                'license_type': data['type'],
                'expires_at': data['expires_at'],
                'is_active': data['active'],
                'is_banned': data['banned'],
                'hwid': data['hwid'],
                'current_activations': data['current_activations'],
                'max_activations': data['max_activations']
            })
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ====== THỐNG KÊ ======
@app.route('/api/stats', methods=['GET'])
def get_stats():
    try:
        total = len(licenses)
        active = sum(1 for d in licenses.values() if d['active'] and not d['banned'])
        banned = sum(1 for d in licenses.values() if d['banned'])
        lifetime = sum(1 for d in licenses.values() if d['type'] == 'lifetime')
        return jsonify({
            'total_licenses': total,
            'active_licenses': active,
            'banned_licenses': banned,
            'lifetime_licenses': lifetime
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ====== BAN KEY ======
@app.route('/api/ban/<key>', methods=['POST'])
def ban_key(key):
    try:
        if key not in licenses:
            return jsonify({'error': 'Key not found'}), 404
        licenses[key]['banned'] = True
        licenses[key]['active'] = False
        return jsonify({'success': True, 'message': f'Key {key} banned'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ====== UNBAN KEY ======
@app.route('/api/unban/<key>', methods=['POST'])
def unban_key(key):
    try:
        if key not in licenses:
            return jsonify({'error': 'Key not found'}), 404
        licenses[key]['banned'] = False
        licenses[key]['active'] = True
        return jsonify({'success': True, 'message': f'Key {key} unbanned'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ====== XÓA KEY ======
@app.route('/api/delete/<key>', methods=['DELETE'])
def delete_key(key):
    try:
        if key not in licenses:
            return jsonify({'error': 'Key not found'}), 404
        del licenses[key]
        return jsonify({'success': True, 'message': f'Key {key} deleted'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ====== BAN HWID ======
@app.route('/api/ban-hwid', methods=['POST'])
def ban_hwid():
    try:
        data = request.json
        hwid = data.get('hwid', '').strip()
        if not hwid:
            return jsonify({'error': 'HWID required'}), 400
        if hwid not in banned_hwids:
            banned_hwids.append(hwid)
        return jsonify({'success': True, 'message': f'HWID {hwid} banned'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ====== UNBAN HWID ======
@app.route('/api/unban-hwid', methods=['POST'])
def unban_hwid():
    try:
        data = request.json
        hwid = data.get('hwid', '').strip()
        if not hwid:
            return jsonify({'error': 'HWID required'}), 400
        if hwid in banned_hwids:
            banned_hwids.remove(hwid)
        return jsonify({'success': True, 'message': f'HWID {hwid} unbanned'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ====== HEALTH CHECK ======
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'alive',
        'licenses': len(licenses),
        'banned_hwids': len(banned_hwids),
        'timestamp': datetime.now().isoformat()
    })

# ====== ROOT ======
@app.route('/', methods=['GET'])
def root():
    return jsonify({
        'name': 'License Server',
        'version': '1.0',
        'endpoints': [
            '/api/create',
            '/api/validate',
            '/api/list',
            '/api/stats',
            '/api/ban/<key>',
            '/api/unban/<key>',
            '/api/delete/<key>',
            '/api/ban-hwid',
            '/api/unban-hwid',
            '/health'
        ]
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print("=" * 50)
    print("🚀 LICENSE SERVER STARTED")
    print("=" * 50)
    print(f"📌 Port: {port}")
    print(f"📌 Licenses: {len(licenses)}")
    print("=" * 50)
    app.run(host='0.0.0.0', port=port)
