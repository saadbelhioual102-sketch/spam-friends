from flask import Flask, request, jsonify
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import MajorLogin_res_pb2
from datetime import datetime
import base64
import json

app = Flask(__name__)

class JWTFetcher:
    def __init__(self):
        self.key = b'Yg&tc%DEuh6%Zc^8'
        self.iv = b'6oyZDr22E3ychjM%'
    
    @staticmethod
    def encode_varint(value):
        result = bytearray()
        while value > 0x7F:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value & 0x7F)
        return bytes(result)
    
    @staticmethod
    def encode_string(field_number, value):
        if isinstance(value, str):
            value = value.encode('utf-8')
        result = bytearray()
        result.extend(JWTFetcher.encode_varint((field_number << 3) | 2))
        result.extend(JWTFetcher.encode_varint(len(value)))
        result.extend(value)
        return bytes(result)
    
    @staticmethod
    def encode_int32(field_number, value):
        result = bytearray()
        result.extend(JWTFetcher.encode_varint((field_number << 3) | 0))
        result.extend(JWTFetcher.encode_varint(value))
        return bytes(result)
    
    def create_login_payload(self, open_id, access_token, platform):
        payload = bytearray()
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        payload.extend(self.encode_string(3, current_time))
        payload.extend(self.encode_string(4, 'free fire'))
        payload.extend(self.encode_int32(5, 1))
        payload.extend(self.encode_string(7, '2.111.2'))
        payload.extend(self.encode_string(8, 'Android OS 12 / API-31 (SP1A.210812.016/T505NDXS6CXB1)'))
        payload.extend(self.encode_string(9, 'Handheld'))
        payload.extend(self.encode_string(10, 'we'))
        payload.extend(self.encode_string(11, 'WIFI'))
        payload.extend(self.encode_int32(12, 1334))
        payload.extend(self.encode_int32(13, 800))
        payload.extend(self.encode_string(14, '225'))
        payload.extend(self.encode_string(15, 'ARM64 FP ASIMD AES | 4032 | 8'))
        payload.extend(self.encode_int32(16, 2705))
        payload.extend(self.encode_string(17, 'Adreno (TM) 610'))
        payload.extend(self.encode_string(18, 'OpenGL ES 3.2 V@0502.0 (GIT@5eaa426211, I07ee46fc66, 1633700387) (Date:10/08/21)'))
        payload.extend(self.encode_string(19, 'Google|dbc5b426-9715-454a-9466-6c82e151d407'))
        payload.extend(self.encode_string(20, '154.183.6.12'))
        payload.extend(self.encode_string(21, 'ar'))
        payload.extend(self.encode_string(22, open_id))
        payload.extend(self.encode_string(23, str(platform)))
        payload.extend(self.encode_string(24, 'Handheld'))
        payload.extend(self.encode_string(25, 'samsung SM-T505N'))
        payload.extend(self.encode_string(29, access_token))
        payload.extend(self.encode_int32(30, 1))
        payload.extend(self.encode_string(41, 'we'))
        payload.extend(self.encode_string(42, 'WIFI'))
        payload.extend(self.encode_string(57, 'e89b158e4bcf988ebd09eb83f5378e87'))
        payload.extend(self.encode_int32(60, 22394))
        payload.extend(self.encode_int32(61, 1424))
        payload.extend(self.encode_int32(62, 3349))
        payload.extend(self.encode_int32(63, 24))
        payload.extend(self.encode_int32(64, 1552))
        payload.extend(self.encode_int32(65, 22394))
        payload.extend(self.encode_int32(66, 1552))
        payload.extend(self.encode_int32(67, 22394))
        payload.extend(self.encode_int32(73, 1))
        payload.extend(self.encode_string(74, '/data/app/~~GAY==/com.dts.zbiiiiiiiiiiiiiiiiiiiio==/arm64'))
        payload.extend(self.encode_int32(76, 2))
        payload.extend(self.encode_string(77, 'b4d2689433917e66100ba91db790bf37|/data/app/~~GAY==/com.dts.zbiiiiiiiiiiiiiiiiiiiio==/zbi.apk'))
        payload.extend(self.encode_int32(78, 2))
        payload.extend(self.encode_int32(79, 2))
        payload.extend(self.encode_string(81, '64'))
        payload.extend(self.encode_string(83, '2019115296'))
        payload.extend(self.encode_int32(85, 1))
        payload.extend(self.encode_string(86, 'OpenGLES3'))
        payload.extend(self.encode_int32(87, 16383))
        payload.extend(self.encode_int32(88, 4))
        payload.extend(self.encode_string(90, 'Damanhur'))
        payload.extend(self.encode_string(91, 'BH'))
        payload.extend(self.encode_int32(92, 31095))
        payload.extend(self.encode_string(93, 'android_max'))
        payload.extend(self.encode_string(94, 'KqsHTzpfADfqKnEg/KMctJLElsm8bN2M4ts0zq+ifY+560USyjMSDL386RFrwRloT0ZSbMxEuM+Y4FSvjghQQZXWWpY='))
        payload.extend(self.encode_int32(97, 1))
        payload.extend(self.encode_int32(98, 1))
        payload.extend(self.encode_string(99, str(platform)))
        payload.extend(self.encode_string(100, str(platform)))
        inner = self.encode_string(8, 'GAW')
        payload.extend(self.encode_string(102, inner.decode('latin1')))
        
        return bytes(payload)
    
    @staticmethod
    def b64url_decode(input_str: str) -> bytes:
        rem = len(input_str) % 4
        if rem:
            input_str += '=' * (4 - rem)
        return base64.urlsafe_b64decode(input_str)
    
    def extract_jwt_payload(self, jwt_s: str):
        try:
            parts = jwt_s.split('.')
            if len(parts) < 2:
                return None
            payload_b64 = parts[1]
            payload_bytes = self.b64url_decode(payload_b64)
            payload = json.loads(payload_bytes.decode('utf-8', errors='ignore'))
            return payload if isinstance(payload, dict) else None
        except Exception:
            return None
    
    def inspect_token(self, access_token):
        inspect_url = f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}"
        headers = {
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close",
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)"
        }
        
        resp = requests.get(inspect_url, headers=headers, timeout=10)
        data = resp.json()
        
        if 'error' in data:
            raise Exception(f"Invalid token: {data.get('error')}")
        
        return data.get('open_id'), data.get('platform')
    
    def get_jwt(self, access_token, open_id=None, platform="google"):
        try:
            if not open_id:
                open_id, platform = self.inspect_token(access_token)
            
            data_pb = self.create_login_payload(open_id, access_token, str(platform))
            data_padded = pad(data_pb, 16)
            cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
            enc_data = cipher.encrypt(data_padded)
            
            MajorLogin_url = "https://loginbp.ggblueshark.com/MajorLogin"
            headers = {
                "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-S908E Build/TP1A.220624.014)",
                "Connection": "Keep-Alive",
                "Accept-Encoding": "gzip",
                "Content-Type": "application/octet-stream",
                "Expect": "100-continue",
                "X-GA": "v1 1",
                "X-Unity-Version": "2018.4.11f1",
                "ReleaseVersion": "OB51"
            }
            
            response = requests.post(MajorLogin_url, headers=headers, data=enc_data, timeout=15)
            
            if not response.ok:
                raise Exception(f"MajorLogin failed: {response.status_code}")
            
            resp_enc = response.content
            cipher_resp = AES.new(self.key, AES.MODE_CBC, self.iv)
            resp_msg = MajorLogin_res_pb2.MajorLoginRes()
            
            try:
                resp_dec = unpad(cipher_resp.decrypt(resp_enc), 16)
                resp_msg.ParseFromString(resp_dec)
            except:
                resp_msg.ParseFromString(resp_enc)
            
            jwt_payload = self.extract_jwt_payload(resp_msg.account_jwt)
            
            return {
                "success": True,
                "jwt": resp_msg.account_jwt,
                "account_id": resp_msg.account_id,
                "aes_key": resp_msg.key.hex(),
                "aes_iv": resp_msg.iv.hex(),
                "jwt_payload": jwt_payload,
                "open_id": open_id,
                "platform": str(platform)
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

@app.route('/access-to-jwt', methods=['GET'])
def access_to_jwt():
    access_token = request.args.get('access-token')
    
    if not access_token:
        return jsonify({
            "success": False,
            "error": "Missing required parameter: access-token"
        }), 400
    
    fetcher = JWTFetcher()
    result = fetcher.get_jwt(access_token)
    
    if result["success"]:
        return jsonify(result), 200
    else:
        return jsonify(result), 400

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "message": "JWT Fetcher API is running",
        "endpoint": "GET /access-to-jwt?access-token={your_token}"
    })
