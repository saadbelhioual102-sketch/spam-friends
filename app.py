import json, requests, warnings, random, threading, time
from datetime import datetime
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher as Cp, algorithms as Al, modes as Md
from cryptography.hazmat.backends import default_backend as Bk
from google.protobuf.internal.decoder import _DecodeVarint32

warnings.filterwarnings("ignore")

k = b"Yg&tc%DEuh6%Zc^8"
iv = b"6oyZDr22E3ychjM%"

def p(d):
    n = 16 - (len(d) % 16)
    return d + bytes([n] * n)

def u(d):
    x = d[-1]
    return d[:-x] if 1 <= x <= 16 else d

def e(d):
    c = Cp(Al.AES(k), Md.CBC(iv), backend=Bk())
    enc = c.encryptor()
    return enc.update(p(d)) + enc.finalize()

def d(d):
    c = Cp(Al.AES(k), Md.CBC(iv), backend=Bk())
    dec = c.decryptor()
    return u(dec.update(d) + dec.finalize())

def pb(d):
    i, out = 0, {}
    while i < len(d):
        try:
            key, i = _DecodeVarint32(d, i)
        except:
            break
        fn, wt = key >> 3, key & 0x7
        if wt == 0:
            v, i = _DecodeVarint32(d, i)
            out[str(fn)] = {"t": "int", "v": v}
        elif wt == 2:
            ln, i = _DecodeVarint32(d, i)
            v = d[i:i+ln]
            i += ln
            try:
                out[str(fn)] = {"t": "str", "v": v.decode()}
            except:
                out[str(fn)] = {"t": "hex", "v": v.hex()}
        elif wt == 1:
            out[str(fn)] = {"t": "64b", "v": d[i:i+8].hex()}
            i += 8
        elif wt == 5:
            out[str(fn)] = {"t": "32b", "v": d[i:i+4].hex()}
            i += 4
        else:
            break
    return out

def ei(x):
    x = int(x)
    dec = ['80','81','82','83','84','85','86','87','88','89','8a','8b','8c','8d','8e','8f',
           '90','91','92','93','94','95','96','97','98','99','9a','9b','9c','9d','9e','9f',
           'a0','a1','a2','a3','a4','a5','a6','a7','a8','a9','aa','ab','ac','ad','ae','af',
           'b0','b1','b2','b3','b4','b5','b6','b7','b8','b9','ba','bb','bc','bd','be','bf',
           'c0','c1','c2','c3','c4','c5','c6','c7','c8','c9','ca','cb','cc','cd','ce','cf',
           'd0','d1','d2','d3','d4','d5','d6','d7','d8','d9','da','db','dc','dd','de','df',
           'e0','e1','e2','e3','e4','e5','e6','e7','e8','e9','ea','eb','ec','ed','ee','ef',
           'f0','f1','f2','f3','f4','f5','f6','f7','f8','f9','fa','fb','fc','fd','fe','ff']
    xxx = ['1','01','02','03','04','05','06','07','08','09','0a','0b','0c','0d','0e','0f',
           '10','11','12','13','14','15','16','17','18','19','1a','1b','1c','1d','1e','1f',
           '20','21','22','23','24','25','26','27','28','29','2a','2b','2c','2d','2e','2f',
           '30','31','32','33','34','35','36','37','38','39','3a','3b','3c','3d','3e','3f',
           '40','41','42','43','44','45','46','47','48','49','4a','4b','4c','4d','4e','4f',
           '50','51','52','53','54','55','56','57','58','59','5a','5b','5c','5d','5e','5f',
           '60','61','62','63','64','65','66','67','68','69','6a','6b','6c','6d','6e','6f',
           '70','71','72','73','74','75','76','77','78','79','7a','7b','7c','7d','7e','7f']
    x = x / 128
    if x > 128:
        x = x / 128
        if x > 128:
            x = x / 128
            if x > 128:
                x = x / 128
                sx, y = int(x), (x - int(x)) * 128
                sy, z = int(y), (y - int(y)) * 128
                sz, n = int(z), (z - int(z)) * 128
                sn, m = int(n), (n - int(n)) * 128
                return dec[int(m)] + dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]
            else:
                sx, y = int(x), (x - int(x)) * 128
                sy, z = int(y), (y - int(y)) * 128
                sz, n = int(z), (z - int(z)) * 128
                return dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]
    r = bytearray()
    n = int(x)
    while True:
        p = n & 0x7F
        n >>= 7
        if n:
            p |= 0x80
        r.append(p)
        if not n:
            break
    return r.hex()

SRV = "https://clientbp.ggpolarbear.com"

def gt(uid, pw):
    ua = ["GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
          "GarenaMSDK/4.0.18P6(SM-A125F ;Android 11;en;IN;)",
          "GarenaMSDK/4.1.0P3(Redmi 9A ;Android 10;en;ID;)"]
    r = requests.post(
        "https://100067.connect.garena.com/oauth/guest/token/grant",
        headers={"Host": "100067.connect.garena.com",
                 "User-Agent": random.choice(ua),
                 "Content-Type": "application/x-www-form-urlencoded",
                 "Accept-Encoding": "gzip, deflate, br",
                 "Connection": "close"},
        data={"uid": uid, "password": pw, "response_type": "token",
              "client_type": "2",
              "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
              "client_id": "100067"},
        verify=False, timeout=15
    )
    if r.status_code != 200:
        raise Exception(f"garena {r.status_code}")
    d = r.json()
    return d["access_token"], d["open_id"]

def bl(at, oid):
    dT = bytes.fromhex(
        "1a13323032352d30372d33302031343a31313a3230220966726565206669726528013a07"
        "312e3132332e314234416e64726f6964204f53203133202f204150492d33332028545031"
        "412e3232303632342e3031342f3235303531355631393737294a0848616e6468656c6452"
        "094f72616e676520544e5a0457494649609c1368b80872033438307a1d41524d3634204650"
        "204153494d4420414553207c2032303030207c20388001973c8a010c4d616c692d473532"
        "204d433292013e4f70656e474c20455320332e322076312e72333270312d3031656163302e"
        "32613839336330346361303032366332653638303264626537643761663563359a012b476f"
        "6f676c657c61326365613833342d353732362d346235622d383666322d373130356364386666"
        "353530a2010e3139362e3138372e3132382e3334aa0102656eb201203965373166616266343364"
        "383863303662373966353438313034633766636237ba010134c2010848616e6468656c64ca0115"
        "494e46494e495820496e66696e6978205836383336ea014063363231663264363231343330646163"
        "316137383261306461623634653663383061393734613662633732386366326536623132323464313836"
        "633962376166f00101ca02094f72616e676520544ed2020457494649ca03203161633462383065636630"
        "343738613434323033626638666163363132306635e003dc810ee803daa106f003ef068004e7a506"
        "8804dc810e9004e7a5069804dc810ec80403d2045b2f646174612f6170702f7e7e73444e524632"
        "526357313830465a4d66624d5a636b773d3d2f636f6d2e6474732e66726565666972656d61782d"
        "4a534d4f476d33464e59454271535376587767495a413d3d2f6c69622f61726d3634e00402ea047b"
        "61393862306265333734326162303061313966393737633637633031633266617c2f646174612f6170"
        "702f7e7e73444e524632526357313830465a4d66624d5a636b773d3d2f636f6d2e6474732e66726565"
        "666972656d61782d4a534d4f476d33464e59454271535376587767495a413d3d2f626173652e61706b"
        "f00402f804028a050236349a050a32303139313135363537a80503b205094f70656e474c455333b805"
        "ff7fc00504d20506526164c3a873da05023133e005b9f601ea050b616e64726f69645f6d6178f2055c"
        "4b71734854346230414a3777466c617231594d4b693653517a6732726b3665764f38334f306f59306763"
        "635a626457467a785633483564454f586a47704e3967476956774b7533547a312b716a36326546673074"
        "627537664350553d8206147b226375725f72617465223a5b36302c39305d7d880601900601"
        "9a060134a2060134b20600"
    )
    ts = str(datetime.now())[:-7].encode()
    dT = dT.replace(b"2025-07-30 14:11:20", ts)
    dT = dT.replace(b"c621f2d621430dac1a782a0dab64e6c80a974a6bc728cf2e6b1224d186c9b7af", at.encode())
    dT = dT.replace(b"9e71fabf43d88c06b79f548104c7fcb7", oid.encode())
    return e(dT)

def gj(uid, pw):
    at, oid = gt(uid, pw)
    pay = bl(at, oid)
    r = requests.post(
        "https://loginbp.common.ggbluefox.com/MajorLogin",
        headers={
            "Expect": "100-continue",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB53",
            "Authorization": "Bearer ",
            "Host": "loginbp.common.ggbluefox.com",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 13; A063)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip"
        },
        data=pay, verify=False, timeout=20
    )
    if r.status_code != 200:
        raise Exception(f"MajorLogin {r.status_code}")
    x = pb(r.content)
    tok = x.get("8", {}).get("v", "")
    if not tok:
        raise Exception("no token")
    return tok.strip()

def hdr(tok):
    return {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB53",
        "Host": "clientbp.ggpolarbear.com",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
        "User-Agent": "Free%20Fire/2019117061 CFNetwork/1399 Darwin/22.1.0",
        "Connection": "keep-alive",
        "Authorization": f"Bearer {tok}",
        "X-Unity-Version": "2018.4.11f1",
        "Accept": "*/*"
    }

def af(jwt, to):
    raw = "08c8b5cfea1810" + ei(to) + "18012008"
    data = bytes.fromhex(e(bytes.fromhex(raw)).hex())
    r = requests.post(f"{SRV}/RequestAddingFriend", headers=hdr(jwt), data=data, verify=False, timeout=2)
    return r.status_code

with open("accs.json") as f:
    accs = json.load(f)

active = {}
tokens = {}

def spam(tgt):
    ev = active[tgt]
    while not ev.is_set():
        for a in accs:
            if ev.is_set():
                break
            uid = a["uid"]
            pw = a["Pw"]
            try:
                if uid not in tokens:
                    tokens[uid] = gj(uid, pw)
                jwt = tokens[uid]
                af(jwt, tgt)
            except:
                if uid in tokens:
                    del tokens[uid]
        time.sleep(0.01)
    del active[tgt]

app = Flask(__name__)

@app.get("/spam")
def start():
    uid = request.args.get("user_id", "").strip()
    if not uid:
        return jsonify({"ok": False, "err": "uid required"}), 400
    if uid in active:
        return jsonify({"ok": True, "msg": "already spamming"})
    ev = threading.Event()
    active[uid] = ev
    threading.Thread(target=spam, args=(uid,), daemon=True).start()
    return jsonify({"ok": True, "msg": "success"})

@app.get("/stop")
def stop():
    uid = request.args.get("uid", "").strip()
    if not uid:
        return jsonify({"ok": False, "err": "uid required"}), 400
    if uid in active:
        active[uid].set()
        return jsonify({"ok": True, "msg": "stopping"})
    return jsonify({"ok": False, "msg": "not spamming"})

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
