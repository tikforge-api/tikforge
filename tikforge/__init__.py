#by hdo
import requests
import uuid
import time
import random
import base64
import hashlib
import secrets
from random import choice,randint,randrange
import string,json
import re
from os import urandom
import binascii
from urllib.parse import urlencode
from hsopyt import Argus, Ladon, Gorgon, md5
import datetime

class GMAIL:
    @staticmethod
    def CheckEmail(email):
        if '@' in email:
            email = email.split('@')[0]
        if '..' in email or '_' in email or len(email) < 5 or len(email) > 30:
            return False
        
        try:    
            name = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for i in range(random.randrange(5,10)))
            birthday = random.randrange(1980,2010),random.randrange(1,12),random.randrange(1,28)
            s = requests.Session()
        
            headers = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'accept-language': 'en-US,en;q=0.9',
                'referer': 'https://accounts.google.com/',
                'upgrade-insecure-requests': '1',
                'user-agent': 'Mozilla/5.0 (Linux; Android 13; SM-G981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36',
                'x-browser-channel': 'stable',
                'x-browser-copyright': 'Copyright 2024 Google LLC. All rights reserved.',
                'x-browser-year': '2024',
            }
        
            params = {
                'biz': 'false',
                'continue': 'https://mail.google.com/mail/u/0/',
                'ddm': '1',
                'emr': '1',
                'flowEntry': 'SignUp',
                'flowName': 'GlifWebSignIn',
                'followup': 'https://mail.google.com/mail/u/0/',
                'osid': '1',
                'service': 'mail',
            }
        
            response = s.get('https://accounts.google.com/lifecycle/flows/signup', params=params, headers=headers)
            tl=response.url.split('TL=')[1]
            s1= response.text.split('"Qzxixc":"')[1].split('"')[0]
            at = response.text.split('"SNlM0e":"')[1].split('"')[0]
            headers = {
                'accept': '*/*',
                'accept-language': 'en-US,en;q=0.9',
                'content-type': 'application/x-www-form-urlencoded;charset=UTF-8',
                'origin': 'https://accounts.google.com',
                'referer': 'https://accounts.google.com/',
                'user-agent': 'Mozilla/5.0 (Linux; Android 13; SM-G981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36',
                'x-goog-ext-278367001-jspb': '["GlifWebSignIn"]',
                'x-goog-ext-391502476-jspb': '["'+s1+'"]',
                'x-same-domain': '1',
            }
        
            params = {
                'rpcids': 'E815hb',
                'source-path': '/lifecycle/steps/signup/name',
                'hl': 'en-US',
                'TL': tl,
                'rt': 'c',
            }
        
            data = 'f.req=%5B%5B%5B%22E815hb%22%2C%22%5B%5C%22{}%5C%22%2C%5C%22%5C%22%2Cnull%2Cnull%2Cnull%2C%5B%5D%2C%5B%5C%22https%3A%2F%2Fmail.google.com%2Fmail%2Fu%2F0%2F%5C%22%2C%5C%22mail%5C%22%5D%2C1%5D%22%2Cnull%2C%22generic%22%5D%5D%5D&at={}&'.format(name,at)
        
            response = s.post(
                'https://accounts.google.com/lifecycle/_/AccountLifecyclePlatformSignupUi/data/batchexecute',
                params=params,
                headers=headers,
                data=data,
            ).text
        
            headers = {
                'accept': '*/*',
                'accept-language': 'en-US,en;q=0.9',
                'content-type': 'application/x-www-form-urlencoded;charset=UTF-8',
                'origin': 'https://accounts.google.com',
                'referer': 'https://accounts.google.com/',
                'user-agent': 'Mozilla/5.0 (Linux; Android 13; SM-G981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36',
                'x-goog-ext-278367001-jspb': '["GlifWebSignIn"]',
                'x-goog-ext-391502476-jspb': '["'+s1+'"]',
                'x-same-domain': '1',
            }
        
            params = {
                'rpcids': 'eOY7Bb',
                'source-path': '/lifecycle/steps/signup/birthdaygender',
                'hl': 'en-US',
                'TL': tl,
                'rt': 'c',
            }
        
            data = 'f.req=%5B%5B%5B%22eOY7Bb%22%2C%22%5B%5B{}%2C{}%2C{}%5D%2C1%2Cnull%2Cnull%2Cnull%2C%5C%22%3Cf7Nqs-sCAAZfiOnPf4iN_32KOpLfQKL0ADQBEArZ1IBDTUyai2FYax3ViMI2wqBpWShhe-OPRhpMjnm9s14Yu65MknXEBWcyTyF3Jx0pzQAAAeGdAAAAC6cBB7EATZAxrowFF7vQ68oKqx7_sdcR_u8t8CJys-8G4opCIVySwUYaUnm-BovA8aThYLISPNMc8Pl3_B0GnkQJ_W4SIed6l6EcM7QLJ8AXVNAaVgbhsnD7q4lyQnlvR14HRW10oP85EU_bwG1E4QJH1V0KnVS4mIeoqB7zHOuxMuGifv6MB3GghUGTewh0tMN1jaf8yvX804tntlrlxm3OZgCZ2UxgDjUVOKFMv1Y3Txr16jJEJ56-T7qrPCtt6H1kmUvCIl_RDZzbt_sj5OLnbX1UvVA-VgG8-X9AJdvGhCKVhkf3iSkjy6_ZKsZSbsOsMjrm7ggnLdMStIf4AzbJIyMC7q4JMCaDaW_UI9SgquR8mHMpHGRmP7zY-WE47l7uRSpkI6oV93XJZ1zskJsxaDz7sDYHpzEL1RGPnkZU45XkIkwuc1ptU_AiM6SQyoZK7wFnhYxYfDQjSwaC7lOfngr6F2e4pDWkiC96QY4xLr6m2oUoDbyKR3ykccKEECEakFKzS-wSxIt9hK6nw-a9PEpVzhf6uIywZofNCs0KJOhhtv_ReG24DOC6NHX-FweCOkiYtT2sISrm6H8Wr4E89oU_mMWtpnXmhs8PB28SXw42-EdhRPsdcQkgKycOVT_IXwCc4Td9-t7715HP-L2XLk5i05aUrk-sHPPEz8SyL3odOb1SkwQ69bRQHfbPZr858iTDD0UaYWE_Jmb4wlGxYOSsvQ3EIljWDtj69cq3slKqMQu0ZC9bdqEh0p_T9zvsVwFiZThf19JL8PtqlXH5bgoEnPqdSfYbnJviQdUTAhuBPE-O8wgmdwl22wqkndacytncjwGR9cuXqAXUk_PbS-0fJGxIwI6-b7bhD7tS2DUAJk708UK5zFDLyqN6hFtj8AAjNM-XGIEqgTavCRhPnVT0u0l7p3iwtwKmRyAn42m3SwWhOQ6LDv-K2DyLl2OKfFu9Y-fPBh-2K2hIn2tKoGMgVbBR8AsVsYL7L6Bh5JIW7LCHaXNk3oDyHDx5QFaPtMmnIxcfFG90YSEPIgWV2nb67zDDacvvCkiPEQMXHJUcz1tuivaAgCTgW68wNYkUt89KJDhJTSWY2jcPsDIyCnS-SGESyR7mvbkvC3Robo0zVQm6q3Z73si9uqJiPmUGgBLycxUq2A_L3B-Hz35vBm5Oc5Hbe8hJToB03ilQzLa8Kld5BY8_kmmh6kfrOvi07uwfusHv3mKfijE2vaK3v2O2He41hCaOv3ExSfdPKb2V5nPPTw8ryyC5ZwlM_DLCU_k5xONsh4uplpRmydmJcit4aj5Ig0qLVF9MxIWU5xoDlvhKL9jHh-HVgIe-CPp4RMM5BfTxDgtESiF97RWjwrNeKn6Fc4311AdCrfZMcZ0F2JnQsfKAz4H-hoWbrOEVBkPcBt5umJ_iaCm0cQ2XTQMjzAtfWbRe6EGSxbkK-DXBl4EQM-6cnH1139MIHLzNou_Tltbl2HaomCS044CwhRNpe95KuYhM4Fz0Z_8rRjqy48tS_L4kQMX1CtxjBNfd4eUoaAIwAcz3LaL5BwL0DAYcV3xruTTuy6X8zFHe8fAIB9pJ_Pw0YJm3Ye28_tTg5xk0R4EU7_IPIHk6RrtSsG0Rfst3Qi5NRfWFg5h9LlmlHO_EUhdw1wbCICTqbS2A94aIBSCQzn7RmqOTTSIXwgFwnSBRKvoo0v9tKQ2rnMZsXRhzQgxwfmYOq29EUbuHmmWQjpRhfzX1Z6-5gXRPr4-PjrInsTiAi36xDyc8a1yTAhKMwnvf3GNqcK8lqx80VCASvcpYxGIAFl4QghroZbIJXlhccCWVF_xrzsw83QUdoZ5ExWi5f_cLvEXeZssdtan1orOaPJuWXT_0ryzpS9fOGtT68pL4HMAPLPpfwhiZ-wtZQU0oVy6T2L6oP1SIHQDU_QDaMR0MkStXNDj69r5cTDdYZiIbFkvWYeL1afTEljx1i2n2KKnDmpJfx2HeGCSZBMKZey24z_LDLA7MyJ2VBo4Zvmm23dwhWHOly56w9ul4sWzpHqgsqmKynRoaq9SXKrrmbR3f2GKBHSvy3Jm0Ln52zwIQfFSXpOjGXq5pkOXlvQc6MPuV3zADVmcUZs6ywI-ER3PkAaA-f-zG-ke_6jvOzGp6WF8UxnIk5tq3tus_R5pUjVQFjk6qZtWOP8VZd1TeJ54Oo_ywj8YAYCphkDtFYRMZSubmnI-F9LLlAfOiDwQ7r-iNvp8psduy9xrWdIpE_l23Y_qYJPHwvtopL3lB7juqEiFkhUts7NEugyWY-m6-9oEgsOY0lM4746V-XUxSeS7UkZkQZZM19g7GkWjJ61D98i0m2u_UYLnyDFQEaIxVhFcmS1Zq7OMsKm_gYpMt4LuD1F3N__Vj05QNyI59QNQADODveiHpfVva9Cd2AzBm9AKGwU4xDS_FyX3XRsRbfQFtqNzPf1LAERHlnHFn%5C%22%2C%5Bnull%2Cnull%2C%5C%22https%3A%2F%2Fmail.google.com%2Fmail%2Fu%2F0%2F%5C%22%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2C%5C%22mail%5C%22%5D%5D%22%2Cnull%2C%22generic%22%5D%5D%5D&at={}&'.format(birthday[0],birthday[1],birthday[2],at)
        
            response = s.post(
                'https://accounts.google.com/lifecycle/_/AccountLifecyclePlatformSignupUi/data/batchexecute',
                params=params,
                headers=headers,
                data=data,
            ).text
        
            headers = {
                'accept': '*/*',
                'accept-language': 'en-US,en;q=0.9',
                'content-type': 'application/x-www-form-urlencoded;charset=UTF-8',
                'origin': 'https://accounts.google.com',
                'referer': 'https://accounts.google.com/',
                'user-agent': 'Mozilla/5.0 (Linux; Android 13; SM-G981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36',
                'x-goog-ext-278367001-jspb': '["GlifWebSignIn"]',
                'x-goog-ext-391502476-jspb': '["'+s1+'"]',
                'x-same-domain': '1',
            }
        
            params = {
                'rpcids': 'NHJMOd',
                'source-path': '/lifecycle/steps/signup/username',
                'hl': 'en-US',
                'TL': tl,
                'rt': 'c',
            }
        
            data = 'f.req=%5B%5B%5B%22NHJMOd%22%2C%22%5B%5C%22{}%5C%22%2C0%2C0%2Cnull%2C%5Bnull%2Cnull%2Cnull%2Cnull%2C1%2C152855%5D%2C0%2C40%5D%22%2Cnull%2C%22generic%22%5D%5D%5D&at={}&'.format(email,at)
        
            response = s.post('https://accounts.google.com/lifecycle/_/AccountLifecyclePlatformSignupUi/data/batchexecute',
                params=params,
                headers=headers,
                data=data,
            ).text
        
            if "password" in response:
                return {"data":{"status":True,"email":email,"error_code":0,"programmer":"@is71s"}}        
            else:
                return {"data":{"status":False,"email":email,"error_code":1,"programmer":"@is71s"}}
        
        except Exception as e:
            return {"data":{"status":False,"error":str(e),"programmer":"@is71s"}}


class TIKTOK:
    @staticmethod
    def sign(params: str, payload: str or None = None, sec_device_id: str = '',
              cookie: str or None = None, aid: int = 1233, license_id: int = 1611921764,
              sdk_version_str: str = 'v05.00.06-ov-android', sdk_version: int = 167775296,
              platform: int = 0, unix: float = None):
        
        x_ss_stub = md5(payload.encode('utf-8')).hexdigest() if payload != None else None
        if not unix:
            unix = time.time()

        return Gorgon(params, unix, payload, cookie).get_value() | {
            'content-length': str(len(payload)),
            'x-ss-stub': x_ss_stub.upper(),
            'x-ladon': Ladon.encrypt(int(unix), license_id, aid),
            'x-argus': Argus.get_sign(
                params, x_ss_stub, int(unix),
                platform=platform,
                aid=aid,
                license_id=license_id,
                sec_device_id=sec_device_id,
                sdk_version=sdk_version_str,
                sdk_version_int=sdk_version
            )
        }





import random
import requests

DEVICES_URL = "https://raw.githubusercontent.com/tikforge-api/tikforge/refs/heads/main/tikforge/devices.txt"

def load_device():
    try:
        r = requests.get(DEVICES_URL, timeout=10)
        r.raise_for_status()
        devices = r.text.strip().splitlines()
    except Exception as e:
        raise RuntimeError(f"Failed to load devices list: {e}")

    if not devices:
        raise RuntimeError("Devices list is empty")

    devicee = random.choice(devices)
    parts = devicee.split(":")

    if len(parts) < 6:
        raise ValueError("Invalid device format")

    iid = parts[0]
    did = parts[1]
    device_type = parts[2]
    device_brand = parts[3]
    openudid = parts[4]
    cdid = parts[5]

    os_version = f"{random.randint(7, 13)}.{random.randint(0, 5)}"

    return iid, did, device_type, device_brand, os_version, openudid, cdid

def CheckTikTok(email, sessionid):
    iid, did, device_type, device_brand, os_version, openudid, cdid = load_device()

    url = "https://api22-normal-c-alisg.tiktokv.com/passport/email/bind_without_verify/"

    params = {
        "passport-sdk-version": "19",
        "iid": iid,
        "device_id": did,
        "ac": "mobile",
        "ac2": "mobile",
        "channel": "googleplay",
        "aid": "1233",
        "app_name": "musical_ly",
        "version_code": "310503",
        "version_name": "31.5.3",
        "ab_version": "31.5.3",
        "build_number": "31.5.3",
        "app_version": "31.5.3",
        "manifest_version_code": "2023105030",
        "update_version_code": "2023105030",
        "device_platform": "android",
        "os": "android",
        "os_api": "28",
        "os_version": "9",
        "device_type": device_type,
        "device_brand": device_brand,
        "host_abi": "arm64-v8a",
        "resolution": "900*1600",
        "dpi": "240",
        "openudid": openudid,
        "language": "en",
        "app_language": "en",
        "locale": "en-GB",
        "content_language": "en,",
        "region": "GB",
        "sys_region": "US",
        "current_region": "TW",
        "op_region": "TW",
        "carrier_region": "TW",
        "carrier_region_v2": "466",
        "residence": "TW",
        "mcc_mnc": "46692",
        "timezone_name": "Asia/Baghdad",
        "timezone_offset": "10800",
        "_rticket": int(time.time() * 1000),
        "ts": int(time.time()),
        "app_type": "normal",
        "is_pad": "0",
        "uoo": "0",
        "support_webview": "1",
        "cronet_version": "2fdb62f9_2023-09-06",
        "ttnet_version": "4.2.152.11-tiktok",
        "use_store_region_cookie": "1",
        "cdid": cdid,
    }

    payload = {
        "account_sdk_source": "app",
        "multi_login": "1",
        "email_source": "9",
        "email": email,
        "mix_mode": "1"
    }

    headers = {
        "user-agent": f"com.zhiliaoapp.musically/310905 (Linux; U; Android {os_version}; en_ma; {device_type}; Build/RP1A.200720.012;tt-ok/3.12.13.4-tiktok)",
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
        "cookie": f"sessionid={sessionid}",
        "sdk-version": "2",
        "passport-sdk-version": "19",
        "x-ss-dp": "1233",
    }

    sec_device_id = "AadCFwpTyztA5j9L" + "".join(
        secrets.choice(string.ascii_letters + string.digits) for _ in range(9)
    )

    headers.update(
        TIKTOK.sign(urlencode(params), urlencode(payload), sec_device_id, None, 1233)
    )

    try:
        res = requests.post(url, params=params, data=payload, headers=headers, timeout=15)
        response_json = res.json()

        data = response_json.get("data", {})
        errur_code = data.get("error_code")
        description = data.get("description", "No description")

        if errur_code is None:
            return {
                "data": {
                    "status": "Unknown response",
                    "raw": response_json,
                    "programmer": "@is71s"
                }
            }

        errur_code = int(errur_code)

        return {
            "data": {
                "status": description,
                "error_code": errur_code,
                "programmer": "@is71s"
            }
        }

    except Exception as e:
        return {
            "data": {
                "status": f"Error {e}",
                "programmer": "@is71s"
            }
    }

class TIKTOK_INFO_V2:
    @staticmethod
    def info(user):

        try:
            url = f"https://www.tiktok.com/@{user}"
            headers = {
                'User-Agent': "com.zhiliaoapp.musically/2023605050 (Linux; U; Android 14; ar; SM-S928B; Build/UP1A.231005.007; Cronet/TTNetVersion:1c651b66 2024-08-30 QuicVersion:182d68c8 2024-05-28)",
                'Accept': "application/json, text/plain, */*",
                'x-tt-passport-csrf-token': secrets.token_hex(16),
                'content-type': "application/x-www-form-urlencoded",
            }
            
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            html = response.text    

            m = re.search(r'<script id="__UNIVERSAL_DATA_FOR_REHYDRATION__" type="application/json">(.*?)</script>', html)    
            if not m:
                m = re.search(r'({"__DEFAULT_SCOPE__":.*})</script>', html)   
            
            if not m:
                return {"data": {"status": False, "message": "No user data found", "programmer": "@is71s"}}
            
            data = json.loads(m.group(1))
            
            try:
                user_data = data["__DEFAULT_SCOPE__"]["webapp.user-detail"]["userInfo"]
            except KeyError:
                try:
                    user_data = data["__DEFAULT_SCOPE__"]["webapp.video-detail"]["userInfo"]
                except KeyError:
                    try:
                        for key in data.keys():
                            if "webapp.user-detail" in str(data[key]):
                                user_data = data[key]["webapp.user-detail"]["userInfo"]
                                break
                        else:
                            raise KeyError("User data not found in expected paths")
                    except:
                        return {"data": {"status": False, "message": "Could not parse user data", "programmer": "@is71s"}}
            
            u = user_data["user"]
            st = user_data["stats"]
            region = u.get('region', '')
           
            if region:
                flag = ''.join(chr(0x1F1E6 + ord(c) - ord('A')) for c in region.upper())
            else:
                flag = ''
            create_time = u.get("createTime", 0)
            if create_time:
                created_date = datetime.datetime.utcfromtimestamp(create_time).strftime("%Y/%m/%d")
            else:
                created_date = "N/A"            
            info = {
                "status": True,
                "username": user,
                "name": u.get("nickname", ""),
                "id": u.get('id', ''),
                "followers": st.get("followerCount", 0),
                "following": st.get("followingCount", 0),
                "likes": st.get("heartCount", 0),
                "videos": st.get("videoCount", 0),
                "created": created_date,
                'privateAccount': u.get('privateAccount', False),
                "region": region,
                "flag": flag,
                "programmer": "@is71s"
            }            
            return {"data": info}            
        except requests.RequestException as e:
            return {"data": {"status": False, "message": f"Network error: {str(e)}", "programmer": "@is71s"}}
        except json.JSONDecodeError as e:
            return {"data": {"status": False, "message": f"JSON parsing error: {str(e)}", "programmer": "@is71s"}}
        except Exception as e:
            return {"data": {"status": False, "message": f"Unexpected error: {str(e)}", "programmer": "@is71s"}}
  
