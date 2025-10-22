from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import json
import hmac
import hashlib
import urllib.parse
from urllib.parse import parse_qs

# مدل برای داده‌های ورودی
class VerifyRequest(BaseModel):
    initData: str

# خواندن توکن از فایل
with open('../token.txt', 'r') as f:
    token = f.read().strip()

app = FastAPI(title="Eitaa Web App Validator")

# تنظیم CORS برای اجازه دسترسی از همه دامنه‌ها
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def handle_request(input_data):
    # بررسی وجود initData
    if 'initData' not in input_data or not input_data['initData']:
        return {
            'status': 'error',
            'message': 'داده‌ای دریافت نشد'
        }
    
    init_data_string = input_data['initData']
    
    # مرحله 1: تجزیه رشته initData به یک دیکشنری و جداسازی hash
    parsed_data = parse_qs(init_data_string)
    web_app_data = {}
    
    for key, values in parsed_data.items():
        web_app_data[key] = values[0] if values else ''
    
    received_hash = web_app_data.get('hash', '')
    if 'hash' in web_app_data:
        del web_app_data['hash']
    
    # مرحله 2: مرتب‌سازی کلیدها به ترتیب الفبایی و ایجاد رشته داده
    key_values = []
    for key, value in web_app_data.items():
        key_values.append(f"{key}={value}")
    key_values.sort()
    
    # مرحله 3: ایجاد رشته joined_pairs
    data_check_string = "\n".join(key_values)
    
    # مرحله 4: ایجاد secret_key با HMAC-SHA256
    secret_key = hmac.new(
        "WebAppData".encode(), 
        token.encode(), 
        hashlib.sha256
    ).digest()
    
    # مرحله 5: ایجاد calculated_hash محاسبه شده با HMAC-SHA256
    calculated_hash = hmac.new(
        secret_key, 
        data_check_string.encode(), 
        hashlib.sha256
    ).hexdigest()
    
    # مرحله 6: مقایسه hash دریافتی با hash محاسبه شده
    if hmac.compare_digest(calculated_hash, received_hash):
        # استخراج اطلاعات کاربر
        user_data = {}
        
        if 'user' in web_app_data:
            user_json = urllib.parse.unquote(web_app_data['user'])
            user = json.loads(user_json)
            user_data = {
                'id': user.get('id'),
                'first_name': user.get('first_name'),
                'last_name': user.get('last_name'),
                'language_code': user.get('language_code'),
                'allows_write_to_pm': user.get('allows_write_to_pm', False)
            }
        
        return {
            'status': 'success',
            'message': 'داده‌ها معتبر هستند',
            'user': user_data
        }
    else:
        return {
            'status': 'error',
            'message': 'داده‌ها نامعتبر هستند'
        }



@app.post("/")
async def verify(request: VerifyRequest):
    """
    اعتبارسنجی داده‌های Eitaa Web App
    """
    try:
        result = handle_request({"initData": request.initData})
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"خطای سرور: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)