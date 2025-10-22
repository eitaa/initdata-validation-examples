package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
)

// یک middleware برای اضافه کردن هدرهای CORS
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// اجازه دسترسی از همه دامنه‌ها
		w.Header().Set("Access-Control-Allow-Origin", "*")
		// هدرهایی که مجاز هستند
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		// متدهای مجاز
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")

		// اگر درخواست OPTIONS بود، همینجا جواب بده
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		// ادامه‌ی هندلر اصلی
		next.ServeHTTP(w, r)
	})
}

func main() {
	// خواندن توکن از فایل
	tokenBytes, err := ioutil.ReadFile("../token.txt")
	if err != nil {
		panic("خطا در خواندن فایل توکن: " + err.Error())
	}
	token := strings.TrimSpace(string(tokenBytes))

	// تعریف هندلر اصلی
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// دریافت داده‌های JSON از درخواست
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "خطا در خواندن داده‌ها", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		var data map[string]string
		if err := json.Unmarshal(body, &data); err != nil {
			http.Error(w, "JSON نامعتبر است", http.StatusBadRequest)
			return
		}

		// بررسی وجود initData
		initDataString, ok := data["initData"]
		if !ok || initDataString == "" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "error",
				"message": "داده‌ای دریافت نشد",
			})
			return
		}

		// مرحله 1: تجزیه رشته initData به یک آرایه از رشته‌ها و جداسازی hash
		webAppData, err := url.ParseQuery(initDataString)
		if err != nil {
			http.Error(w, "initData نامعتبر است", http.StatusBadRequest)
			return
		}
		receivedHash := webAppData.Get("hash")
		webAppData.Del("hash")

		// مرحله 2: مرتب‌سازی کلیدها به ترتیب الفبایی و ایجاد رشته داده
		var keyValues []string
		for key := range webAppData {
			keyValues = append(keyValues, key+"="+webAppData.Get(key))
		}
		sort.Strings(keyValues)

		// مرحله 3: ایجاد رشته joined_pairs
		dataCheckString := strings.Join(keyValues, "\n")

		// مرحله 4: ایجاد secret_key با HMAC-SHA256
		h := hmac.New(sha256.New, []byte("WebAppData"))
		h.Write([]byte(token))
		secretKey := h.Sum(nil)

		// مرحله 5: ایجاد calculatedHash محاسبه شده با HMAC-SHA256
		h2 := hmac.New(sha256.New, secretKey)
		h2.Write([]byte(dataCheckString))
		calculatedHash := hex.EncodeToString(h2.Sum(nil))

		// مرحله 6: مقایسه hash دریافتی با hash محاسبه شده
		if hmac.Equal([]byte(calculatedHash), []byte(receivedHash)) {
			// استخراج اطلاعات کاربر
			userData := map[string]interface{}{}
			if userStr := webAppData.Get("user"); userStr != "" {
				decoded, _ := url.QueryUnescape(userStr)
				var user map[string]interface{}
				if err := json.Unmarshal([]byte(decoded), &user); err == nil {
					userData["id"] = user["id"]
					userData["first_name"] = user["first_name"]
					userData["last_name"] = user["last_name"]
					userData["language_code"] = user["language_code"]
					userData["allows_write_to_pm"] = user["allows_write_to_pm"]
				}
			}

			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "success",
				"message": "داده‌ها معتبر هستند",
				"user":    userData,
			})
		} else {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "error",
				"message": "داده‌ها نامعتبر هستند",
			})
		}
	})

	// اجرای سرور با middleware CORS
	fmt.Println("Server is running on port 8080...")
	if err := http.ListenAndServe(":8080", withCORS(handler)); err != nil {
		os.Exit(1)
	}
}