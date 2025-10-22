using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

class Program
{
    static async Task Main(string[] args)
    {
        // خواندن توکن از فایل
        string token = System.IO.File.ReadAllText("../token.txt").Trim();

        using var listener = new HttpListener();
        listener.Prefixes.Add("http://localhost:8080/");
        listener.Start();
        Console.WriteLine("Listening on http://localhost:8080/");

        while (true)
        {
            var context = await listener.GetContextAsync();
            _ = Task.Run(() => ProcessRequest(context, token));
        }
    }

    static async Task ProcessRequest(HttpListenerContext context, string token)
    {
        var request = context.Request;
        var response = context.Response;

        // تنظیم هدرهای CORS
        response.Headers.Add("Access-Control-Allow-Origin", "*");
        response.Headers.Add("Access-Control-Allow-Methods", "POST, OPTIONS");
        response.Headers.Add("Access-Control-Allow-Headers", "Content-Type");
        response.Headers.Add("Content-Type", "application/json; charset=utf-8");

        // هندل کردن درخواست OPTIONS برای CORS
        if (request.HttpMethod == "OPTIONS")
        {
            response.StatusCode = 200;
            response.Close();
            return;
        }

        // دریافت داده‌های JSON از درخواست
        using var reader = new System.IO.StreamReader(request.InputStream);
        string body = await reader.ReadToEndAsync();

        var json = JsonSerializer.Deserialize<Dictionary<string, string>>(body);

        // بررسی وجود initData
        if (!json.TryGetValue("initData", out string initDataString) || string.IsNullOrEmpty(initDataString))
        {
            SendJson(response, new { status = "error", message = "داده‌ای دریافت نشد" });
            return;
        }

        // مرحله 1: تجزیه رشته initData به یک دیکشنری و جداسازی hash
        var webAppData = ParseQueryString(initDataString);
        if (!webAppData.TryGetValue("hash", out string receivedHash))
        {
            SendJson(response, new { status = "error", message = "hash یافت نشد" });
            return;
        }
        webAppData.Remove("hash");

        // مرحله 2: مرتب‌سازی کلیدها به ترتیب الفبایی و ایجاد رشته داده
        var keyValues = webAppData
            .Select(kv => $"{kv.Key}={kv.Value}")
            .OrderBy(s => s, StringComparer.Ordinal)
            .ToList();

        // مرحله 3: ایجاد رشته joined_pairs
        string dataCheckString = string.Join("\n", keyValues);

        // مرحله 4: ایجاد secret_key با HMAC-SHA256
        byte[] secretKey;
        using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes("WebAppData")))
        {
            secretKey = hmac.ComputeHash(Encoding.UTF8.GetBytes(token));
        }

        // مرحله 5: ایجاد calculatedHash محاسبه شده با HMAC-SHA256
        string calculatedHash;
        using (var hmac = new HMACSHA256(secretKey))
        {
            byte[] hashBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(dataCheckString));
            calculatedHash = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
        }

        // مرحله 6: مقایسه hash دریافتی با hash محاسبه شده
        if (SecureCompare(calculatedHash, receivedHash))
        {
            // استخراج اطلاعات کاربر
            var userData = new Dictionary<string, object>();
            
            if (webAppData.TryGetValue("user", out string userJson))
            {
                var user = JsonSerializer.Deserialize<Dictionary<string, object>>(WebUtility.UrlDecode(userJson));
                userData["id"] = user.GetValueOrDefault("id");
                userData["first_name"] = user.GetValueOrDefault("first_name");
                userData["last_name"] = user.GetValueOrDefault("last_name");
                userData["language_code"] = user.GetValueOrDefault("language_code");
                userData["allows_write_to_pm"] = user.GetValueOrDefault("allows_write_to_pm") ?? false;
            }

            SendJson(response, new
            {
                status = "success",
                message = "داده‌ها معتبر هستند",
                user = userData
            });
        }
        else
        {
            SendJson(response, new { status = "error", message = "داده‌ها نامعتبر هستند" });
        }
    }

    // تابع برای تجزیه رشته query string به دیکشنری
    static Dictionary<string, string> ParseQueryString(string query)
    {
        return query.Split('&')
            .Select(part => part.Split('='))
            .Where(kv => kv.Length == 2)
            .ToDictionary(
                kv => WebUtility.UrlDecode(kv[0]),
                kv => WebUtility.UrlDecode(kv[1])
            );
    }

    // تابع برای مقایسه امن هش‌ها (معادل hash_equals در PHP)
    static bool SecureCompare(string a, string b)
    {
        if (a.Length != b.Length) return false;
        int result = 0;
        for (int i = 0; i < a.Length; i++)
        {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    // تابع برای ارسال پاسخ JSON
    static void SendJson(HttpListenerResponse response, object obj)
    {
        string json = JsonSerializer.Serialize(obj, new JsonSerializerOptions { WriteIndented = true });
        byte[] buffer = Encoding.UTF8.GetBytes(json);
        response.ContentLength64 = buffer.Length;
        response.OutputStream.Write(buffer, 0, buffer.Length);
        response.Close();
    }
}