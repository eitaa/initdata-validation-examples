<?php

// خواندن توکن از فایل
$token = trim(file_get_contents('../token.txt'));

// دریافت داده‌های JSON از درخواست
$input = file_get_contents('php://input');
$data = json_decode($input, true);

// بررسی وجود initData
if (empty($data['initData'])) {
    echo json_encode([
        'status' => 'error',
        'message' => 'داده‌ای دریافت نشد'
    ]);
    exit;
}

$initDataString = $data['initData'];

// مرحله 1: تجزیه رشته initData به یک آرایه از رشته‌ها و جداسازی hash
parse_str($initDataString, $webAppData);
$receivedHash = $webAppData['hash'] ?? '';
unset($webAppData['hash']);

// مرحله 2: مرتب‌سازی کلیدها به ترتیب الفبایی و ایجاد رشته داده
$keyValues = [];
foreach ($webAppData as $key => $value) {
    $keyValues[] = $key . "=" . $value;
}
sort($keyValues);

// مرحله 3: ایجاد رشته joined_pairs
$data_check_string = implode("\n", $keyValues);

// مرحله 4: ایجاد secret_key با HMAC-SHA256
$secret_key = hash_hmac('sha256', $token, "WebAppData", true);

// مرحله 5: ایجاد calculatedHash محاسبه شده با HMAC-SHA256
$calculatedHash = bin2hex(hash_hmac('sha256', $data_check_string, $secret_key, true));

// مرحله 6: مقایسه hash دریافتی با hash محاسبه شده
if (hash_equals($calculatedHash, $receivedHash)) {
    // استخراج اطلاعات کاربر
    $userData = [];
    
    if (isset($webAppData['user'])) {
        $user = json_decode(urldecode($webAppData['user']), true);
        $userData = [
            'id' => $user['id'] ?? null,
            'first_name' => $user['first_name'] ?? null,
            'last_name' => $user['last_name'] ?? null,
            'language_code' => $user['language_code'] ?? null,
            'allows_write_to_pm' => $user['allows_write_to_pm'] ?? false
        ];
    }
    
    echo json_encode([
        'status' => 'success',
        'message' => 'داده‌ها معتبر هستند',
        'user' => $userData
    ]);
} else {
    echo json_encode([
        'status' => 'error',
        'message' => 'داده‌ها نامعتبر هستند'
    ]);
}
?>