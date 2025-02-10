
import re

SENSITIVE_PATTERNS = {
    # Cryptographic Issues
    "Private Key": re.compile(r'(?i)private\s+key'),
    "ECBCipherCheck": re.compile(r'(?i)Cipher\.getInstance\("AES/ECB'),
    "RSACipherCheck": re.compile(r'(?i)Cipher\.getInstance\("RSA"'),
    "SecureRandomSeed": re.compile(r'(?i)new SecureRandom\(.*\)'),
    
    # Logging & Debugging Issues
    "Debug Logging": re.compile(r'(?i)log\.(d|v|i|w|e)'),
    "Debugging Tags": re.compile(r'(?i)android:debuggable="true"'),
    "Exception Handling": re.compile(r'(?i)try\s*{.*}\s*catch'),
    
    # Data Leakage & Hardcoded Secrets
    "API Keys": re.compile(r'(?i)(api[_]?key|auth[_]?token|access[_]?token)[\s:=]'),
    "Hardcoded HTTP URL": re.compile(r'(?i)http://'),
    "Hardcoded Information": re.compile(r'(?i)(password|secret|key|token)[\s:=]'),
    
    # Insecure Storage & Permissions
    "External Storage": re.compile(r'(?i)Environment\.getExternalStorageDirectory\(\)'),
    "Global File Permissions": re.compile(r'(?i)setPermissions\(.*MODE_WORLD_READABLE|MODE_WORLD_WRITABLE'),
    "File Permissions": re.compile(r'(?i)setReadable\(true,\s*false\)|setWritable\(true,\s*false\)'),
    "SharedPreferences Security": re.compile(r'(?i)getSharedPreferences\(.*MODE_WORLD_READABLE|MODE_WORLD_WRITABLE'),
    
    # WebView & URL Handling Issues
    "WebView Security": re.compile(r'(?i)addJavascriptInterface|setJavaScriptEnabled|loadDataWithBaseURL|setWebContentsDebuggingEnabled|setAllowContentAccess|setAllowFileAccess|setDomStorageEnabled|setAllowUniversalAccessFromFileURLs'),
    "Custom URL Schemes": re.compile(r'(?i)intent-filter.*data.*scheme'),
    # "Implicit Intents": re.compile(r'(?i)startActivity\(new Intent\(\))'),
    
    # Broadcast & Intent Security Issues
    "Broadcast Security": re.compile(r'(?i)sendBroadcast|sendBroadcastAsUser|sendOrderedBroadcast|sendOrderedBroadcastAsUser|sendStickyBroadcast|sendStickyBroadcastAsUser|sendStickyOrderedBroadcast|sendStickyOrderedBroadcastAsUser'),
    "Pending Intents": re.compile(r'(?i)PendingIntent\.getActivity|PendingIntent\.getBroadcast|PendingIntent\.getService'),
    
    # Task & Activity Security Issues
    "Task Hijacking": re.compile(r'(?i)FLAG_ACTIVITY_NEW_TASK'),
    "Permission Granting": re.compile(r'(?i)grantUriPermission|setComponentEnabledSetting'),
    "Exported Service": re.compile(r'(?i)android:exported="true"'),
    "Services": re.compile(r'(?i)Landroid/app/Service;'),
    
    # Network & SSL Issues
    "Android Network Security Config": re.compile(r'(?i)android:networkSecurityConfig="@xml/.*"'),
    "Weak SSL/TLS Protocols": re.compile(r'(?i)TLSv1|TLSv1\.1'),
    "Certificate Validation": re.compile(r'(?i)checkServerTrusted|OnReceivedSSL|TrustManager|SSLSocketFactory'),
    
    # SQL Security Issues
    "SQL Databases": re.compile(r'(?i)(openOrCreateDatabase|SQLiteDatabase)'),
    "SQL Injection Risk": re.compile(r'(?i)execSQL\(.*".*"'),
    
    # Other Issues
    "Allow Backup Enabled": re.compile(r'(?i)android:allowBackup="true"'),
    "Obfuscated Code": re.compile(r'(?i)Proguard|DexGuard|R8'),
    "Weak Random Function": re.compile(r'(?i)new Random\(\)|Math\.random\(\)'),
    "Notification Manager": re.compile(r'(?i)NotificationManager'),
    "Auto Generated Screenshot": re.compile(r'(?i)setSecure\(false\)')
}
