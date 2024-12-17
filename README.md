# شناسگر کلاهبرداری (Scam Detector)
**نسخه: 1.0.0-beta**
**توسعه‌دهنده: v7lthronyx (AIDENAZAD)**

## توضیحات پروژه
شناسگر کلاهبرداری یک ابزار پیشرفته و جامع برای شناسایی و تحلیل امنیتی وب‌سایت‌های مشکوک به کلاهبرداری است. این ابزار با استفاده از ترکیبی از تکنیک‌های مختلف، هوش مصنوعی و API‌های امنیتی، به کاربران کمک می‌کند تا از امنیت وب‌سایت‌ها اطمینان حاصل کنند.

## ویژگی‌های اصلی

### 🔒 تحلیل امنیت زیرساخت
- بررسی جامع گواهینامه SSL/TLS و پیکربندی آن
- تحلیل هدرهای امنیتی HTTP و HSTS
- بررسی امنیت کوکی‌ها و Content Security Policy
- تحلیل WAF و CDN

### 🌐 بررسی دامنه و DNS
- تحلیل سن و اعتبار دامنه
- بررسی DNSSEC، SPF و DMARC
- شناسایی TLD‌های مشکوک
- نگاشت زیردامنه‌ها

### 🔍 اسکن شبکه و پورت
- اسکن پورت‌ها با Nmap
- تحلیل سرویس‌های در معرض
- بررسی آسیب‌پذیری‌های شبکه
- شناسایی پروتکل‌های ناامن

### 📊 تحلیل محتوا و کد
- تشخیص محتوای فارسی مشکوک
- شناسایی کدهای مبهم JavaScript
- تحلیل OCR تصاویر
- بررسی فرم‌های ورود اطلاعات

### 🤖 هوش مصنوعی و یادگیری ماشین
- مدل RandomForest برای تشخیص الگوهای کلاهبرداری
- به‌روزرسانی خودکار دیتاست
- یادگیری مستمر از نمونه‌های جدید
- امتیازدهی هوشمند به ریسک‌ها

### 🔄 یکپارچگی با API‌های امنیتی
- Google Safe Browsing
- VirusTotal
- PhishTank
- Shodan و Censys
- OTX و CVE Database

### 📈 گزارش‌دهی پیشرفته
- نمودارهای تعاملی تحلیل ریسک
- گزارش تفصیلی برای متخصصان
- امکان صدور گزارش در قالب‌های مختلف
- توصیه‌های امنیتی اولویت‌بندی شده

## پیش‌نیازها
- Python 3.8 یا بالاتر
- پکیج‌های مورد نیاز (در requirements.txt)
- Nmap
- Nikto
- Chrome و ChromeDriver (برای اسکن‌های پویا)
- کلیدهای API سرویس‌های امنیتی

## نصب و راه‌اندازی

### 1. کلون کردن مخزن
```bash
git clone https://github.com/v7lthronyxprojects/ScamDetection.git
cd ScamDetection
```

### 2. نصب وابستگی‌ها
```bash
pip install -r requirements.txt
```

### 3. تنظیم کلیدهای API
یک فایل `.env` ایجاد کنید و کلیدهای API خود را در آن قرار دهید:
```plaintext
PHISHTANK_API_KEY=your_phishtank_api_key
URLSCAN_API_KEY=your_urlscan_api_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key
SAFE_BROWSING_KEY=your_safe_browsing_key
ABUSEIPDB_KEY=your_abuseipdb_key
TALOS_API_KEY=your_talos_api_key
OTX_API_KEY=your_otx_api_key
UMBRELLA_KEY=your_umbrella_key
METADEFENDER_KEY=your_metadefender_key
SHODAN_API_KEY=your_shodan_api_key
CENSYS_API_ID=your_censys_api_id
CENSYS_API_SECRET=your_censys_api_secret
```

### 4. اجرای اسکن
برای اسکن یک وب‌سایت، دستور زیر را اجرا کنید:
```bash
python main.py
```

### 5. آموزش مدل (اختیاری)
برای آموزش مدل یادگیری ماشین، دستور زیر را اجرا کنید:
```bash
python scanner.py --train
```

## مجوز
این پروژه تحت مجوز اختصاصی v7lthronyx منتشر شده است. برای اطلاعات بیشتر به فایل LICENSE مراجعه کنید.





