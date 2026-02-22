# استخدام صورة Python رسمية خفيفة
FROM python:3-slim

# تحديد مجلد العمل داخل الحاوية
WORKDIR /app

# نسخ ملف المتطلبات أولا (للاستفادة من خاصية الـ Cache في Docker)
COPY requirements.txt .

# تثبيت الاعتماديات المكتوبة في requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# نسخ باقي ملفات المشروع (بما في ذلك app.py) إلى مجلد العمل
COPY . .

# الأمر الذي سيتم تشغيله عند بدء الحاوية
# تأكد أن "app" هو اسم الملف (بدون .py) أو استخدم "app.py"
CMD ["python", "app.py"]