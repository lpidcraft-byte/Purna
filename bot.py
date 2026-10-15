import logging
import requests
import json
import os
import random
import re
import hashlib
import threading
from datetime import datetime
from flask import Flask, jsonify
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler,
    ContextTypes, MessageHandler, filters
)

# ═══════════════════════════════════════════
#                ⚙️ AYARLAR
# ═══════════════════════════════════════════
BOT_TOKEN = "8361049874:AAEG_-938EZeaf7UaRBFjRuwSuMgHfnbtCM"
API_URL = "https://numberpanel.tech/api/lifetime"
ADMIN_IDS = [8967909400, 8913966694]
LOG_KANAL_ID = -1003812660420
PORT = int(os.environ.get("PORT", "8080"))

KANALLAR = [
    "https://t.me/vantoriumbanned",
    "https://t.me/zyrvenilkyazanss",
    "https://t.me/otpbotlogss"
]
KANAL_IDLERI = [-1003947388912, -1004326807501, -1003812660420]
VERI_DOSYASI = "bot_data.json"

IADE_BEKLEME_SN = 60
OTO_IPTAL_SN = 900
SMS_BEKLEME_SN = 900
SMS_POLL_INTERVAL = 3
REFERANS_PUAN = 1
GORULEN_LIMIT = 30
SAYFA_BOYUT = 10

WHATSAPP_KEYWORDS = ["whatsapp", "wa", "whats_app"]
TELEGRAM_KEYWORDS = ["telegram", "tg", "telega"]

FIYAT_HAVUZU = [1, 2, 3, 5, 8, 10]

SUNUCU1_ULKELER = ["90", "1", "44", "49", "33", "7", "971", "966", "20", "62", "92", "880", "994", "995", "998"]
SUNUCU1_SERVISLER = WHATSAPP_KEYWORDS + TELEGRAM_KEYWORDS + ["instagram", "facebook", "tiktok", "google", "twitter", "discord"]

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════
#              🌍 ÜLKE KODLARI
# ═══════════════════════════════════════════
ULKE_KODLARI = {
    "1": "🇺🇸 ABD/Kanada", "7": "🇷🇺 Rusya", "20": "🇪🇬 Mısır",
    "27": "🇿🇦 G.Afrika", "30": "🇬🇷 Yunanistan", "31": "🇳🇱 Hollanda",
    "32": "🇧🇪 Belçika", "33": "🇫🇷 Fransa", "34": "🇪🇸 İspanya",
    "36": "🇭🇺 Macaristan", "39": "🇮🇹 İtalya", "40": "🇷🇴 Romanya",
    "41": "🇨🇭 İsviçre", "43": "🇦🇹 Avusturya", "44": "🇬🇧 İngiltere",
    "45": "🇩🇰 Danimarka", "46": "🇸🇪 İsveç", "47": "🇳🇴 Norveç",
    "48": "🇵🇱 Polonya", "49": "🇩🇪 Almanya", "51": "🇵🇪 Peru",
    "52": "🇲🇽 Meksika", "54": "🇦🇷 Arjantin", "55": "🇧🇷 Brezilya",
    "60": "🇲🇾 Malezya", "61": "🇦🇺 Avustralya", "62": "🇮🇩 Endonezya",
    "63": "🇵🇭 Filipinler", "64": "🇳🇿 Yeni Zelanda", "65": "🇸🇬 Singapur",
    "66": "🇹🇭 Tayland", "81": "🇯🇵 Japonya", "82": "🇰🇷 G.Kore",
    "84": "🇻🇳 Vietnam", "86": "🇨🇳 Çin", "90": "🇹🇷 Türkiye",
    "91": "🇮🇳 Hindistan", "92": "🇵🇰 Pakistan", "93": "🇦🇫 Afganistan",
    "94": "🇱🇰 Sri Lanka", "98": "🇮🇷 İran", "212": "🇲🇦 Fas",
    "213": "🇩🇿 Cezayir", "216": "🇹🇳 Tunus", "218": "🇱🇾 Libya",
    "234": "🇳🇬 Nijerya", "249": "🇸🇩 Sudan", "251": "🇪🇹 Etiyopya",
    "254": "🇰🇪 Kenya", "255": "🇹🇿 Tanzanya", "256": "🇺🇬 Uganda",
    "351": "🇵🇹 Portekiz", "352": "🇱🇺 Lüksemburg", "353": "🇮🇪 İrlanda",
    "354": "🇮🇸 İzlanda", "355": "🇦🇱 Arnavutluk", "356": "🇲🇹 Malta",
    "357": "🇨🇾 Kıbrıs", "358": "🇫🇮 Finlandiya", "359": "🇧🇬 Bulgaristan",
    "370": "🇱🇹 Litvanya", "371": "🇱🇻 Letonya", "372": "🇪🇪 Estonya",
    "373": "🇲🇩 Moldova", "380": "🇺🇦 Ukrayna", "381": "🇷🇸 Sırbistan",
    "385": "🇭🇷 Hırvatistan", "386": "🇸🇮 Slovenya", "387": "🇧🇦 Bosna",
    "389": "🇲🇰 Makedonya", "420": "🇨🇿 Çekya", "421": "🇸🇰 Slovakya",
    "880": "🇧🇩 Bangladeş", "961": "🇱🇧 Lübnan", "962": "🇯🇴 Ürdün",
    "963": "🇸🇾 Suriye", "964": "🇮🇶 Irak", "965": "🇰🇼 Kuveyt",
    "966": "🇸🇦 S.Arabistan", "967": "🇾🇪 Yemen", "968": "🇴🇲 Umman",
    "971": "🇦🇪 BAE", "972": "🇮🇱 İsrail", "973": "🇧🇭 Bahreyn",
    "974": "🇶🇦 Katar", "976": "🇲🇳 Moğolistan", "977": "🇳🇵 Nepal",
    "994": "🇦🇿 Azerbaycan", "995": "🇬🇪 Gürcistan", "996": "🇰🇬 Kırgızistan",
    "998": "🇺🇿 Özbekistan",
}

def ulke_kodu_bul(numara: str) -> str:
    temiz = re.sub(r"\D", "", numara)
    for uzunluk in (3, 2, 1):
        kod = temiz[:uzunluk]
        if kod in ULKE_KODLARI:
            return kod
    return ""

def ulke_bul(numara: str) -> str:
    temiz = re.sub(r"\D", "", numara)
    if not temiz:
        return "🌍 Bilinmiyor"
    for uzunluk in (3, 2, 1):
        kod = temiz[:uzunluk]
        if kod in ULKE_KODLARI:
            return ULKE_KODLARI[kod]
    return f"🌍 +{temiz[:3]}"

def sunucu_bul(servis: str, numara: str) -> int:
    servis_l = str(servis).lower()
    ulke_k = ulke_kodu_bul(numara)
    if any(k in servis_l for k in SUNUCU1_SERVISLER):
        return 1
    if ulke_k in SUNUCU1_ULKELER:
        return 1
    return 2

# ═══════════════════════════════════════════
#              💾 VERİ YÖNETİMİ
# ═══════════════════════════════════════════
def veri_yukle():
    if os.path.exists(VERI_DOSYASI):
        with open(VERI_DOSYASI, 'r', encoding='utf-8') as f:
            d = json.load(f)
            for k in ("siparisler", "gecici_numaralar"):
                if k not in d:
                    d[k] = {}
            return d
    return {
        "kullanicilar": {},
        "siparisler": {},
        "gecici_numaralar": {},
        "duyuru": "✨ Hoş geldin! Botumuzu kullanmak için önce kanallara katıl.",
        "adminler": ADMIN_IDS.copy()
    }

def veri_kaydet(veri):
    with open(VERI_DOSYASI, 'w', encoding='utf-8') as f:
        json.dump(veri, f, ensure_ascii=False, indent=2)

data = veri_yukle()

# ═══════════════════════════════════════════
#           📢 LOG KANALI BİLDİRİMİ
# ═══════════════════════════════════════════
async def log_gonder(context, baslik, detay, ikon="📌"):
    try:
        text = (
            f"{ikon} **{baslik}**\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"{detay}\n"
            f"🕐 `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`"
        )
        await context.bot.send_message(
            chat_id=LOG_KANAL_ID,
            text=text,
            parse_mode="Markdown"
        )
    except Exception as e:
        print(f"[log_gonder] {e}")

# ═══════════════════════════════════════════
#              🛠 YARDIMCILAR
# ═══════════════════════════════════════════
def kullanici_kayit(user_id, referans_eden=None):
    yeni_kayit = False
    if str(user_id) not in data["kullanicilar"]:
        data["kullanicilar"][str(user_id)] = {
            "puan": 0, "referans": 0, "ban": False,
            "referans_eden": referans_eden, "gorulen_numaralar": []
        }
        yeni_kayit = True
        if referans_eden:
            ref_id = str(referans_eden)
            if ref_id in data["kullanicilar"]:
                data["kullanicilar"][ref_id]["puan"] += REFERANS_PUAN
                data["kullanicilar"][ref_id]["referans"] += 1
        veri_kaydet(data)
    return yeni_kayit

async def kanal_kontrol(context, user_id):
    for kanal_id in KANAL_IDLERI:
        try:
            member = await context.bot.get_chat_member(chat_id=kanal_id, user_id=user_id)
            if member.status in ["left", "kicked"]:
                return False
        except Exception as e:
            print(f"[kanal_kontrol] {kanal_id} hata: {e}")
    return True

def admin_mi(user_id):
    return user_id in data["adminler"]

def numara_normalize(n):
    return re.sub(r"\D", "", str(n))

def numara_eslesme(hedef, api_numara):
    h = numara_normalize(hedef)
    a = numara_normalize(api_numara)
    if len(h) < 7 or len(a) < 7:
        return False
    return h[-7:] == a[-7:]

def mesaj_imzasi(item):
    try:
        numara = numara_normalize(item[1])[-9:]
        mesaj = str(item[2]).strip()[:120]
        tarih = str(item[3]).strip()
        ham = f"{numara}|{mesaj}|{tarih}"
        return hashlib.md5(ham.encode()).hexdigest()
    except Exception:
        return None

# ═══════════════════════════════════════════
#          🔔 REFERANS BİLDİRİMİ
# ═══════════════════════════════════════════
async def referans_bildirim_gonder(context, davet_eden_id, yeni_kullanici):
    try:
        yeni_isim = yeni_kullanici.first_name or "Anonim"
        yeni_username = f"@{yeni_kullanici.username}" if yeni_kullanici.username else "_(yok)_"
        davet_eden_data = data["kullanicilar"].get(str(davet_eden_id), {})
        toplam_ref = davet_eden_data.get("referans", 0)
        toplam_puan = davet_eden_data.get("puan", 0)

        text = (
            "╔══════════════════════════╗\n"
            "   🎉  **YENİ DAVET!**\n"
            "╚══════════════════════════╝\n\n"
            f"👤 **İsim:** {yeni_isim}\n"
            f"🔗 **Kullanıcı:** {yeni_username}\n"
            f"🆔 **ID:** `{yeni_kullanici.id}`\n\n"
            "┌──────────────────────┐\n"
            f"│  💎 **+{REFERANS_PUAN} Puan** kazandın!\n"
            "└──────────────────────┘\n\n"
            f"📊 **Güncel:**\n"
            f"👥 Referans: **{toplam_ref}**\n"
            f"💰 Puan: **{toplam_puan}**"
        )
        keyboard = InlineKeyboardMarkup([
            [InlineKeyboardButton("🔗 Referans Linkim", callback_data="referans", style="primary")],
            [InlineKeyboardButton("🏠 Ana Menü", callback_data="geri_menu", style="success")]
        ])
        await context.bot.send_message(
            chat_id=davet_eden_id, text=text,
            reply_markup=keyboard, parse_mode="Markdown"
        )
    except Exception as e:
        print(f"[referans_bildirim] {e}")

    try:
        await log_gonder(
            context, "YENİ DAVET",
            f"👤 **Davet eden:** `{davet_eden_id}`\n"
            f"🎁 **Katılan:** {yeni_kullanici.first_name} (`{yeni_kullanici.id}`)\n"
            f"💎 **Kazanç:** +{REFERANS_PUAN} puan",
            ikon="🎉"
        )
    except Exception:
        pass

# ═══════════════════════════════════════════
#              🎨 MENÜLER
# ═══════════════════════════════════════════
def ana_menu():
    keyboard = [
        [InlineKeyboardButton("🚀 Sunucu 1 (Önerilen)", callback_data="sunucu_1", style="success"),
         InlineKeyboardButton("📡 Sunucu 2", callback_data="sunucu_2", style="primary")],
        [InlineKeyboardButton("👤 Profilim", callback_data="profil", style="primary"),
         InlineKeyboardButton("🔗 Referans", callback_data="referans", style="primary")],
        [InlineKeyboardButton("📢 Duyuru", callback_data="duyuru", style="primary")],
        [InlineKeyboardButton("👑 Admin Paneli", callback_data="admin_panel", style="danger")]
    ]
    return InlineKeyboardMarkup(keyboard)

def kanal_menu():
    keyboard = [
        [InlineKeyboardButton("📢 VANTORİUM BANNED", url=KANALLAR[0], style="primary")],
        [InlineKeyboardButton("📢 Zyrven İlk Yazan", url=KANALLAR[1], style="primary")],
        [InlineKeyboardButton("📢 OTP BOT LOGS", url=KANALLAR[2], style="primary")],
        [InlineKeyboardButton("✅ Katıldım", callback_data="katildim", style="success")]
    ]
    return InlineKeyboardMarkup(keyboard)

def geri_menu():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🔙 Ana Menü", callback_data="geri_menu", style="success")]
    ])

# ═══════════════════════════════════════════
#           👥 KİŞİ LİSTESİ GÖRÜNÜMÜ
# ═══════════════════════════════════════════
def kisi_listesi_ekrani(sayfa=0):
    """Kişi listesini sayfalı olarak hazırla."""
    kullanicilar = list(data["kullanicilar"].items())
    # Puanı yüksekten düşüğe sırala
    kullanicilar.sort(key=lambda x: x[1].get("puan", 0), reverse=True)

    toplam = len(kullanicilar)
    toplam_sayfa = max(1, (toplam + SAYFA_BOYUT - 1) // SAYFA_BOYUT)

    if sayfa < 0:
        sayfa = 0
    if sayfa >= toplam_sayfa:
        sayfa = toplam_sayfa - 1

    baslangic = sayfa * SAYFA_BOYUT
    bitis = baslangic + SAYFA_BOYUT
    sayfa_kisiler = kullanicilar[baslangic:bitis]

    banli_sayi = sum(1 for _, v in kullanicilar if v.get("ban"))
    toplam_puan = sum(v.get("puan", 0) for _, v in kullanicilar)
    toplam_ref = sum(v.get("referans", 0) for _, v in kullanicilar)

    text = (
        "╔══════════════════════════╗\n"
        "     👥  **KİŞİ LİSTESİ**\n"
        "╚══════════════════════════╝\n\n"
        f"📊 **İstatistikler:**\n"
        f"👤 Toplam: **{toplam}**\n"
        f"🚫 Banlı: **{banli_sayi}**\n"
        f"💰 Toplam Puan: **{toplam_puan}**\n"
        f"🎁 Toplam Referans: **{toplam_ref}**\n\n"
        f"📄 **Sayfa {sayfa + 1}/{toplam_sayfa}**\n"
        "━━━━━━━━━━━━━━━━━━\n"
    )

    if not sayfa_kisiler:
        text += "\n_Liste boş._\n"
    else:
        for i, (uid, u) in enumerate(sayfa_kisiler, baslangic + 1):
            ban_ikon = "🚫" if u.get("ban") else "✅"
            adm_ikon = "👑" if int(uid) in data["adminler"] else ""
            text += (
                f"**{i}.** {ban_ikon} {adm_ikon} `{uid}`\n"
                f"    💰 {u.get('puan', 0)} | 🎁 {u.get('referans', 0)}\n"
            )

    # Sayfalama butonları
    keyboard = []
    nav_row = []
    if sayfa > 0:
        nav_row.append(InlineKeyboardButton("⬅️ Önceki", callback_data=f"kisi_sayfa_{sayfa - 1}", style="primary"))
    if sayfa < toplam_sayfa - 1:
        nav_row.append(InlineKeyboardButton("Sonraki ➡️", callback_data=f"kisi_sayfa_{sayfa + 1}", style="primary"))
    if nav_row:
        keyboard.append(nav_row)

    keyboard.append([InlineKeyboardButton("🔄 Yenile", callback_data=f"kisi_sayfa_{sayfa}", style="success")])
    keyboard.append([InlineKeyboardButton("🔙 Admin Paneli", callback_data="admin_panel", style="danger")])

    return text, InlineKeyboardMarkup(keyboard)

# ═══════════════════════════════════════════
#              📡 API FONKSİYONLARI
# ═══════════════════════════════════════════
def api_veri_cek():
    try:
        r = requests.get(API_URL, timeout=15)
        if r.status_code != 200:
            return []
        return r.json()
    except Exception as e:
        print(f"[api_veri_cek] {e}")
        return []

def numaraya_ait_mevcut_imzalar(numara):
    imzalar = set()
    for item in api_veri_cek():
        try:
            if numara_eslesme(numara, str(item[1])):
                imza = mesaj_imzasi(item)
                if imza:
                    imzalar.add(imza)
        except Exception:
            continue
    return imzalar

def bu_numaraya_yeni_mesaj_var_mi(numara, eski_imzalar):
    for item in api_veri_cek():
        try:
            if not numara_eslesme(numara, str(item[1])):
                continue
            imza = mesaj_imzasi(item)
            if not imza:
                continue
            if imza not in eski_imzalar:
                return str(item[2]), item
        except Exception:
            continue
    return None

def tek_numara_getir(user_id, sunucu=1):
    tum = api_veri_cek()
    if not tum:
        return None

    kullanici = data["kullanicilar"].get(str(user_id), {})
    gorulenler = set(kullanici.get("gorulen_numaralar", []))

    sunucu_listesi = []
    for item in tum:
        try:
            servis = str(item[0])
            numara = str(item[1])
        except Exception:
            continue
        if sunucu_bul(servis, numara) == sunucu:
            sunucu_listesi.append(item)

    if not sunucu_listesi:
        return None

    yeni_liste = [item for item in sunucu_listesi if str(item[1]) not in gorulenler]
    if not yeni_liste:
        kullanici["gorulen_numaralar"] = []
        data["kullanicilar"][str(user_id)] = kullanici
        veri_kaydet(data)
        yeni_liste = sunucu_listesi

    secilen = random.choice(yeni_liste)

    yeni_gorulen = kullanici.get("gorulen_numaralar", [])
    yeni_gorulen.append(str(secilen[1]))
    if len(yeni_gorulen) > GORULEN_LIMIT:
        yeni_gorulen = yeni_gorulen[-GORULEN_LIMIT:]
    kullanici["gorulen_numaralar"] = yeni_gorulen
    data["kullanicilar"][str(user_id)] = kullanici
    veri_kaydet(data)

    numara = str(secilen[1])
    servis_adi = str(secilen[0])

    servis_l = servis_adi.lower()
    if any(k in servis_l for k in WHATSAPP_KEYWORDS):
        servis_tip = "WhatsApp"
        servis_ikon = "💚"
    elif any(k in servis_l for k in TELEGRAM_KEYWORDS):
        servis_tip = "Telegram"
        servis_ikon = "✈️"
    else:
        servis_tip = servis_adi
        servis_ikon = "💬"

    return {
        "servis": servis_adi,
        "servis_tip": servis_tip,
        "servis_ikon": servis_ikon,
        "numara": numara,
        "mesaj": str(secilen[2]) if len(secilen) > 2 else "",
        "tarih": str(secilen[3]) if len(secilen) > 3 else "",
        "ulke": ulke_bul(numara),
        "fiyat": random.choice(FIYAT_HAVUZU),
        "sunucu": sunucu
    }

def kod_ayikla(mesaj):
    patterns = [
        r"(?:code|kod|otp|pin|password)[\s:]*[`\s]*(\d{4,8})",
        r"(\d{4,8})[\s]*(?:is your|kodunuz|kodun)",
        r"\b(\d{4,8})\b"
    ]
    for p in patterns:
        m = re.search(p, mesaj, re.IGNORECASE)
        if m:
            return m.group(1)
    return None

# ═══════════════════════════════════════════
#              🎯 JOB FONKSİYONLARI
# ═══════════════════════════════════════════
async def iade_aktif_et(context: ContextTypes.DEFAULT_TYPE):
    job = context.job
    order_id = job.data["order_id"]
    if order_id not in data["siparisler"]:
        return
    order = data["siparisler"][order_id]
    if order["durum"] != "aktif":
        return
    keyboard = [[InlineKeyboardButton("💰 İade Et", callback_data=f"iade_et_{order_id}", style="success")]]
    try:
        await context.bot.edit_message_reply_markup(
            chat_id=order["chat_id"], message_id=order["message_id"],
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        await context.bot.send_message(
            chat_id=order["chat_id"],
            text="┌───────────────────────┐\n"
                 "    ✅  **İADE AKTİF**\n"
                 "└───────────────────────┘\n\n"
                 "💰 15 dakika içinde iade edebilirsin.",
            parse_mode="Markdown"
        )
    except Exception as e:
        print(f"[iade_aktif_et] {e}")

async def otomatik_iptal(context: ContextTypes.DEFAULT_TYPE):
    job = context.job
    order_id = job.data["order_id"]
    if order_id not in data["siparisler"]:
        return
    order = data["siparisler"][order_id]
    if order["durum"] != "aktif":
        return
    order["durum"] = "iptal"
    veri_kaydet(data)
    try:
        await context.bot.edit_message_reply_markup(
            chat_id=order["chat_id"], message_id=order["message_id"], reply_markup=None
        )
    except Exception:
        pass
    try:
        await context.bot.send_message(
            chat_id=order["chat_id"],
            text="┌───────────────────────┐\n"
                 "    ⏰  **SÜRE DOLDU**\n"
                 "└───────────────────────┘\n\n"
                 "❌ 15 dakika geçti, sipariş iptal edildi.\n"
                 "💸 SMS gelmediği için puan iadesi yapılmadı.",
            parse_mode="Markdown"
        )
    except Exception as e:
        print(f"[otomatik_iptal] {e}")

    await log_gonder(context, "SİPARİŞ İPTAL",
        f"👤 **Kullanıcı:** `{order_id}`\n"
        f"📞 **Numara:** `{order['numara']}`\n"
        f"⏰ **Sebep:** 15 dk doldu, SMS gelmedi",
        ikon="⏰")

async def sms_bekle(context: ContextTypes.DEFAULT_TYPE):
    job = context.job
    order_id = job.data["order_id"]
    if order_id not in data["siparisler"]:
        return
    order = data["siparisler"][order_id]
    if order["durum"] != "aktif":
        return

    baslangic = datetime.fromisoformat(order["baslangic"])
    gecen = (datetime.now() - baslangic).total_seconds()
    if gecen > SMS_BEKLEME_SN:
        return

    eski_imzalar = set(order.get("eski_imzalar", []))
    sonuc = bu_numaraya_yeni_mesaj_var_mi(order["numara"], eski_imzalar)

    if sonuc:
        yeni_mesaj, item = sonuc
        order["durum"] = "sms_geldi"
        order["sms_kodu"] = yeni_mesaj
        veri_kaydet(data)

        for j in context.job_queue.get_jobs_by_name(f"iade_aktif_{order_id}"):
            j.schedule_removal()
        for j in context.job_queue.get_jobs_by_name(f"iptal_{order_id}"):
            j.schedule_removal()

        kod = kod_ayikla(yeni_mesaj)

        if kod:
            text = (
                "╔══════════════════════════╗\n"
                "     🎉  **SMS GELDİ!**\n"
                "╚══════════════════════════╝\n\n"
                f"🌍 Ülke: {order.get('ulke', 'Bilinmiyor')}\n"
                f"📞 Numara: `{order['numara']}`\n"
                f"💬 Servis: {order.get('servis', '-')}\n\n"
                "┌──────────────────────┐\n"
                f"│  🔑 **KOD:** `{kod}`\n"
                "└──────────────────────┘\n\n"
                f"📩 **Tam Mesaj:**\n"
                f"_{yeni_mesaj[:300]}_\n\n"
                "👇 Kodu kopyala ve kullan! ✨"
            )
        else:
            text = (
                "╔══════════════════════════╗\n"
                "     🎉  **SMS GELDİ!**\n"
                "╚══════════════════════════╝\n\n"
                f"🌍 Ülke: {order.get('ulke', 'Bilinmiyor')}\n"
                f"📞 Numara: `{order['numara']}`\n"
                f"💬 Servis: {order.get('servis', '-')}\n\n"
                "📩 **Mesaj:**\n"
                f"```{yeni_mesaj[:400]}```\n\n"
                "👇 Kodu kopyala ve kullan! ✨"
            )

        keyboard = InlineKeyboardMarkup([
            [InlineKeyboardButton("🔄 Yeni Numara Al", callback_data="numara_al", style="primary")],
            [InlineKeyboardButton("🔙 Ana Menü", callback_data="geri_menu", style="success")]
        ])

        await context.bot.send_message(
            chat_id=order["chat_id"], text=text,
            reply_markup=keyboard, parse_mode="Markdown"
        )

        await log_gonder(context, "YENİ KOD DÜŞTÜ",
            f"👤 **Kullanıcı:** `{order_id}`\n"
            f"🌍 **Ülke:** {order.get('ulke', '-')}\n"
            f"📞 **Numara:** `{order['numara']}`\n"
            f"💬 **Servis:** {order.get('servis', '-')}\n"
            f"🔑 **Kod:** `{kod or 'ayıklanamadı'}`\n"
            f"📩 **Mesaj:** `{yeni_mesaj[:200]}`",
            ikon="🔥")
        return

    context.job_queue.run_once(
        sms_bekle, when=SMS_POLL_INTERVAL,
        data={"order_id": order_id},
        name=f"sms_poll_{order_id}"
    )

# ═══════════════════════════════════════════
#              🚀 KOMUTLAR
# ═══════════════════════════════════════════
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    args = context.args
    referans_eden = None
    if args and args[0].startswith("ref_"):
        try:
            referans_eden = int(args[0].split("_")[1])
        except Exception:
            referans_eden = None

    yeni_kayit = kullanici_kayit(user.id, referans_eden)

    if yeni_kayit:
        await log_gonder(context, "YENİ KULLANICI",
            f"👤 **İsim:** {user.first_name}\n"
            f"🆔 **ID:** `{user.id}`\n"
            f"🔗 **Username:** @{user.username if user.username else '-'}",
            ikon="🆕")

    if yeni_kayit and referans_eden and referans_eden != user.id:
        if str(referans_eden) in data["kullanicilar"]:
            await referans_bildirim_gonder(context, referans_eden, user)

    user_data = data["kullanicilar"].get(str(user.id), {})

    if user_data.get("ban"):
        await update.message.reply_text(
            "┌───────────────────────┐\n"
            "    🚫  **BANLANDIN**\n"
            "└───────────────────────┘",
            parse_mode="Markdown"
        )
        return

    if not await kanal_kontrol(context, user.id):
        await update.message.reply_text(
            "╔══════════════════════════╗\n"
            "   ⚠️  **KANAL ZORUNLU**\n"
            "╚══════════════════════════╝\n\n"
            "Botu kullanmak için aşağıdaki\n"
            "**3 kanala** katılman gerekiyor 👇",
            reply_markup=kanal_menu()
        )
        return

    await update.message.reply_text(
        f"╔══════════════════════════╗\n"
        f"   👋  **MERHABA {user.first_name.upper()}!**\n"
        f"╚══════════════════════════╝\n\n"
        f"📢 **Duyuru:**\n_{data['duyuru']}_\n\n"
        f"🚀 **Sunucu 1** — Aktif numaralar (Önerilen)\n"
        f"📡 **Sunucu 2** — Yedek numaralar\n\n"
        f"💎 Aşağıdan seç:",
        reply_markup=ana_menu(),
        parse_mode="Markdown"
    )

# ═══════════════════════════════════════════
#              🎛 CALLBACK HANDLER
# ═══════════════════════════════════════════
async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    user_id = query.from_user.id
    cdata = query.data

    # Kişi listesi callback'i kanal kontrolünden muaf değil ama admin kontrolü var
    if not cdata.startswith("iade"):
        if not await kanal_kontrol(context, user_id):
            await query.answer()
            await query.edit_message_text(
                "⚠️ Lütfen önce 3 kanala da katılın!",
                reply_markup=kanal_menu()
            )
            return

    user_data = data["kullanicilar"].get(str(user_id), {})

    if cdata == "katildim":
        await query.answer()
        if await kanal_kontrol(context, user_id):
            await query.edit_message_text(
                f"╔══════════════════════════╗\n"
                f"   ✅  **HOŞ GELDİN!**\n"
                f"╚══════════════════════════╝\n\n"
                f"📢 _{data['duyuru']}_",
                reply_markup=ana_menu(),
                parse_mode="Markdown"
            )
        else:
            await query.edit_message_text("❌ Hala kanallara katılmadınız!")

    elif cdata in ("sunucu_1", "sunucu_2", "numara_al"):
        await query.answer()
        if user_data.get("ban"):
            await query.edit_message_text("🚫 Hesabınız banlı!")
            return

        aktif = data["siparisler"].get(str(user_id))
        if aktif and aktif["durum"] in ["aktif", "sms_geldi"]:
            await query.answer("⚠️ Zaten aktif siparişin var!", show_alert=True)
            return

        if cdata == "sunucu_2":
            sunucu = 2
            sunucu_adi = "📡 Sunucu 2"
            await query.edit_message_text("📡 Sunucu 2'den numara getiriliyor...")
        else:
            sunucu = 1
            sunucu_adi = "🚀 Sunucu 1 (Önerilen)"
            await query.edit_message_text("🚀 Sunucu 1'den numara getiriliyor...")

        numara = tek_numara_getir(user_id, sunucu=sunucu)
        if not numara:
            keyboard = InlineKeyboardMarkup([
                [InlineKeyboardButton("🚀 Sunucu 1", callback_data="sunucu_1", style="success"),
                 InlineKeyboardButton("📡 Sunucu 2", callback_data="sunucu_2", style="primary")],
                [InlineKeyboardButton("🔙 Ana Menü", callback_data="geri_menu", style="danger")]
            ])
            await query.edit_message_text(
                f"❌ **{sunucu_adi}**'da uygun numara bulunamadı.\nDiğer sunucuyu dene 👇",
                reply_markup=keyboard,
                parse_mode="Markdown"
            )
            return

        data["gecici_numaralar"][str(user_id)] = [numara]
        veri_kaydet(data)

        user_puan = user_data.get("puan", 0)
        yeterli = user_puan >= numara["fiyat"]
        sunucu_etiketi = "🚀 **Sunucu 1** — Önerilen" if sunucu == 1 else "📡 **Sunucu 2**"

        text = (
            "╔══════════════════════════╗\n"
            "    📱  **NUMARA HAZIR**\n"
            "╚══════════════════════════╝\n\n"
            f"{sunucu_etiketi}\n\n"
            f"🌍 Ülke: {numara['ulke']}\n"
            f"📞 Numara: `{numara['numara']}`\n"
            f"{numara['servis_ikon']} Servis: **{numara['servis_tip']}**\n"
            f"💎 Fiyat: **{numara['fiyat']} Puan**\n\n"
            f"💰 Puanın: **{user_puan}**"
        )

        if yeterli:
            keyboard = InlineKeyboardMarkup([
                [InlineKeyboardButton(f"✅ Satın Al ({numara['fiyat']} 💎)", callback_data="satin_al_0", style="success")],
                [InlineKeyboardButton("🔄 Başka Numara", callback_data=f"sunucu_{sunucu}", style="primary")],
                [InlineKeyboardButton("🔙 Geri", callback_data="geri_menu", style="danger")]
            ])
        else:
            text += f"\n\n❌ **Yetersiz puan!** En az {numara['fiyat']} puan gerekli."
            keyboard = InlineKeyboardMarkup([
                [InlineKeyboardButton("🔄 Başka Numara", callback_data=f"sunucu_{sunucu}", style="primary")],
                [InlineKeyboardButton("🔙 Geri", callback_data="geri_menu", style="danger")]
            ])

        await query.edit_message_text(text, reply_markup=keyboard, parse_mode="Markdown")

    elif cdata.startswith("satin_al_"):
        await query.answer()
        gecici = data.get("gecici_numaralar", {}).get(str(user_id), [])
        if not gecici:
            await query.answer("❌ Numara bulunamadı!", show_alert=True)
            return

        secilen = gecici[0]
        fiyat = secilen["fiyat"]

        if user_data.get("puan", 0) < fiyat:
            await query.answer(f"❌ {fiyat} puan gerekli.", show_alert=True)
            return

        user_data["puan"] -= fiyat

        await query.edit_message_text("⏳ Mevcut mesajlar taranıyor...")
        eski_imzalar = numaraya_ait_mevcut_imzalar(secilen["numara"])

        order_id = str(user_id)
        data["siparisler"][order_id] = {
            "numara": secilen["numara"],
            "servis": secilen["servis"],
            "mesaj": secilen["mesaj"],
            "tarih": secilen["tarih"],
            "ulke": secilen["ulke"],
            "fiyat": fiyat,
            "baslangic": datetime.now().isoformat(),
            "durum": "aktif",
            "chat_id": query.message.chat_id,
            "message_id": query.message.message_id,
            "eski_imzalar": list(eski_imzalar),
            "sunucu": secilen.get("sunucu", 1)
        }
        if str(user_id) in data["gecici_numaralar"]:
            del data["gecici_numaralar"][str(user_id)]
        veri_kaydet(data)

        text = (
            "╔══════════════════════════╗\n"
            "   🎉  **NUMARA ALINDI!**\n"
            "╚══════════════════════════╝\n\n"
            f"🌍 Ülke: {secilen['ulke']}\n"
            f"📞 Numara: `{secilen['numara']}`\n"
            f"{secilen['servis_ikon']} Servis: **{secilen['servis_tip']}**\n\n"
            f"💸 Ödenen: **{fiyat} Puan**\n"
            f"💳 Kalan: **{user_data['puan']} Puan**\n\n"
            "┌──────────────────────┐\n"
            "│  ⏳ SMS bekleniyor...\n"
            "│  🔔 Kod düşünce anında gelir\n"
            "└──────────────────────┘\n\n"
            f"📸 {len(eski_imzalar)} eski mesaj kaydedildi\n"
            "✅ Sadece **YENİ** SMS kabul edilecek\n\n"
            "⏱️ İade: **1 dk sonra** aktif\n"
            "⚠️ 15 dk içinde iade etmezsen puan yanar"
        )

        keyboard = InlineKeyboardMarkup([
            [InlineKeyboardButton("⏳ İade (1 dk bekleyin)", callback_data=f"iade_bekle_{order_id}", style="danger")]
        ])

        await query.edit_message_text(text, reply_markup=keyboard, parse_mode="Markdown")

        for name in (f"iade_aktif_{order_id}", f"iptal_{order_id}", f"sms_poll_{order_id}"):
            for j in context.job_queue.get_jobs_by_name(name):
                j.schedule_removal()

        context.job_queue.run_once(iade_aktif_et, when=IADE_BEKLEME_SN,
            data={"order_id": order_id}, name=f"iade_aktif_{order_id}")
        context.job_queue.run_once(otomatik_iptal, when=OTO_IPTAL_SN,
            data={"order_id": order_id}, name=f"iptal_{order_id}")
        context.job_queue.run_once(sms_bekle, when=SMS_POLL_INTERVAL,
            data={"order_id": order_id}, name=f"sms_poll_{order_id}")

        await log_gonder(context, "SİPARİŞ OLUŞTURULDU",
            f"👤 **Kullanıcı:** `{user_id}`\n"
            f"🌍 **Ülke:** {secilen['ulke']}\n"
            f"📞 **Numara:** `{secilen['numara']}`\n"
            f"💬 **Servis:** {secilen['servis_tip']}\n"
            f"💎 **Ödenen:** {fiyat} puan\n"
            f"🖥 **Sunucu:** {secilen.get('sunucu', 1)}",
            ikon="💼")

    elif cdata == "geri_menu":
        await query.answer()
        await query.edit_message_text(
            f"╔══════════════════════════╗\n"
            f"      🏠  **ANA MENÜ**\n"
            f"╚══════════════════════════╝\n\n"
            f"📢 _{data['duyuru']}_",
            reply_markup=ana_menu(),
            parse_mode="Markdown"
        )

    elif cdata.startswith("iade_bekle_"):
        await query.answer("⏳ İade 1 dakika sonra aktif olacak!", show_alert=True)

    elif cdata.startswith("iade_et_"):
        order_id = cdata.replace("iade_et_", "")
        if order_id not in data["siparisler"]:
            await query.answer("❌ Sipariş yok!", show_alert=True)
            return
        order = data["siparisler"][order_id]
        if order["durum"] != "aktif":
            await query.answer("❌ Zaten kapatılmış!", show_alert=True)
            return
        gecen = (datetime.now() - datetime.fromisoformat(order["baslangic"])).total_seconds()
        if gecen < IADE_BEKLEME_SN:
            await query.answer("⏳ Henüz iade edilemez!", show_alert=True)
            return
        if gecen > OTO_IPTAL_SN:
            await query.answer("❌ 15 dk geçti!", show_alert=True)
            return

        if order_id in data["kullanicilar"]:
            data["kullanicilar"][order_id]["puan"] += order.get("fiyat", 1)
        order["durum"] = "iade_edildi"
        veri_kaydet(data)

        for name in (f"iptal_{order_id}", f"iade_aktif_{order_id}", f"sms_poll_{order_id}"):
            for j in context.job_queue.get_jobs_by_name(name):
                j.schedule_removal()

        await query.answer("✅ İade başarılı!")
        try:
            await query.edit_message_reply_markup(reply_markup=None)
        except Exception:
            pass
        await query.edit_message_text(
            "╔══════════════════════════╗\n"
            "   💰  **İADE BAŞARILI!**\n"
            "╚══════════════════════════╝\n\n"
            f"✅ **{order.get('fiyat', 1)} puan** geri yüklendi.",
            reply_markup=geri_menu(),
            parse_mode="Markdown"
        )

        await log_gonder(context, "İADE YAPILDI",
            f"👤 **Kullanıcı:** `{order_id}`\n"
            f"📞 **Numara:** `{order['numara']}`\n"
            f"💎 **İade:** {order.get('fiyat', 1)} puan",
            ikon="💰")

    elif cdata == "profil":
        await query.answer()
        ban_durum = "🚫 Banlı" if user_data.get('ban') else "✅ Aktif"
        text = (
            "╔══════════════════════════╗\n"
            "      👤  **PROFİLİM**\n"
            "╚══════════════════════════╝\n\n"
            f"🆔 ID: `{user_id}`\n"
            f"💰 Puan: **{user_data.get('puan', 0)}**\n"
            f"👥 Referans: **{user_data.get('referans', 0)}**\n"
            f"📊 Durum: {ban_durum}"
        )
        await query.edit_message_text(text, reply_markup=geri_menu(), parse_mode="Markdown")

    elif cdata == "referans":
        await query.answer()
        bot_username = (await context.bot.get_me()).username
        ref_link = f"https://t.me/{bot_username}?start=ref_{user_id}"
        text = (
            "╔══════════════════════════╗\n"
            "    🔗  **REFERANS LİNKİN**\n"
            "╚══════════════════════════╝\n\n"
            f"`{ref_link}`\n\n"
            f"💎 Her davet = **{REFERANS_PUAN} puan**\n"
            f"👥 Toplam: **{user_data.get('referans', 0)}**\n\n"
            "🔔 Davet edilen bota girince sana\nbildirim gelir!"
        )
        await query.edit_message_text(text, reply_markup=geri_menu(), parse_mode="Markdown")

    elif cdata == "duyuru":
        await query.answer()
        await query.edit_message_text(
            "╔══════════════════════════╗\n"
            "      📢  **DUYURU**\n"
            "╚══════════════════════════╝\n\n"
            f"{data['duyuru']}",
            reply_markup=geri_menu(), parse_mode="Markdown"
        )

    # ═══════════ ADMIN PANEL ═══════════
    elif cdata == "admin_panel":
        await query.answer()
        if not admin_mi(user_id):
            await query.edit_message_text("❌ Yetkin yok!")
            return
        keyboard = InlineKeyboardMarkup([
            [InlineKeyboardButton("📢 Duyuru Yap", callback_data="admin_duyuru", style="primary")],
            [InlineKeyboardButton("➕ Puan Ekle", callback_data="admin_puan_ekle", style="success"),
             InlineKeyboardButton("➖ Puan Eksilt", callback_data="admin_puan_eksilt", style="danger")],
            [InlineKeyboardButton("🚫 Banla", callback_data="admin_banla", style="danger"),
             InlineKeyboardButton("✅ Ban Aç", callback_data="admin_ban_ac", style="success")],
            [InlineKeyboardButton("👑 Admin Ekle", callback_data="admin_ekle", style="primary"),
             InlineKeyboardButton("🗑️ Admin Çıkar", callback_data="admin_cikar", style="danger")],
            [InlineKeyboardButton("👥 Kişi Listesi", callback_data="kisi_listesi", style="primary")],
            [InlineKeyboardButton("🔙 Ana Menü", callback_data="geri_menu", style="success")]
        ])
        await query.edit_message_text(
            "╔══════════════════════════╗\n"
            "     👑  **ADMIN PANELİ**\n"
            "╚══════════════════════════╝\n\n"
            "**Komutlar:**\n"
            "`/puan_ekle <id> <miktar>`\n"
            "`/puan_eksilt <id> <miktar>`\n"
            "`/banla <id>` - `/ban_ac <id>`\n"
            "`/admin_ekle <id>` - `/admin_cikar <id>`\n"
            "`/duyuru <metin>`\n"
            "`/kisiler` — tüm kullanıcı listesi",
            reply_markup=keyboard, parse_mode="Markdown"
        )

    # ═══════════ KİŞİ LİSTESİ ═══════════
    elif cdata == "kisi_listesi":
        await query.answer()
        if not admin_mi(user_id):
            await query.edit_message_text("❌ Yetkin yok!")
            return
        text, keyboard = kisi_listesi_ekrani(sayfa=0)
        await query.edit_message_text(text, reply_markup=keyboard, parse_mode="Markdown")

    elif cdata.startswith("kisi_sayfa_"):
        await query.answer()
        if not admin_mi(user_id):
            await query.edit_message_text("❌ Yetkin yok!")
            return
        sayfa = int(cdata.replace("kisi_sayfa_", ""))
        text, keyboard = kisi_listesi_ekrani(sayfa=sayfa)
        await query.edit_message_text(text, reply_markup=keyboard, parse_mode="Markdown")

# ═══════════════════════════════════════════
#              👑 ADMIN KOMUTLARI
# ═══════════════════════════════════════════
async def admin_puan_ekle(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not admin_mi(update.effective_user.id): return
    args = context.args
    if len(args) != 2:
        await update.message.reply_text("Kullanım: /puan_ekle <id> <miktar>")
        return
    uid, miktar = args[0], int(args[1])
    if uid in data["kullanicilar"]:
        data["kullanicilar"][uid]["puan"] += miktar
        veri_kaydet(data)
        await update.message.reply_text(f"✅ {uid} → +{miktar}")
        await log_gonder(context, "PUAN EKLENDİ",
            f"👑 **Admin:** `{update.effective_user.id}`\n"
            f"👤 **Kullanıcı:** `{uid}`\n"
            f"💎 **Miktar:** +{miktar}", ikon="➕")

async def admin_puan_eksilt(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not admin_mi(update.effective_user.id): return
    args = context.args
    if len(args) != 2:
        await update.message.reply_text("Kullanım: /puan_eksilt <id> <miktar>")
        return
    uid, miktar = args[0], int(args[1])
    if uid in data["kullanicilar"]:
        data["kullanicilar"][uid]["puan"] = max(0, data["kullanicilar"][uid]["puan"] - miktar)
        veri_kaydet(data)
        await update.message.reply_text(f"✅ {uid} → -{miktar}")
        await log_gonder(context, "PUAN EKSİLTİLDİ",
            f"👑 **Admin:** `{update.effective_user.id}`\n"
            f"👤 **Kullanıcı:** `{uid}`\n"
            f"💎 **Miktar:** -{miktar}", ikon="➖")

async def admin_banla(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not admin_mi(update.effective_user.id): return
    if len(context.args) != 1:
        await update.message.reply_text("Kullanım: /banla <id>")
        return
    uid = context.args[0]
    if uid in data["kullanicilar"]:
        data["kullanicilar"][uid]["ban"] = True
        veri_kaydet(data)
        await update.message.reply_text(f"🚫 {uid} banlandı")
        await log_gonder(context, "KULLANICI BANLANDI",
            f"👑 **Admin:** `{update.effective_user.id}`\n"
            f"👤 **Banlanan:** `{uid}`", ikon="🚫")

async def admin_ban_ac(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not admin_mi(update.effective_user.id): return
    if len(context.args) != 1:
        await update.message.reply_text("Kullanım: /ban_ac <id>")
        return
    uid = context.args[0]
    if uid in data["kullanicilar"]:
        data["kullanicilar"][uid]["ban"] = False
        veri_kaydet(data)
        await update.message.reply_text(f"✅ {uid} banı açıldı")
        await log_gonder(context, "BAN AÇILDI",
            f"👑 **Admin:** `{update.effective_user.id}`\n"
            f"👤 **Kullanıcı:** `{uid}`", ikon="✅")

async def admin_ekle(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not admin_mi(update.effective_user.id): return
    if len(context.args) != 1:
        await update.message.reply_text("Kullanım: /admin_ekle <id>")
        return
    new_admin = int(context.args[0])
    if new_admin not in data["adminler"]:
        data["adminler"].append(new_admin)
        veri_kaydet(data)
        await update.message.reply_text(f"👑 {new_admin} admin")
        await log_gonder(context, "ADMIN EKLENDİ",
            f"👑 **Ekleyen:** `{update.effective_user.id}`\n"
            f"👤 **Yeni Admin:** `{new_admin}`", ikon="👑")

async def admin_cikar(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not admin_mi(update.effective_user.id): return
    if len(context.args) != 1:
        await update.message.reply_text("Kullanım: /admin_cikar <id>")
        return
    uid = int(context.args[0])
    if uid in data["adminler"] and uid != update.effective_user.id:
        data["adminler"].remove(uid)
        veri_kaydet(data)
        await update.message.reply_text(f"🗑️ {uid} çıkarıldı")
        await log_gonder(context, "ADMIN ÇIKARILDI",
            f"👑 **Çıkaran:** `{update.effective_user.id}`\n"
            f"👤 **Çıkarılan:** `{uid}`", ikon="🗑️")

async def duyuru_yap(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not admin_mi(update.effective_user.id): return
    if context.args:
        data["duyuru"] = " ".join(context.args)
        veri_kaydet(data)
        await update.message.reply_text("✅ Duyuru güncellendi")
        await log_gonder(context, "DUYURU GÜNCELLENDİ",
            f"👑 **Admin:** `{update.effective_user.id}`\n"
            f"📢 **Yeni:** {data['duyuru'][:200]}", ikon="📢")

async def kisiler_komutu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Kullanıcı listesini komutla göster."""
    if not admin_mi(update.effective_user.id): return
    text, keyboard = kisi_listesi_ekrani(sayfa=0)
    await update.message.reply_text(text, reply_markup=keyboard, parse_mode="Markdown")

async def log_kaydet(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.message and update.message.text:
        print(f"[{datetime.now()}] {update.effective_user.id}: {update.message.text}")

# ═══════════════════════════════════════════
#          🌐 FLASK — RENDER HEALTH CHECK
# ═══════════════════════════════════════════
flask_app = Flask(__name__)

@flask_app.route("/")
@flask_app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "vantorium-bot",
        "time": datetime.now().isoformat(),
        "users": len(data.get("kullanicilar", {})),
        "orders": len(data.get("siparisler", {}))
    }), 200

def run_flask():
    logger.info(f"Flask başlatılıyor: port {PORT}")
    flask_app.run(host="0.0.0.0", port=PORT, debug=False, use_reloader=False)

# ═══════════════════════════════════════════
#              🚀 BAŞLAT
# ═══════════════════════════════════════════
def main():
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    logger.info("Flask thread başlatıldı")

    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CallbackQueryHandler(button_handler))
    app.add_handler(CommandHandler("puan_ekle", admin_puan_ekle))
    app.add_handler(CommandHandler("puan_eksilt", admin_puan_eksilt))
    app.add_handler(CommandHandler("banla", admin_banla))
    app.add_handler(CommandHandler("ban_ac", admin_ban_ac))
    app.add_handler(CommandHandler("admin_ekle", admin_ekle))
    app.add_handler(CommandHandler("admin_cikar", admin_cikar))
    app.add_handler(CommandHandler("duyuru", duyuru_yap))
    app.add_handler(CommandHandler("kisiler", kisiler_komutu))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, log_kaydet))

    logger.info("╔══════════════════════════╗")
    logger.info("   🤖  BOT ÇALIŞIYOR...")
    logger.info("╚══════════════════════════╝")
    app.run_polling(drop_pending_updates=True)

if __name__ == "__main__":
    main()
