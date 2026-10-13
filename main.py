import json
import re
import os
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Sigorta Mesaj API", version="1.0")

# CORS - her yerden erişime izin ver (istersen kısıtla)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# JSON dosyasını yükle (dosya main.py ile aynı klasörde olmalı)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
JSON_PATH = os.path.join(BASE_DIR, "sigorta.json")

with open(JSON_PATH, "r", encoding="utf-8") as f:
    DATA = json.load(f)


# ---------------------------
# Pydantic Modelleri
# ---------------------------
class Message(BaseModel):
    id: str
    displayName: Optional[str] = None
    originalarrivaltime: Optional[str] = None
    messagetype: Optional[str] = None
    content: Optional[str] = None
    from_: Optional[str] = None
    conversationid: Optional[str] = None


class Conversation(BaseModel):
    id: str
    displayName: Optional[str] = None
    version: Optional[int] = None
    properties: Optional[dict] = None
    threadProperties: Optional[dict] = None


class VehicleInfo(BaseModel):
    plate: Optional[str] = None
    tc: Optional[str] = None
    birthDate: Optional[str] = None
    brand: Optional[str] = None
    model: Optional[str] = None
    year: Optional[str] = None
    vehicleType: Optional[str] = None
    price: Optional[str] = None
    raw: str


# ---------------------------
# Yardımcı Fonksiyonlar
# ---------------------------
def get_all_messages():
    """Tüm mesajları tek bir listede döndürür."""
    messages = []
    for conv in DATA.get("conversations", []):
        for msg in conv.get("MessageList", []):
            msg_copy = msg.copy()
            msg_copy["from_"] = msg_copy.pop("from", None)
            messages.append(msg_copy)
    return messages


def extract_vehicle_info(content: str) -> Optional[VehicleInfo]:
    """Mesaj içeriğinden araç bilgilerini çıkarmaya çalışır."""
    if not content:
        return None

    lines = [l.strip() for l in content.split("\n") if l.strip()]
    if len(lines) < 3:
        return None

    plate = tc = birth = brand = model = year = vehicle_type = price = None

    # Plaka: 07UR553, 42ABC123 gibi
    for line in lines:
        if re.fullmatch(r"\d{2}[A-Z]{1,3}\d{2,4}", line):
            plate = line
            break

    # TC: 11 haneli rakam
    for line in lines:
        if re.fullmatch(r"\d{11}", line):
            tc = line
            break

    # Doğum tarihi
    for line in lines:
        if re.fullmatch(r"\d{2}[.,]\d{2}[.,]\d{4}", line):
            birth = line
            break

    # Marka: "100 - TOFAS-FIAT"
    for line in lines:
        m = re.match(r"(\d+)\s*-\s*(.+)", line)
        if m and ("-" in line or "," in line):
            brand = m.group(2).strip()
            break

    # Model
    for line in lines:
        m = re.match(r"(\d+)\s*-\s*(.+)", line)
        if m and brand and m.group(2).strip() != brand:
            model = m.group(2).strip()
            break

    # Yıl
    for line in lines:
        if re.fullmatch(r"(19|20)\d{2}", line):
            year = line
            break

    # Araç tipi
    for line in lines:
        if any(k in line.upper() for k in
               ["OTOMOBİL", "KAMYONET", "MİNİBÜS", "TRAKTÖR", "MOTORSİKLET", "ÇEKİCİ"]):
            vehicle_type = line
            break

    # Fiyat
    for line in lines:
        m = re.search(r"([\d.,]+)\s*(TL|tl)", line)
        if m:
            price = m.group(1)
            break

    if not any([plate, tc, brand, model]):
        return None

    return VehicleInfo(
        plate=plate, tc=tc, birthDate=birth,
        brand=brand, model=model, year=year,
        vehicleType=vehicle_type, price=price, raw=content,
    )


# ---------------------------
# Endpoint'ler
# ---------------------------
@app.get("/")
def root():
    return {
        "message": "Sigorta Mesaj API çalışıyor 🚀",
        "userId": DATA.get("userId"),
        "exportDate": DATA.get("exportDate"),
        "conversationCount": len(DATA.get("conversations", [])),
        "endpoints": [
            "/api/conversations",
            "/api/messages",
            "/api/vehicles",
            "/api/stats",
            "/docs",
        ],
    }


@app.get("/api/conversations", response_model=List[Conversation])
def list_conversations():
    result = []
    for conv in DATA.get("conversations", []):
        result.append(Conversation(
            id=conv.get("id"),
            displayName=conv.get("displayName"),
            version=conv.get("version"),
            properties=conv.get("properties"),
            threadProperties=conv.get("threadProperties"),
        ))
    return result


@app.get("/api/conversations/{conversation_id}")
def get_conversation(conversation_id: str):
    for conv in DATA.get("conversations", []):
        if conv.get("id") == conversation_id:
            return conv
    raise HTTPException(status_code=404, detail="Konuşma bulunamadı")


@app.get("/api/conversations/{conversation_id}/messages")
def get_conversation_messages(
    conversation_id: str,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    for conv in DATA.get("conversations", []):
        if conv.get("id") == conversation_id:
            messages = conv.get("MessageList", [])
            return {
                "total": len(messages),
                "limit": limit,
                "offset": offset,
                "messages": messages[offset:offset + limit],
            }
    raise HTTPException(status_code=404, detail="Konuşma bulunamadı")


@app.get("/api/messages")
def list_all_messages(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    search: Optional[str] = None,
):
    messages = get_all_messages()
    if search:
        messages = [m for m in messages
                    if search.lower() in (m.get("content") or "").lower()]
    return {
        "total": len(messages),
        "limit": limit,
        "offset": offset,
        "messages": messages[offset:offset + limit],
    }


@app.get("/api/messages/{message_id}")
def get_message(message_id: str):
    for msg in get_all_messages():
        if msg.get("id") == message_id:
            return msg
    raise HTTPException(status_code=404, detail="Mesaj bulunamadı")


@app.get("/api/vehicles", response_model=List[VehicleInfo])
def list_vehicles(limit: int = Query(100, ge=1, le=1000)):
    vehicles = []
    for msg in get_all_messages():
        content = msg.get("content") or ""
        info = extract_vehicle_info(content)
        if info:
            vehicles.append(info)
        if len(vehicles) >= limit:
            break
    return vehicles


@app.get("/api/stats")
def get_stats():
    messages = get_all_messages()
    if not messages:
        return {"messageCount": 0}
    dates = [m.get("originalarrivaltime") for m in messages if m.get("originalarrivaltime")]
    dates_sorted = sorted(dates)
    return {
        "messageCount": len(messages),
        "firstMessage": dates_sorted[0] if dates_sorted else None,
        "lastMessage": dates_sorted[-1] if dates_sorted else None,
        "conversationCount": len(DATA.get("conversations", [])),
        "uniqueSenders": len(set(m.get("from_") for m in messages if m.get("from_"))),
    }
