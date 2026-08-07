from fastapi import FastAPI, APIRouter, HTTPException, Depends, Header, Query, Request
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import re
import random
import logging
import difflib
import asyncio
import jwt
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone, timedelta

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]
JWT_SECRET = os.environ['JWT_SECRET']

app = FastAPI()
api_router = APIRouter(prefix="/api")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ---------- HTTP Method Override middleware ----------
# Some hosting providers / proxies (nginx, Cloudflare, some shared hosts)
# only forward GET/POST and block PUT/PATCH/DELETE -> client gets HTTP 405
# ("Method Not Allowed"). The frontend sends an X-HTTP-Method-Override
# header alongside a real POST; this middleware rewrites the request so it
# reaches the right FastAPI route handler.
class MethodOverrideMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        override = request.headers.get("x-http-method-override") or request.headers.get("X-HTTP-Method-Override")
        if override and override.upper() != request.method.upper():
            # Rebuild the request scope with the override method
            scope = dict(request.scope)
            scope["method"] = override.upper()
            new_request = Request(scope, receive=request.receive)
            return await call_next(new_request)
        return await call_next(request)


def now():
    return datetime.now(timezone.utc)


def iso(dt=None):
    return (dt or now()).isoformat()


def uid():
    return str(uuid.uuid4())


# ---------- Models ----------
class SendOtpReq(BaseModel):
    phone: str


class VerifyOtpReq(BaseModel):
    phone: str
    code: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    language: Optional[str] = "uz"


class ProfileReq(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    language: Optional[str] = None


class AddressReq(BaseModel):
    label: str
    text: str
    lat: Optional[float] = None
    lng: Optional[float] = None


class LocationReq(BaseModel):
    lat: float
    lng: float


class PromoReq(BaseModel):
    code: str
    subtotal: float


class OrderItemReq(BaseModel):
    product_id: str
    qty: int
    variation: Optional[str] = None


class OrderReq(BaseModel):
    items: List[OrderItemReq]
    address_text: str
    address_lat: Optional[float] = None
    address_lng: Optional[float] = None
    delivery_method: str = "courier"  # courier | pickup
    payment_method: str = "cash"
    comment: Optional[str] = ""
    promo_code: Optional[str] = None


class ReviewReq(BaseModel):
    rating: int
    text: str


class SellerApplyReq(BaseModel):
    shop_name: str
    document: Optional[str] = ""
    shop_lat: Optional[float] = None
    shop_lng: Optional[float] = None


class MarkupReq(BaseModel):
    percent: float


class BulkMarkupReq(BaseModel):
    percent: float
    only_without_override: bool = False


class CourierApplyReq(BaseModel):
    zone: str = "Toshkent"
    lat: Optional[float] = None
    lng: Optional[float] = None


class ProductReq(BaseModel):
    name_uz: str
    name_ru: str = ""
    name_en: str = ""
    desc_uz: str = ""
    desc_ru: str = ""
    desc_en: str = ""
    category_id: str
    price: float
    old_price: Optional[float] = None
    cost_price: Optional[float] = None  # tannarx (sof foyda hisobi uchun)
    box_price: Optional[float] = None
    units_per_box: int = 0
    images: List[str] = []
    stock: int = 0
    variations: List[Dict[str, Any]] = []


class ActionReq(BaseModel):
    action: str
    reason: Optional[str] = ""


class StatusReq(BaseModel):
    status: str


class CourierFinalizeItemReq(BaseModel):
    index: int
    action: str = "delivered"  # delivered | returned


class CourierFinalizeReq(BaseModel):
    items: List[CourierFinalizeItemReq]


class ToggleReq(BaseModel):
    online: bool


class CategoryReq(BaseModel):
    name_uz: str
    name_ru: str = ""
    name_en: str = ""
    icon: str = "package"
    parent_id: Optional[str] = None
    order: int = 0
    preview_image: Optional[str] = None


class BannerReq(BaseModel):
    image: str
    title: str
    link_type: str = "none"
    link_id: Optional[str] = None
    expires_at: Optional[str] = None


class PromoCreateReq(BaseModel):
    code: str
    type: str = "percent"
    value: float
    min_cart: float = 0
    limit: int = 100
    expires_at: Optional[str] = None


class FlashReq(BaseModel):
    product_id: str
    price: float
    hours: int = 24


class SettingsReq(BaseModel):
    delivery_fee: Optional[float] = None
    min_order: Optional[float] = None
    work_hours: Optional[str] = None
    contact: Optional[str] = None
    default_markup_percent: Optional[float] = None


class CourierCreateReq(BaseModel):
    phone: str
    first_name: str
    zone: str = "Toshkent"


class BlockReq(BaseModel):
    blocked: bool


# ---------- Auth helpers ----------
def make_token(user_id: str, role: str):
    return jwt.encode({"sub": user_id, "role": role, "exp": now() + timedelta(days=30)}, JWT_SECRET, algorithm="HS256")


async def get_user_optional(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        return None
    try:
        payload = jwt.decode(authorization[7:], JWT_SECRET, algorithms=["HS256"])
        user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0})
        if user and user.get("blocked"):
            return None
        return user
    except Exception:
        return None


async def get_user(authorization: Optional[str] = Header(None)):
    user = await get_user_optional(authorization)
    if not user:
        raise HTTPException(401, "Avtorizatsiya talab qilinadi")
    return user


async def get_admin(user=Depends(get_user)):
    if user["role"] not in ("admin", "moderator"):
        raise HTTPException(403, "Ruxsat yo'q")
    return user


def public_user(u):
    u = {k: v for k, v in u.items() if k != "_id"}
    return u


async def notify(user_id: str, title: str, body: str):
    await db.notifications.insert_one({"id": uid(), "user_id": user_id, "title": title, "body": body, "read": False, "created_at": iso()})


TASHKENT_CENTER = (41.311081, 69.240562)


async def get_settings():
    return await db.settings.find_one({"id": "main"}) or {}


async def geocode_best_effort(address_text: str):
    """Free geocoding via OpenStreetMap Nominatim. Best-effort only — never raises."""
    try:
        import httpx
        q = address_text if "toshkent" in address_text.lower() or "tashkent" in address_text.lower() else f"{address_text}, Toshkent"
        async with httpx.AsyncClient(timeout=4.0) as c:
            r = await c.get(
                "https://nominatim.openstreetmap.org/search",
                params={"q": q, "format": "json", "limit": 1},
                headers={"User-Agent": "UzMarket/1.0 (delivery-app)"},
            )
            data = r.json()
            if data:
                return float(data[0]["lat"]), float(data[0]["lon"])
    except Exception:
        pass
    return None


def shop_location(seller_user: Optional[dict]):
    if seller_user:
        si = seller_user.get("seller_info") or {}
        if si.get("shop_lat") is not None and si.get("shop_lng") is not None:
            return si["shop_lat"], si["shop_lng"]
        addrs = seller_user.get("addresses") or []
        for a in addrs:
            if a.get("lat") is not None and a.get("lng") is not None:
                return a["lat"], a["lng"]
    return TASHKENT_CENTER


# ---------- Auth ----------
@api_router.post("/auth/send-otp")
async def send_otp(req: SendOtpReq):
    phone = re.sub(r"[^\d+]", "", req.phone)
    if len(phone) < 9:
        raise HTTPException(400, "Telefon raqam noto'g'ri")
    minute_ago = iso(now() - timedelta(minutes=1))
    hour_ago = iso(now() - timedelta(hours=1))
    if await db.otps.find_one({"phone": phone, "created_at": {"$gt": minute_ago}}):
        raise HTTPException(429, "1 daqiqada faqat 1 ta SMS yuborish mumkin")
    if await db.otps.count_documents({"phone": phone, "created_at": {"$gt": hour_ago}}) >= 5:
        raise HTTPException(429, "1 soatda maksimum 5 ta SMS. Keyinroq urinib ko'ring")
    code = f"{random.randint(100000, 999999)}"
    await db.otps.insert_one({"id": uid(), "phone": phone, "code": code, "expires_at": iso(now() + timedelta(minutes=2)), "created_at": iso(), "used": False})
    await db.sms_log.insert_one({"id": uid(), "phone": phone, "text": f"UzMarket tasdiqlash kodi: {code}", "status": "demo", "sent_at": iso()})
    exists = await db.users.find_one({"phone": phone}) is not None
    logger.info(f"DEMO OTP for {phone}: {code}")
    return {"demo_code": code, "expires_in": 120, "exists": exists, "demo": True}


@api_router.post("/auth/verify-otp")
async def verify_otp(req: VerifyOtpReq):
    phone = re.sub(r"[^\d+]", "", req.phone)
    otp = await db.otps.find_one({"phone": phone, "code": req.code, "used": False}, sort=[("created_at", -1)])
    if not otp:
        raise HTTPException(400, "Kod noto'g'ri")
    if otp["expires_at"] < iso():
        raise HTTPException(400, "Kod muddati tugagan")
    await db.otps.update_one({"id": otp["id"]}, {"$set": {"used": True}})
    user = await db.users.find_one({"phone": phone})
    is_new = user is None
    if is_new:
        user = {
            "id": uid(), "phone": phone,
            "first_name": req.first_name or "Foydalanuvchi", "last_name": req.last_name or "",
            "role": "client", "language": req.language or "uz", "blocked": False,
            "referral_code": f"UZ{random.randint(10000, 99999)}",
            "favorites": [], "addresses": [], "created_at": iso(),
        }
        await db.users.insert_one(dict(user))
    if user.get("blocked"):
        raise HTTPException(403, "Akkaunt bloklangan")
    return {"token": make_token(user["id"], user["role"]), "user": public_user(user), "is_new": is_new}


@api_router.get("/auth/me")
async def me(user=Depends(get_user)):
    return public_user(user)


@api_router.put("/auth/profile")
async def update_profile(req: ProfileReq, user=Depends(get_user)):
    upd = {k: v for k, v in req.dict().items() if v is not None}
    if upd:
        await db.users.update_one({"id": user["id"]}, {"$set": upd})
    u = await db.users.find_one({"id": user["id"]}, {"_id": 0})
    return u


@api_router.delete("/auth/account")
async def delete_account(user=Depends(get_user)):
    await db.users.delete_one({"id": user["id"]})
    return {"ok": True}


# ---------- Addresses ----------
@api_router.post("/addresses")
async def add_address(req: AddressReq, user=Depends(get_user)):
    addr = {"id": uid(), **req.dict()}
    await db.users.update_one({"id": user["id"]}, {"$push": {"addresses": addr}})
    return addr


@api_router.delete("/addresses/{addr_id}")
async def del_address(addr_id: str, user=Depends(get_user)):
    await db.users.update_one({"id": user["id"]}, {"$pull": {"addresses": {"id": addr_id}}})
    return {"ok": True}


# ---------- Location ----------
@api_router.put("/users/me/location")
async def save_my_location(req: LocationReq, user=Depends(get_user)):
    loc = {"lat": req.lat, "lng": req.lng, "updated_at": iso()}
    await db.users.update_one({"id": user["id"]}, {"$set": {"saved_location": loc}})
    u = await db.users.find_one({"id": user["id"]}, {"_id": 0})
    return public_user(u)


@api_router.put("/seller/location")
async def save_shop_location(req: LocationReq, user=Depends(get_user)):
    if not user.get("seller_info"):
        raise HTTPException(403, "Siz sotuvchi emassiz")
    await db.users.update_one({"id": user["id"]}, {"$set": {"seller_info.shop_lat": req.lat, "seller_info.shop_lng": req.lng}})
    u = await db.users.find_one({"id": user["id"]}, {"_id": 0})
    return public_user(u)


# ---------- Catalog ----------
@api_router.get("/categories")
async def categories():
    cats = await db.categories.find({}, {"_id": 0}).sort("order", 1).to_list(200)
    products = await db.products.find({"images.0": {"$exists": True}}, {"_id": 0, "category_id": 1, "subcategory_id": 1, "images": 1}).to_list(1000)

    preview_map: Dict[str, str] = {}
    for p in products:
        image = (p.get("images") or [None])[0]
        if not image:
            continue
        for cid in (p.get("subcategory_id"), p.get("category_id")):
            if cid and cid not in preview_map:
                preview_map[cid] = image

    children_by_parent: Dict[str, List[str]] = {}
    for cat in cats:
        if cat.get("parent_id"):
            children_by_parent.setdefault(cat["parent_id"], []).append(cat["id"])

    for cat in cats:
        preview = cat.get("preview_image") or preview_map.get(cat["id"])
        if not preview:
            for child_id in children_by_parent.get(cat["id"], []):
                if preview_map.get(child_id):
                    preview = preview_map[child_id]
                    break
        cat["preview_image"] = preview
    return cats


@api_router.get("/banners")
async def banners():
    items = await db.banners.find({"active": True}, {"_id": 0}).sort("order", 1).to_list(20)
    return [b for b in items if not b.get("expires_at") or b["expires_at"] > iso()]


SETTINGS_CACHE: Dict[str, Any] = {"default_markup_percent": 0}


def product_out(p):
    p = {k: v for k, v in p.items() if k != "_id"}
    fs = p.get("flash_sale")
    base_price = float(p.get("price") or 0)
    markup = p.get("markup_percent")
    if markup is None:
        markup = SETTINGS_CACHE.get("default_markup_percent") or 0
    units_per_box = max(int(p.get("units_per_box") or 0), 0)
    seller_old_price = p.get("old_price")
    seller_box_price = p.get("box_price")
    if units_per_box > 0 and not seller_box_price:
        seller_box_price = round(base_price * units_per_box)

    marked_price = round(base_price * (1 + markup / 100)) if markup else base_price
    effective_old_price = None
    if seller_old_price is not None:
        effective_old_price = round(float(seller_old_price) * (1 + markup / 100)) if markup else float(seller_old_price)

    flash_active = bool(fs and fs.get("ends_at", "") > iso())
    seller_effective_price = float(fs["price"]) if flash_active else base_price
    effective_price = float(fs["price"]) if flash_active else marked_price

    effective_box_price = None
    seller_effective_box_price = None
    if units_per_box > 0:
        if flash_active:
            seller_effective_box_price = round(seller_effective_price * units_per_box)
            effective_box_price = round(effective_price * units_per_box)
        else:
            base_box = float(seller_box_price if seller_box_price else base_price * units_per_box)
            seller_effective_box_price = base_box
            effective_box_price = round(base_box * (1 + markup / 100)) if markup else base_box

    sale_mode = "box" if units_per_box > 0 else "piece"
    display_price = effective_box_price if sale_mode == "box" and effective_box_price is not None else effective_price
    display_old_price = None
    if sale_mode == "box" and effective_old_price is not None:
        display_old_price = round(effective_old_price * units_per_box)
    elif effective_old_price is not None:
        display_old_price = effective_old_price

    stock_total_units = int(p.get("stock", 0) or 0)
    display_stock = stock_total_units
    display_stock_label = "dona"
    if sale_mode == "box" and units_per_box > 0:
        display_stock = stock_total_units // units_per_box
        display_stock_label = "quti"

    p["effective_price"] = effective_price
    p["flash_active"] = flash_active
    p["seller_price"] = base_price
    p["seller_old_price"] = seller_old_price
    p["effective_old_price"] = effective_old_price
    p["seller_box_price"] = seller_box_price
    p["effective_box_price"] = effective_box_price
    p["seller_effective_price"] = seller_effective_price
    p["seller_effective_box_price"] = seller_effective_box_price
    p["seller_display_price"] = seller_effective_box_price if sale_mode == "box" and seller_effective_box_price is not None else seller_effective_price
    p["display_price"] = display_price
    p["display_old_price"] = display_old_price
    p["piece_price"] = effective_price
    p["sale_mode"] = sale_mode
    p["sale_units"] = units_per_box if sale_mode == "box" and units_per_box > 0 else 1
    p["units_per_box"] = units_per_box
    p["stock_unit"] = "dona"
    p["stock_total_units"] = stock_total_units
    p["display_stock"] = display_stock
    p["display_stock_label"] = display_stock_label
    p["markup_percent"] = markup
    p["out_of_stock"] = display_stock <= 0
    return p



PRODUCT_FILTER = {"status": "approved", "hidden": {"$ne": True}}


@api_router.get("/products")
async def list_products(
    search: Optional[str] = None, category_id: Optional[str] = None,
    seller_id: Optional[str] = None, min_price: Optional[float] = None,
    max_price: Optional[float] = None, discount: Optional[bool] = None,
    min_rating: Optional[float] = None, in_stock: Optional[bool] = None,
    sort: Optional[str] = "mix", skip: int = 0, limit: int = Query(20, le=50),
):
    q: Dict[str, Any] = dict(PRODUCT_FILTER)
    if category_id:
        q["$or"] = [{"category_id": category_id}, {"subcategory_id": category_id}]
    if seller_id:
        q["seller_id"] = seller_id
    if min_price is not None:
        q["price"] = {"$gte": min_price}
    if max_price is not None:
        q.setdefault("price", {})["$lte"] = max_price
    if discount:
        q["old_price"] = {"$ne": None, "$gt": 0}
    if min_rating:
        q["rating"] = {"$gte": min_rating}
    if in_stock:
        q["stock"] = {"$gt": 0}
    if search:
        rx = {"$regex": re.escape(search), "$options": "i"}
        q["$and"] = [{"$or": [{"name.uz": rx}, {"name.ru": rx}, {"name.en": rx}, {"desc.uz": rx}]}]
        await db.search_log.insert_one({"id": uid(), "q": search, "at": iso()})
    sort_map = {"cheap": [("price", 1)], "expensive": [("price", -1)], "new": [("created_at", -1)],
                "popular": [("sold", -1)], "rating": [("rating", -1)], "mix": [("pinned", -1), ("sold", -1)]}
    cursor = db.products.find(q).sort(sort_map.get(sort, sort_map["mix"])).skip(skip).limit(limit)
    items = [product_out(p) for p in await cursor.to_list(limit)]
    # category-name fallback: "telefon" matches category "Telefonlar"
    if search and not items and not skip:
        rx = {"$regex": re.escape(search), "$options": "i"}
        cats = await db.categories.find({"$or": [{"name.uz": rx}, {"name.ru": rx}, {"name.en": rx}]}).to_list(20)
        if cats:
            cat_ids = [c["id"] for c in cats]
            by_cat = await db.products.find({**PRODUCT_FILTER, "$or": [{"category_id": {"$in": cat_ids}}, {"subcategory_id": {"$in": cat_ids}}]}).limit(limit).to_list(limit)
            items = [product_out(p) for p in by_cat]
    # fuzzy fallback
    if search and not items and not skip:
        all_names = await db.products.find(PRODUCT_FILTER, {"_id": 0, "id": 1, "name": 1}).to_list(500)
        matched_ids = []
        for p in all_names:
            for lang_name in p["name"].values():
                for word in lang_name.lower().split():
                    if difflib.SequenceMatcher(None, search.lower(), word).ratio() > 0.6:
                        matched_ids.append(p["id"])
                        break
        if matched_ids:
            fuzzy = await db.products.find({"id": {"$in": matched_ids}}).to_list(limit)
            items = [product_out(p) for p in fuzzy]
    # fuzzy against category names: "tilifon" -> "Telefonlar"
    if search and not items and not skip:
        all_cats = await db.categories.find({}).to_list(200)
        fuzzy_cat_ids = []
        for c in all_cats:
            for lang_name in c["name"].values():
                for word in lang_name.lower().split():
                    if difflib.SequenceMatcher(None, search.lower(), word).ratio() > 0.55:
                        fuzzy_cat_ids.append(c["id"])
                        break
        if fuzzy_cat_ids:
            by_cat = await db.products.find({**PRODUCT_FILTER, "$or": [{"category_id": {"$in": fuzzy_cat_ids}}, {"subcategory_id": {"$in": fuzzy_cat_ids}}]}).limit(limit).to_list(limit)
            items = [product_out(p) for p in by_cat]
    total = await db.products.count_documents(q)
    return {"items": items, "total": total}


@api_router.get("/products/flash-sale")
async def flash_sale():
    items = await db.products.find({**PRODUCT_FILTER, "flash_sale.ends_at": {"$gt": iso()}}).to_list(20)
    return [product_out(p) for p in items]


@api_router.get("/products/recommendations")
async def recommendations(user=Depends(get_user_optional)):
    cat_ids = []
    if user:
        views = await db.views.find({"user_id": user["id"]}).sort("at", -1).to_list(20)
        cat_ids = list({v["category_id"] for v in views if v.get("category_id")})
    q = dict(PRODUCT_FILTER)
    if cat_ids:
        q["category_id"] = {"$in": cat_ids}
    items = await db.products.find(q).sort("sold", -1).limit(10).to_list(10)
    if len(items) < 6:
        more = await db.products.find(PRODUCT_FILTER).sort("views", -1).limit(10).to_list(10)
        seen = {p["id"] for p in items}
        items += [p for p in more if p["id"] not in seen]
    return [product_out(p) for p in items[:10]]


@api_router.get("/products/{pid}")
async def get_product(pid: str, user=Depends(get_user_optional)):
    p = await db.products.find_one({"id": pid})
    if not p:
        raise HTTPException(404, "Mahsulot topilmadi")
    await db.products.update_one({"id": pid}, {"$inc": {"views": 1}})
    if user:
        await db.views.insert_one({"id": uid(), "user_id": user["id"], "product_id": pid, "category_id": p.get("category_id"), "at": iso()})
    seller = await db.users.find_one({"id": p["seller_id"]}, {"_id": 0})
    out = product_out(p)
    if seller:
        count = await db.products.count_documents({"seller_id": seller["id"], **PRODUCT_FILTER})
        out["seller"] = {"id": seller["id"], "shop_name": seller.get("seller_info", {}).get("shop_name", "Do'kon"),
                        "rating": seller.get("seller_info", {}).get("rating", 5.0), "products_count": count}
    return out


@api_router.get("/products/{pid}/similar")
async def similar(pid: str):
    p = await db.products.find_one({"id": pid})
    if not p:
        return []
    items = await db.products.find({**PRODUCT_FILTER, "category_id": p.get("category_id"), "id": {"$ne": pid}}).limit(8).to_list(8)
    return [product_out(x) for x in items]


@api_router.get("/products/{pid}/reviews")
async def product_reviews(pid: str):
    return await db.reviews.find({"product_id": pid, "hidden": {"$ne": True}}, {"_id": 0}).sort("created_at", -1).to_list(100)


@api_router.post("/products/{pid}/reviews")
async def add_review(pid: str, req: ReviewReq, user=Depends(get_user)):
    bought = await db.orders.find_one({"client_id": user["id"], "status": "delivered", "items.product_id": pid})
    if not bought:
        raise HTTPException(403, "Faqat mahsulotni xarid qilganlar sharh yoza oladi")
    if await db.reviews.find_one({"product_id": pid, "client_id": user["id"]}):
        raise HTTPException(400, "Siz allaqachon sharh yozgansiz")
    rev = {"id": uid(), "product_id": pid, "client_id": user["id"],
           "client_name": f"{user['first_name']} {user.get('last_name', '')}".strip(),
           "rating": max(1, min(5, req.rating)), "text": req.text, "verified": True, "created_at": iso()}
    await db.reviews.insert_one(dict(rev))
    revs = await db.reviews.find({"product_id": pid, "hidden": {"$ne": True}}).to_list(1000)
    avg = round(sum(r["rating"] for r in revs) / len(revs), 1)
    await db.products.update_one({"id": pid}, {"$set": {"rating": avg, "reviews_count": len(revs)}})
    return {k: v for k, v in rev.items() if k != "_id"}


@api_router.get("/search/suggest")
async def suggest(q: str = ""):
    if not q:
        pop = await db.search_log.aggregate([{"$group": {"_id": "$q", "c": {"$sum": 1}}}, {"$sort": {"c": -1}}, {"$limit": 8}]).to_list(8)
        return {"suggestions": [p["_id"] for p in pop]}
    rx = {"$regex": re.escape(q), "$options": "i"}
    prods = await db.products.find({**PRODUCT_FILTER, "$or": [{"name.uz": rx}, {"name.ru": rx}, {"name.en": rx}]}, {"_id": 0, "name": 1}).limit(6).to_list(6)
    return {"suggestions": list({p["name"]["uz"] for p in prods})}


# ---------- Favorites ----------
@api_router.post("/favorites/{pid}")
async def toggle_favorite(pid: str, user=Depends(get_user)):
    favs = user.get("favorites", [])
    if pid in favs:
        await db.users.update_one({"id": user["id"]}, {"$pull": {"favorites": pid}})
        return {"favorited": False}
    await db.users.update_one({"id": user["id"]}, {"$push": {"favorites": pid}})
    return {"favorited": True}


@api_router.get("/favorites")
async def list_favorites(user=Depends(get_user)):
    items = await db.products.find({"id": {"$in": user.get("favorites", [])}}).to_list(100)
    return [product_out(p) for p in items]


# ---------- Promo ----------
@api_router.post("/promo/validate")
async def validate_promo(req: PromoReq, user=Depends(get_user)):
    promo = await db.promocodes.find_one({"code": req.code.upper(), "active": True}, {"_id": 0})
    if not promo:
        raise HTTPException(404, "Promokod topilmadi")
    if promo.get("expires_at") and promo["expires_at"] < iso():
        raise HTTPException(400, "Promokod muddati tugagan")
    if promo.get("used", 0) >= promo.get("limit", 0):
        raise HTTPException(400, "Promokod limiti tugagan")
    if req.subtotal < promo.get("min_cart", 0):
        raise HTTPException(400, f"Minimal savat summasi: {int(promo['min_cart']):,} so'm")
    discount = req.subtotal * promo["value"] / 100 if promo["type"] == "percent" else promo["value"]
    return {"code": promo["code"], "discount": min(discount, req.subtotal), "type": promo["type"], "value": promo["value"]}


# ---------- Orders ----------
STATUS_FLOW = ["new", "confirmed", "packing", "courier", "delivered"]


@api_router.post("/orders")
async def create_order(req: OrderReq, user=Depends(get_user)):
    if not req.items:
        raise HTTPException(400, "Savat bo'sh")
    settings = await db.settings.find_one({"id": "main"}) or {}
    delivery_fee = settings.get("delivery_fee", 15000) if req.delivery_method == "courier" else 0
    by_seller: Dict[str, list] = {}
    subtotal_all = 0.0
    for it in req.items:
        p = await db.products.find_one({"id": it.product_id})
        if not p or p.get("status") != "approved":
            raise HTTPException(400, "Mahsulot mavjud emas")
        out = product_out(p)
        sale_units = int(out.get("sale_units") or 1)
        requested_units = it.qty * sale_units
        if p.get("stock", 0) < requested_units:
            raise HTTPException(400, f"{p['name']['uz']}: omborda yetarli emas ({max(int(out.get('display_stock', 0) or 0), 0)} {out.get('display_stock_label', 'dona')})")
        price = float(out.get("display_price", out["effective_price"]))
        base_price = float(out.get("seller_display_price", out.get("seller_effective_price", p["price"])))
        subtotal_all += price * it.qty
        by_seller.setdefault(p["seller_id"], []).append({
            "item_id": uid(), "product_id": p["id"], "name": p["name"], "image": (p.get("images") or [""])[0],
            "price": price, "base_price": base_price, "qty": it.qty, "variation": it.variation,
            "sale_mode": out.get("sale_mode", "piece"), "units_per_box": int(out.get("units_per_box") or 0),
            "ordered_units": requested_units,
            "delivery_status": "pending"})
    discount_all = 0.0
    promo = None
    if req.promo_code:
        promo = await db.promocodes.find_one({"code": req.promo_code.upper(), "active": True})
        if promo and (not promo.get("expires_at") or promo["expires_at"] > iso()) and promo.get("used", 0) < promo.get("limit", 0) and subtotal_all >= promo.get("min_cart", 0):
            discount_all = subtotal_all * promo["value"] / 100 if promo["type"] == "percent" else promo["value"]
            await db.promocodes.update_one({"id": promo["id"]}, {"$inc": {"used": 1}})
        else:
            promo = None
    group_id = uid()
    counter = await db.counters.find_one_and_update({"id": "order"}, {"$inc": {"seq": 1}}, upsert=True, return_document=True)
    base_num = 1000 + counter["seq"]
    addr_lat, addr_lng = req.address_lat, req.address_lng
    if addr_lat is None or addr_lng is None:
        geo = await geocode_best_effort(req.address_text)
        if geo:
            addr_lat, addr_lng = geo
    orders = []
    idx = 0
    for seller_id, items in by_seller.items():
        idx += 1
        seller_user = await db.users.find_one({"id": seller_id}, {"_id": 0})
        slat, slng = shop_location(seller_user)
        sub = sum(i["price"] * i["qty"] for i in items)
        seller_sub = sum(i["base_price"] * i["qty"] for i in items)
        share = sub / subtotal_all if subtotal_all else 0
        disc = round(discount_all * share)
        dfee = delivery_fee if idx == 1 else 0
        order = {
            "id": uid(), "number": f"#{base_num}-{idx}" if len(by_seller) > 1 else f"#{base_num}",
            "group_id": group_id, "client_id": user["id"],
            "client_name": f"{user['first_name']} {user.get('last_name', '')}".strip(), "client_phone": user["phone"],
            "seller_id": seller_id, "items": items, "subtotal": sub, "seller_subtotal": seller_sub, "delivery_fee": dfee,
            "discount": disc, "total": sub + dfee - disc, "promo_code": promo["code"] if promo else None,
            "status": "new", "address_text": req.address_text, "address_lat": addr_lat, "address_lng": addr_lng,
            "delivery_location": {"lat": addr_lat, "lng": addr_lng} if addr_lat is not None and addr_lng is not None else None,
            "pickup_location": {"lat": slat, "lng": slng},
            "delivery_method": req.delivery_method,
            "payment_method": req.payment_method, "comment": req.comment, "courier_id": None,
            "status_history": [{"status": "new", "at": iso()}], "created_at": iso(),
        }
        await db.orders.insert_one(dict(order))
        orders.append({k: v for k, v in order.items() if k != "_id"})
        for it in items:
            ordered_units = int(it.get("ordered_units") or it.get("qty", 0) or 0)
            newp = await db.products.find_one_and_update({"id": it["product_id"]}, {"$inc": {"stock": -ordered_units, "sold": ordered_units}}, return_document=True)
            if newp and newp.get("stock", 0) <= 0:
                await notify(seller_id, "Mahsulot tugadi", f"{newp['name']['uz']} ombordagi qoldig'i tugadi")
        await notify(seller_id, "Yangi buyurtma", f"{order['number']} — {int(order['total']):,} so'm")
    admins = await db.users.find({"role": "admin"}).to_list(10)
    for a in admins:
        await notify(a["id"], "Yangi buyurtma", f"#{base_num} — {user['first_name']}, {int(subtotal_all + delivery_fee - discount_all):,} so'm")
    return {"orders": orders, "group_id": group_id, "number": f"#{base_num}"}


@api_router.get("/orders/my")
async def my_orders(user=Depends(get_user)):
    return await db.orders.find({"client_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(200)


@api_router.get("/orders/{oid}")
async def get_order(oid: str, user=Depends(get_user)):
    o = await db.orders.find_one({"id": oid}, {"_id": 0})
    if not o:
        raise HTTPException(404, "Buyurtma topilmadi")
    if o.get("courier_id"):
        c = await db.users.find_one({"id": o["courier_id"]}, {"_id": 0})
        if c:
            o["courier"] = {"name": c["first_name"], "phone": c["phone"]}
    return o


@api_router.post("/orders/{oid}/cancel")
async def cancel_order(oid: str, user=Depends(get_user)):
    o = await db.orders.find_one({"id": oid, "client_id": user["id"]})
    if not o or o["status"] not in ("new", "confirmed"):
        raise HTTPException(400, "Bu buyurtmani bekor qilib bo'lmaydi")
    await set_order_status(o, "cancelled", "Mijoz bekor qildi")
    return {"ok": True}


def parse_iso_dt(value: Optional[str]):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def status_at(order: dict, target: str):
    for h in reversed(order.get("status_history") or []):
        if h.get("status") == target and h.get("at"):
            return h["at"]
    return None


def item_name(item: dict):
    name = item.get("name")
    if isinstance(name, dict):
        return name.get("uz") or name.get("ru") or name.get("en") or item.get("product_id") or "Mahsulot"
    return name or item.get("product_id") or "Mahsulot"


def item_line_total(item: dict) -> float:
    return float(item.get("price", 0) or 0) * int(item.get("qty", 0) or 0)


def item_line_base_total(item: dict) -> float:
    return float(item.get("base_price", item.get("price", 0)) or 0) * int(item.get("qty", 0) or 0)


def delivered_item_qty(order: dict) -> int:
    items = order.get("items") or []
    if any(i.get("delivery_status") for i in items):
        return sum(int(i.get("qty", 0) or 0) for i in items if i.get("delivery_status") != "returned")
    return sum(int(i.get("qty", 0) or 0) for i in items)


def returned_item_qty(order: dict) -> int:
    return sum(int(i.get("qty", 0) or 0) for i in (order.get("items") or []) if i.get("delivery_status") == "returned")


def returned_item_amount(order: dict) -> float:
    return sum(item_line_base_total(i) for i in (order.get("items") or []) if i.get("delivery_status") == "returned")


def seller_today_snapshot(user: dict, orders: Optional[List[dict]] = None):
    si = user.get("seller_info", {})
    orders = orders if orders is not None else []
    today = iso()[:10]
    reset_at = parse_iso_dt(si.get("stats_reset_at"))

    def after_reset(ts: Optional[str]) -> bool:
        if reset_at is None:
            return True
        dt = parse_iso_dt(ts)
        return bool(dt and dt >= reset_at)

    todays = []
    for o in orders:
        created_ts = o.get("created_at") or status_at(o, "new")
        if (created_ts or "")[:10] != today:
            continue
        if not after_reset(created_ts):
            continue
        todays.append(o)

    return {
        "today_orders": len(todays),
        "today_amount": sum(float(o.get("seller_subtotal", 0) or 0) for o in todays),
        "today_returns_count": sum(1 for o in todays if (o.get("returned_items_count") or returned_item_qty(o)) > 0),
        "today_returns_amount": sum(returned_item_amount(o) for o in todays),
        "stats_reset_at": si.get("stats_reset_at"),
        "today_orders_list": [
            {
                "id": o["id"],
                "number": o["number"],
                "status": o.get("status"),
                "created_at": o.get("created_at"),
                "amount": float(o.get("seller_subtotal", 0) or 0),
                "returned_items_count": o.get("returned_items_count") or returned_item_qty(o),
            }
            for o in sorted(todays, key=lambda x: x.get("created_at", ""), reverse=True)[:20]
        ],
    }


def courier_fee_for_order(order: dict) -> float:
    delivered_qty = delivered_item_qty(order)
    if delivered_qty <= 0:
        return 0.0
    return float(order.get("original_delivery_fee", order.get("delivery_fee", 0)) or 0)


async def build_courier_stats(user: dict, orders: Optional[List[dict]] = None):
    ci = user.get("courier_info", {})
    orders = orders if orders is not None else await db.orders.find({"courier_id": user["id"]}, {"_id": 0}).to_list(1000)
    today = iso()[:10]
    reset_at = parse_iso_dt(ci.get("stats_reset_at"))

    def after_reset(ts: Optional[str]) -> bool:
        if reset_at is None:
            return True
        dt = parse_iso_dt(ts)
        return bool(dt and dt >= reset_at)

    active_orders = [o for o in orders if o.get("status") == "courier"]
    taken_today = [o for o in orders if (status_at(o, "courier") or "")[:10] == today]
    delivered_today = [o for o in orders if (status_at(o, "delivered") or "")[:10] == today]
    delivered_since_reset = [o for o in orders if status_at(o, "delivered") and after_reset(status_at(o, "delivered"))]

    return {
        "deliveries": len(delivered_since_reset),
        "earnings": sum(courier_fee_for_order(o) for o in delivered_since_reset),
        "today_deliveries": len(delivered_today),
        "today_earnings": sum(courier_fee_for_order(o) for o in delivered_today),
        "today_taken_count": len(taken_today),
        "today_taken_total": sum(float(o.get("total", 0) or 0) for o in taken_today),
        "active_count": len(active_orders),
        "active_total": sum(float(o.get("total", 0) or 0) for o in active_orders),
        "online": ci.get("online", False),
        "zone": ci.get("zone", ""),
        "stats_reset_at": ci.get("stats_reset_at"),
    }


async def finalize_courier_order(order: dict, selections: List[CourierFinalizeItemReq], courier_user: dict):
    if order.get("status") != "courier":
        raise HTTPException(400, "Buyurtma hali kuryerda emas")

    items = [dict(i) for i in (order.get("items") or [])]
    if not items:
        raise HTTPException(400, "Buyurtmada mahsulot topilmadi")

    selection_map = {int(s.index): s.action for s in selections}
    delivered_qty = 0
    returned_qty = 0
    delivered_total = 0.0
    returned_total = 0.0
    delivered_seller_total = 0.0
    returned_names = []

    for idx, item in enumerate(items):
        action = selection_map.get(idx, item.get("delivery_status") or "delivered")
        if action not in ("delivered", "returned"):
            raise HTTPException(400, "Mahsulot holati noto'g'ri")
        item["delivery_status"] = action
        item["finalized_at"] = iso()
        if action == "returned":
            returned_qty += int(item.get("qty", 0) or 0)
            returned_total += item_line_total(item)
            returned_names.append(item_name(item))
            await db.products.update_one({"id": item["product_id"]}, {"$inc": {"stock": int(item.get("qty", 0) or 0), "sold": -int(item.get("qty", 0) or 0)}})
        else:
            delivered_qty += int(item.get("qty", 0) or 0)
            delivered_total += item_line_total(item)
            delivered_seller_total += item_line_base_total(item)

    original_subtotal = float(order.get("original_subtotal", order.get("subtotal", 0)) or 0)
    original_discount = float(order.get("original_discount", order.get("discount", 0)) or 0)
    original_delivery_fee = float(order.get("original_delivery_fee", order.get("delivery_fee", 0)) or 0)
    original_total = float(order.get("original_total", order.get("total", 0)) or 0)
    delivered_discount = round(original_discount * (delivered_total / original_subtotal)) if original_subtotal else 0
    returned_discount = max(original_discount - delivered_discount, 0)
    final_delivery_fee = original_delivery_fee if delivered_qty > 0 else 0
    final_total = max(delivered_total + final_delivery_fee - delivered_discount, 0)
    courier_fee = final_delivery_fee

    note = "Kuryer yetkazib berishni yakunladi"
    if returned_qty > 0:
        note += f". Qaytgan mahsulotlar: {', '.join(returned_names)}"

    await db.orders.update_one(
        {"id": order["id"]},
        {
            "$set": {
                "items": items,
                "status": "delivered",
                "has_returns": returned_qty > 0,
                "delivered_items_count": delivered_qty,
                "returned_items_count": returned_qty,
                "delivered_subtotal": delivered_total,
                "returned_subtotal": returned_total,
                "seller_subtotal": delivered_seller_total,
                "original_subtotal": original_subtotal,
                "subtotal": delivered_total,
                "original_discount": original_discount,
                "discount": delivered_discount,
                "returned_discount": returned_discount,
                "original_delivery_fee": original_delivery_fee,
                "delivery_fee": final_delivery_fee,
                "original_total": original_total,
                "total": final_total,
                "delivery_completed_at": iso(),
            },
            "$push": {"status_history": {"status": "delivered", "at": iso(), "note": note}},
        },
    )

    client_body = "Holat: Yetkazildi"
    if returned_qty > 0:
        client_body += f". Qaytgan mahsulotlar soni: {returned_qty}"
    await notify(order["client_id"], f"Buyurtma {order['number']}", client_body)

    seller_body = f"{order['number']} yakunlandi. Yetkazilgan mahsulotlar: {delivered_qty} ta"
    if returned_qty > 0:
        seller_body += f", qaytganlar: {returned_qty} ta"
    await notify(order["seller_id"], "Buyurtma yakunlandi", seller_body)

    if delivered_seller_total > 0:
        await db.users.update_one({"id": order["seller_id"]}, {"$inc": {"seller_info.balance": delivered_seller_total}})
    if courier_fee > 0:
        await db.users.update_one({"id": courier_user["id"]}, {"$inc": {"courier_info.earnings": courier_fee, "courier_info.deliveries": 1}})

    admins = await db.users.find({"role": "admin"}, {"_id": 0}).to_list(20)
    for admin in admins:
        admin_body = f"{order['number']} • Kuryer: {courier_user.get('first_name', '')} • Mijoz: {order.get('client_name', '')}"
        if returned_qty > 0:
            admin_body += f" • Qaytdi: {returned_qty} ta"
        await notify(admin["id"], "Kuryer buyurtmani yopdi", admin_body)


async def set_order_status(order, status, note=""):
    await db.orders.update_one({"id": order["id"]}, {"$set": {"status": status}, "$push": {"status_history": {"status": status, "at": iso(), "note": note}}})
    labels = {"confirmed": "Tasdiqlandi", "packing": "Yig'ilmoqda", "courier": "Kuryerda", "delivered": "Yetkazildi", "cancelled": "Bekor qilindi", "new": "Yangi"}
    await notify(order["client_id"], f"Buyurtma {order['number']}", f"Holat: {labels.get(status, status)}")
    if status == "cancelled":
        for it in order["items"]:
            await db.products.update_one({"id": it["product_id"]}, {"$inc": {"stock": it["qty"], "sold": -it["qty"]}})
    if status == "delivered":
        earn = order.get("seller_subtotal", order["subtotal"])
        await db.users.update_one({"id": order["seller_id"]}, {"$inc": {"seller_info.balance": earn}})


# ---------- Notifications ----------
@api_router.get("/notifications")
async def notifications(user=Depends(get_user)):
    items = await db.notifications.find({"user_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(100)
    await db.notifications.update_many({"user_id": user["id"]}, {"$set": {"read": True}})
    return items


# ---------- Seller ----------
@api_router.post("/seller/apply")
async def seller_apply(req: SellerApplyReq, user=Depends(get_user)):
    if user.get("seller_info"):
        raise HTTPException(400, "Ariza allaqachon yuborilgan")
    shop_lat, shop_lng = req.shop_lat, req.shop_lng
    if shop_lat is None or shop_lng is None:
        addrs = user.get("addresses") or []
        if addrs and addrs[0].get("lat") is not None:
            shop_lat, shop_lng = addrs[0]["lat"], addrs[0]["lng"]
    await db.users.update_one({"id": user["id"]}, {"$set": {"seller_info": {
        "shop_name": req.shop_name, "document": req.document, "approved": False, "rejected": False,
        "commission": None, "balance": 0, "rating": 5.0, "applied_at": iso(),
        "shop_lat": shop_lat, "shop_lng": shop_lng}}})
    admins = await db.users.find({"role": "admin"}).to_list(10)
    for a in admins:
        await notify(a["id"], "Yangi sotuvchi arizasi", f"{req.shop_name} — {user['phone']}")
    return {"ok": True}


async def get_seller(user=Depends(get_user)):
    si = user.get("seller_info")
    if not si or not si.get("approved"):
        raise HTTPException(403, "Sotuvchi tasdiqlanmagan")
    return user


@api_router.get("/seller/products")
async def seller_products(user=Depends(get_seller)):
    items = await db.products.find({"seller_id": user["id"]}).sort("created_at", -1).to_list(500)
    return [product_out(p) for p in items]


@api_router.post("/seller/products")
async def seller_add_product(req: ProductReq, user=Depends(get_seller)):
    p = {
        "id": uid(), "seller_id": user["id"],
        "name": {"uz": req.name_uz, "ru": req.name_ru or req.name_uz, "en": req.name_en or req.name_uz},
        "desc": {"uz": req.desc_uz, "ru": req.desc_ru or req.desc_uz, "en": req.desc_en or req.desc_uz},
        "category_id": req.category_id, "price": req.price, "old_price": req.old_price,
        "cost_price": req.cost_price or 0,
        "box_price": req.box_price,
        "units_per_box": max(int(req.units_per_box or 0), 0),
        "images": req.images or ["https://images.unsplash.com/photo-1553456558-aff63285bdd1?w=600&q=80"],
        "stock": req.stock, "variations": req.variations, "status": "pending", "hidden": False,
        "pinned": False, "rating": 0, "reviews_count": 0, "views": 0, "sold": 0, "created_at": iso(),
    }
    await db.products.insert_one(dict(p))
    return product_out(p)


@api_router.put("/seller/products/{pid}")
async def seller_edit_product(pid: str, req: ProductReq, user=Depends(get_seller)):
    p = await db.products.find_one({"id": pid, "seller_id": user["id"]})
    if not p:
        raise HTTPException(404, "Topilmadi")
    upd = {
        "name": {"uz": req.name_uz, "ru": req.name_ru or req.name_uz, "en": req.name_en or req.name_uz},
        "desc": {"uz": req.desc_uz, "ru": req.desc_ru or req.desc_uz, "en": req.desc_en or req.desc_uz},
        "category_id": req.category_id, "price": req.price, "old_price": req.old_price,
        "cost_price": req.cost_price if req.cost_price is not None else p.get("cost_price", 0),
        "box_price": req.box_price,
        "units_per_box": max(int(req.units_per_box or 0), 0),
        "stock": req.stock, "status": "pending",
    }
    if req.images:
        upd["images"] = req.images
    await db.products.update_one({"id": pid}, {"$set": upd})
    return {"ok": True}


@api_router.post("/seller/products/{pid}/toggle-hide")
async def seller_hide(pid: str, user=Depends(get_seller)):
    p = await db.products.find_one({"id": pid, "seller_id": user["id"]})
    if not p:
        raise HTTPException(404, "Topilmadi")
    await db.products.update_one({"id": pid}, {"$set": {"hidden": not p.get("hidden", False)}})
    return {"hidden": not p.get("hidden", False)}


@api_router.delete("/seller/products/{pid}")
async def seller_del_product(pid: str, user=Depends(get_seller)):
    await db.products.delete_one({"id": pid, "seller_id": user["id"]})
    return {"ok": True}


def seller_order_out(o):
    """Sellers must never see buyer's personal data — only the order id/number and what they need to pack."""
    items = [{
        "product_id": i.get("product_id"), "name": i.get("name"), "image": i.get("image"),
        "price": i.get("base_price", i.get("price")), "qty": i.get("qty"), "variation": i.get("variation"),
        "delivery_status": i.get("delivery_status", "delivered" if o.get("status") == "delivered" else "pending"),
    } for i in o.get("items", [])]
    return {
        "id": o["id"], "number": o["number"], "items": items,
        "earn_total": o.get("seller_subtotal", sum(i["price"] * i["qty"] for i in items if i.get("delivery_status") != "returned")),
        "status": o["status"], "delivery_method": o.get("delivery_method"),
        "created_at": o.get("created_at"),
        "has_returns": o.get("has_returns", False),
        "returned_items_count": o.get("returned_items_count", 0),
        "delivered_items_count": o.get("delivered_items_count", 0),
    }


@api_router.get("/seller/orders")
async def seller_orders(user=Depends(get_seller)):
    items = await db.orders.find({"seller_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(300)
    return [seller_order_out(o) for o in items]


@api_router.post("/seller/orders/{oid}/action")
async def seller_order_action(oid: str, req: ActionReq, user=Depends(get_seller)):
    o = await db.orders.find_one({"id": oid, "seller_id": user["id"]})
    if not o:
        raise HTTPException(404, "Topilmadi")
    if req.action == "accept" and o["status"] == "new":
        await set_order_status(o, "confirmed")
    elif req.action == "reject" and o["status"] in ("new", "confirmed"):
        await set_order_status(o, "cancelled", req.reason or "Sotuvchi rad etdi")
    elif req.action == "packed" and o["status"] == "confirmed":
        await set_order_status(o, "packing")
    else:
        raise HTTPException(400, "Noto'g'ri harakat")
    return {"ok": True}


@api_router.get("/seller/stats")
async def seller_stats(user=Depends(get_seller)):
    orders = await db.orders.find({"seller_id": user["id"]}).to_list(2000)
    snap = seller_today_snapshot(user, orders)
    prods = await db.products.find({"seller_id": user["id"]}).sort("sold", -1).to_list(100)
    return {
        "today_orders": snap["today_orders"],
        "today_sales": snap["today_amount"],
        "today_returns_count": snap["today_returns_count"],
        "today_returns_amount": snap["today_returns_amount"],
        "stats_reset_at": snap.get("stats_reset_at"),
        "top_products": [{"name": p["name"]["uz"], "sold": p.get("sold", 0), "views": p.get("views", 0)} for p in prods[:5]],
        "today_orders_list": snap["today_orders_list"],
    }


# ---------- Courier ----------
async def get_courier(user=Depends(get_user)):
    if user["role"] != "courier":
        raise HTTPException(403, "Faqat kuryerlar uchun")
    return user


@api_router.post("/courier/apply")
async def courier_apply(req: CourierApplyReq, user=Depends(get_user)):
    if user["role"] == "courier":
        raise HTTPException(400, "Siz allaqachon kuryersiz")
    if user["role"] in ("admin", "moderator"):
        raise HTTPException(400, "Bu amal uchun ruxsat yo'q")
    lat, lng = req.lat, req.lng
    if lat is None or lng is None:
        addrs = user.get("addresses") or []
        if addrs and addrs[0].get("lat") is not None:
            lat, lng = addrs[0]["lat"], addrs[0]["lng"]
    await db.users.update_one({"id": user["id"]}, {"$set": {
        "role": "courier",
        "courier_info": {"online": False, "zone": req.zone, "earnings": 0, "deliveries": 0, "lat": lat, "lng": lng, "stats_reset_at": None},
    }})
    u = await db.users.find_one({"id": user["id"]}, {"_id": 0})
    return public_user(u)


async def order_with_route(o: dict):
    o = {k: v for k, v in o.items() if k != "_id"}
    seller = await db.users.find_one({"id": o["seller_id"]}, {"_id": 0})
    o["shop_name"] = seller.get("seller_info", {}).get("shop_name", "Do'kon") if seller else "Do'kon"
    o["shop_phone"] = seller.get("phone", "") if seller else ""
    o["shop_contact_name"] = (f"{seller.get('first_name', '')} {seller.get('last_name', '')}".strip() if seller else "")
    pu = o.get("pickup_location") or {}
    if pu.get("lat") is not None and pu.get("lng") is not None:
        o["shop_lat"], o["shop_lng"] = pu["lat"], pu["lng"]
    else:
        o["shop_lat"], o["shop_lng"] = shop_location(seller)
    dl = o.get("delivery_location") or {}
    if dl.get("lat") is not None and dl.get("lng") is not None:
        o["address_lat"], o["address_lng"] = dl["lat"], dl["lng"]
    if o.get("address_lat") is None or o.get("address_lng") is None:
        o["address_lat"], o["address_lng"] = TASHKENT_CENTER
        o["location_approx"] = True
    return o


@api_router.post("/courier/toggle")
async def courier_toggle(req: ToggleReq, user=Depends(get_courier)):
    await db.users.update_one({"id": user["id"]}, {"$set": {"courier_info.online": req.online}})
    return {"online": req.online}


@api_router.get("/courier/available")
async def courier_available(user=Depends(get_courier)):
    orders = await db.orders.find({"status": "packing", "courier_id": None, "delivery_method": "courier"}, {"_id": 0}).sort("created_at", 1).to_list(50)
    return [await order_with_route(o) for o in orders]


@api_router.get("/courier/my")
async def courier_my(user=Depends(get_courier)):
    orders = await db.orders.find({"courier_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(200)
    return [await order_with_route(o) for o in orders]


@api_router.post("/courier/orders/{oid}/accept")
async def courier_accept(oid: str, user=Depends(get_courier)):
    o = await db.orders.find_one({"id": oid, "status": "packing", "courier_id": None})
    if not o:
        raise HTTPException(400, "Buyurtma band yoki mavjud emas")
    await db.orders.update_one({"id": oid}, {"$set": {"courier_id": user["id"]}})
    o["courier_id"] = user["id"]
    await set_order_status(o, "courier")
    return {"ok": True}


@api_router.post("/courier/orders/{oid}/status")
async def courier_status(oid: str, req: StatusReq, user=Depends(get_courier)):
    o = await db.orders.find_one({"id": oid, "courier_id": user["id"]})
    if not o:
        raise HTTPException(404, "Topilmadi")
    if req.status == "delivered" and o["status"] == "courier":
        selections = [CourierFinalizeItemReq(index=idx, action="delivered") for idx, _ in enumerate(o.get("items") or [])]
        await finalize_courier_order(o, selections, user)
    else:
        raise HTTPException(400, "Noto'g'ri status")
    return {"ok": True}


@api_router.post("/courier/orders/{oid}/complete")
async def courier_complete_order(oid: str, req: CourierFinalizeReq, user=Depends(get_courier)):
    o = await db.orders.find_one({"id": oid, "courier_id": user["id"]})
    if not o:
        raise HTTPException(404, "Topilmadi")
    if not req.items:
        raise HTTPException(400, "Mahsulotlar ro'yxati bo'sh")
    await finalize_courier_order(o, req.items, user)
    return {"ok": True}


@api_router.get("/courier/stats")
async def courier_stats(user=Depends(get_courier)):
    orders = await db.orders.find({"courier_id": user["id"]}, {"_id": 0}).to_list(1000)
    return await build_courier_stats(user, orders)


# ---------- Admin ----------
@api_router.get("/admin/dashboard")
async def admin_dashboard(user=Depends(get_admin)):
    today = iso()[:10]
    orders = await db.orders.find({}).to_list(5000)
    today_orders = [o for o in orders if o["created_at"][:10] == today]

    # Sof foyda hisobi: har bir buyurtmadagi mahsulot sotuv narxi - tannarx
    # Tannarx kiritilgan bo'lsa sof foyda = effective_price - cost_price
    products = await db.products.find({}, {"id": 1, "cost_price": 1, "price": 1, "markup_percent": 1, "_id": 0}).to_list(5000)
    cost_map = {p["id"]: (p.get("cost_price") or 0) for p in products}
    pricing_map = {p["id"]: p for p in products}

    def calc_profit(order):
        prof = 0.0
        for it in order.get("items", []):
            pid = it.get("product_id")
            cp = cost_map.get(pid, 0)
            if cp <= 0:
                continue  # tannarx kiritilmagan mahsulotlar sof foyda hisobiga kirmaydi
            base_price = it.get("base_price", 0)
            actual_price = base_price or it.get("price", 0)
            qty = it.get("qty", 0) or 0
            # qaytgan mahsulot sof foyda kirmaydi
            if it.get("delivery_status") == "returned":
                continue
            prof += max(0, actual_price - cp) * qty
        return prof

    today_profit = sum(calc_profit(o) for o in today_orders if o["status"] != "cancelled")
    total_profit = sum(calc_profit(o) for o in orders if o["status"] == "delivered")
    today_sales_total = sum(o["total"] for o in today_orders if o["status"] != "cancelled")
    profit_margin = round((today_profit / today_sales_total) * 100, 1) if today_sales_total > 0 else 0.0

    return {
        "today_orders": len(today_orders),
        "today_sales": today_sales_total,
        "today_profit": today_profit,
        "total_orders": len(orders),
        "total_sales": sum(o["total"] for o in orders if o["status"] == "delivered"),
        "total_profit": total_profit,
        "profit_margin": profit_margin,
        "clients": await db.users.count_documents({"role": "client"}),
        "sellers": await db.users.count_documents({"seller_info.approved": True}),
        "couriers_online": await db.users.count_documents({"role": "courier", "courier_info.online": True}),
        "pending_products": await db.products.count_documents({"status": "pending"}),
        "pending_sellers": await db.users.count_documents({"seller_info.approved": False, "seller_info.rejected": False, "seller_info": {"$exists": True}}),
        "new_orders": len([o for o in orders if o["status"] == "new"]),
    }


@api_router.get("/admin/dashboard/history")
async def admin_dashboard_history(metric: str, user=Depends(get_admin)):
    today = iso()[:10]
    orders = await db.orders.find({}, {"_id": 0}).sort("created_at", -1).to_list(5000)
    users = await db.users.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    products = await db.products.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    product_costs = {p["id"]: float(p.get("cost_price") or 0) for p in products}

    def order_profit(order: dict) -> float:
        total = 0.0
        for it in order.get("items", []):
            cost = product_costs.get(it.get("product_id"), 0)
            if cost <= 0 or it.get("delivery_status") == "returned":
                continue
            actual_price = float(it.get("base_price", it.get("price", 0)) or 0)
            total += max(0.0, actual_price - cost) * int(it.get("qty", 0) or 0)
        return total

    items = []
    title = metric
    if metric == "today_orders":
        title = "Bugungi buyurtmalar tarixi"
        items = [{"id": o["id"], "primary": o["number"], "secondary": f"{o.get('client_name', '')} • {o.get('status', '')}", "value": float(o.get("total", 0) or 0), "date": o.get("created_at")} for o in orders if (o.get("created_at") or "")[:10] == today]
    elif metric == "today_sales":
        title = "Bugungi savdo tarixi"
        items = [{"id": o["id"], "primary": o["number"], "secondary": o.get("client_name", ""), "value": float(o.get("total", 0) or 0), "date": o.get("created_at")} for o in orders if (o.get("created_at") or "")[:10] == today and o.get("status") != "cancelled"]
    elif metric == "today_profit":
        title = "Bugungi sof foyda manbalari"
        items = [{"id": o["id"], "primary": o["number"], "secondary": o.get("client_name", ""), "value": order_profit(o), "date": o.get("created_at")} for o in orders if (o.get("created_at") or "")[:10] == today and o.get("status") != "cancelled"]
    elif metric == "total_orders":
        title = "Barcha buyurtmalar"
        items = [{"id": o["id"], "primary": o["number"], "secondary": f"{o.get('client_name', '')} • {o.get('status', '')}", "value": float(o.get("total", 0) or 0), "date": o.get("created_at")} for o in orders]
    elif metric == "total_sales":
        title = "Jami savdo"
        items = [{"id": o["id"], "primary": o["number"], "secondary": o.get("client_name", ""), "value": float(o.get("total", 0) or 0), "date": o.get("created_at")} for o in orders if o.get("status") == "delivered"]
    elif metric == "total_profit":
        title = "Jami sof foyda"
        items = [{"id": o["id"], "primary": o["number"], "secondary": o.get("client_name", ""), "value": order_profit(o), "date": o.get("created_at")} for o in orders if o.get("status") == "delivered"]
    elif metric == "profit_margin":
        title = "Bugungi marja hisob-kitobi"
        items = [{"id": o["id"], "primary": o["number"], "secondary": o.get("client_name", ""), "value": order_profit(o), "date": o.get("created_at")} for o in orders if (o.get("created_at") or "")[:10] == today and o.get("status") != "cancelled"]
    elif metric == "clients":
        title = "Mijozlar ro'yxati"
        items = [{"id": u["id"], "primary": f"{u.get('first_name', '')} {u.get('last_name', '')}".strip() or u.get("phone", ""), "secondary": u.get("phone", ""), "value": 0, "date": u.get("created_at")} for u in users if u.get("role") == "client"]
    elif metric == "sellers":
        title = "Tasdiqlangan sotuvchilar"
        items = [{"id": u["id"], "primary": (u.get("seller_info") or {}).get("shop_name", "Do'kon"), "secondary": f"{u.get('first_name', '')} {u.get('last_name', '')}".strip() or u.get("phone", ""), "value": float((u.get("seller_info") or {}).get("balance", 0) or 0), "date": (u.get("seller_info") or {}).get("applied_at") or u.get("created_at")} for u in users if (u.get("seller_info") or {}).get("approved")]
    elif metric == "couriers_online":
        title = "Onlayn kuryerlar"
        items = [{"id": u["id"], "primary": f"{u.get('first_name', '')} {u.get('last_name', '')}".strip() or u.get("phone", ""), "secondary": u.get("phone", ""), "value": 0, "date": u.get("created_at")} for u in users if u.get("role") == "courier" and (u.get("courier_info") or {}).get("online")]
    elif metric == "new_orders":
        title = "Yangi buyurtmalar"
        items = [{"id": o["id"], "primary": o["number"], "secondary": o.get("client_name", ""), "value": float(o.get("total", 0) or 0), "date": o.get("created_at")} for o in orders if o.get("status") == "new"]
    elif metric == "pending_products":
        title = "Moderatsiyadagi mahsulotlar"
        items = [{"id": p["id"], "primary": p.get("name", {}).get("uz") or p.get("id"), "secondary": p.get("seller_id", ""), "value": float(product_out(p).get("display_price", p.get("price", 0)) or 0), "date": p.get("created_at")} for p in products if p.get("status") == "pending"]
    elif metric == "pending_sellers":
        title = "Kutilayotgan sotuvchilar"
        items = [{"id": u["id"], "primary": (u.get("seller_info") or {}).get("shop_name", "Do'kon"), "secondary": u.get("phone", ""), "value": 0, "date": (u.get("seller_info") or {}).get("applied_at") or u.get("created_at")} for u in users if u.get("seller_info") and not (u.get("seller_info") or {}).get("approved") and not (u.get("seller_info") or {}).get("rejected")]
    else:
        raise HTTPException(404, "Statistika turi topilmadi")

    return {"metric": metric, "title": title, "items": items[:100]}


@api_router.get("/admin/users")
async def admin_users(role: Optional[str] = None, q: Optional[str] = None, user=Depends(get_admin)):
    query: Dict[str, Any] = {}
    if role == "seller":
        query["seller_info"] = {"$exists": True}
    elif role:
        query["role"] = role
    if q:
        rx = {"$regex": re.escape(q), "$options": "i"}
        query["$or"] = [{"first_name": rx}, {"last_name": rx}, {"phone": rx}]
    users = await db.users.find(query, {"_id": 0}).sort("created_at", -1).to_list(300)

    if role == "seller":
        result = []
        for seller_user in users:
            orders = await db.orders.find({"seller_id": seller_user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(1000)
            snap = dict(seller_user)
            today_stats = seller_today_snapshot(seller_user, orders)
            snap["seller_today_summary"] = {
                "today_orders": today_stats["today_orders"],
                "today_amount": today_stats["today_amount"],
                "today_returns_count": today_stats["today_returns_count"],
                "today_returns_amount": today_stats["today_returns_amount"],
                "stats_reset_at": today_stats.get("stats_reset_at"),
            }
            snap["seller_today_orders"] = today_stats["today_orders_list"]
            result.append(snap)
        return result

    if role != "courier":
        return users

    result = []
    for courier_user in users:
        orders = await db.orders.find({"courier_id": courier_user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(1000)
        delivered_orders = [o for o in orders if status_at(o, "delivered")]
        daily: Dict[str, Dict[str, Any]] = {}
        recent_orders = []
        for o in delivered_orders:
            delivered_ts = status_at(o, "delivered") or o.get("delivery_completed_at") or o.get("created_at")
            day = (delivered_ts or "")[:10]
            delivered_products = delivered_item_qty(o)
            returned_products = returned_item_qty(o)
            bucket = daily.setdefault(day, {"date": day, "orders": 0, "delivered_products": 0, "returned_products": 0, "recipients": []})
            bucket["orders"] += 1
            bucket["delivered_products"] += delivered_products
            bucket["returned_products"] += returned_products
            bucket["recipients"].append(o.get("client_name") or o.get("client_phone") or o.get("number"))
            recent_orders.append({
                "id": o["id"],
                "number": o["number"],
                "date": delivered_ts,
                "client_name": o.get("client_name", ""),
                "client_phone": o.get("client_phone", ""),
                "delivered_products": delivered_products,
                "returned_products": returned_products,
                "items": [{
                    "name": item_name(i),
                    "qty": int(i.get("qty", 0) or 0),
                    "delivery_status": i.get("delivery_status", "delivered" if o.get("status") == "delivered" else "pending")
                } for i in (o.get("items") or [])],
            })
        snap = dict(courier_user)
        snap["courier_stats_summary"] = await build_courier_stats(courier_user, orders)
        snap["courier_daily_history"] = sorted(daily.values(), key=lambda x: x["date"], reverse=True)[:14]
        snap["courier_recent_orders"] = recent_orders[:10]
        result.append(snap)
    return result


@api_router.post("/admin/users/{target_id}/block")
async def admin_block(target_id: str, req: BlockReq, user=Depends(get_admin)):
    await db.users.update_one({"id": target_id}, {"$set": {"blocked": req.blocked}})
    return {"ok": True}


@api_router.post("/admin/couriers/{target_id}/reset-stats")
async def admin_reset_courier_stats(target_id: str, user=Depends(get_admin)):
    courier_user = await db.users.find_one({"id": target_id, "role": "courier"}, {"_id": 0})
    if not courier_user:
        raise HTTPException(404, "Kuryer topilmadi")
    reset_at = iso()
    await db.users.update_one(
        {"id": target_id},
        {"$set": {"courier_info.earnings": 0, "courier_info.deliveries": 0, "courier_info.stats_reset_at": reset_at}},
    )
    await notify(target_id, "Kuryer statistikasi yangilandi", "Admin statistik hisoblagichlarini 0 ga tushirdi")
    return {"ok": True, "reset_at": reset_at}


@api_router.post("/admin/sellers/{target_id}/reset-stats")
async def admin_reset_seller_stats(target_id: str, user=Depends(get_admin)):
    seller_user = await db.users.find_one({"id": target_id, "seller_info": {"$exists": True}}, {"_id": 0})
    if not seller_user:
        raise HTTPException(404, "Sotuvchi topilmadi")
    reset_at = iso()
    await db.users.update_one({"id": target_id}, {"$set": {"seller_info.stats_reset_at": reset_at}})
    await notify(target_id, "Sotuvchi statistikasi yangilandi", "Admin bugungi statistika hisoblagichini 0 ga tushirdi")
    return {"ok": True, "reset_at": reset_at}


@api_router.post("/admin/sellers/{target_id}/approve")
async def admin_approve_seller(target_id: str, user=Depends(get_admin)):
    await db.users.update_one({"id": target_id}, {"$set": {"seller_info.approved": True, "seller_info.rejected": False}})
    await notify(target_id, "Tabriklaymiz!", "Sotuvchi arizangiz tasdiqlandi. Mahsulot joylashtirishingiz mumkin")
    return {"ok": True}


@api_router.post("/admin/sellers/{target_id}/reject")
async def admin_reject_seller(target_id: str, user=Depends(get_admin)):
    await db.users.update_one({"id": target_id}, {"$set": {"seller_info.rejected": True}})
    await notify(target_id, "Ariza rad etildi", "Sotuvchi arizangiz rad etildi")
    return {"ok": True}


@api_router.get("/admin/products")
async def admin_products(status: Optional[str] = None, user=Depends(get_admin)):
    q = {"status": status} if status else {}
    items = await db.products.find(q).sort("created_at", -1).to_list(500)
    return [product_out(p) for p in items]


@api_router.post("/admin/products/{pid}/moderate")
async def admin_moderate(pid: str, req: ActionReq, user=Depends(get_admin)):
    p = await db.products.find_one({"id": pid})
    if not p:
        raise HTTPException(404, "Topilmadi")
    if req.action == "approve":
        await db.products.update_one({"id": pid}, {"$set": {"status": "approved"}})
        await notify(p["seller_id"], "Mahsulot tasdiqlandi", p["name"]["uz"])
    elif req.action == "reject":
        await db.products.update_one({"id": pid}, {"$set": {"status": "rejected"}})
        await notify(p["seller_id"], "Mahsulot rad etildi", f"{p['name']['uz']}: {req.reason}")
    elif req.action == "pin":
        await db.products.update_one({"id": pid}, {"$set": {"pinned": not p.get("pinned", False)}})
    elif req.action == "delete":
        await db.products.delete_one({"id": pid})
    return {"ok": True}


@api_router.post("/admin/products/{pid}/markup")
async def admin_product_markup(pid: str, req: MarkupReq, user=Depends(get_admin)):
    """Admin sets how many percent to add on top of this seller's price. Buyers see price*(1+percent/100); seller keeps seeing their own raw price."""
    p = await db.products.find_one({"id": pid})
    if not p:
        raise HTTPException(404, "Topilmadi")
    percent = max(0.0, req.percent)
    await db.products.update_one({"id": pid}, {"$set": {"markup_percent": percent}})
    return product_out(await db.products.find_one({"id": pid}))


@api_router.post("/admin/products/bulk-markup")
async def admin_bulk_markup(req: BulkMarkupReq, user=Depends(get_admin)):
    """Add req.percent on top of every product's seller price at once (market-wide)."""
    percent = max(0.0, req.percent)
    q = {"markup_percent": {"$exists": False}} if req.only_without_override else {}
    result = await db.products.update_many(q, {"$set": {"markup_percent": percent}})
    return {"ok": True, "updated": result.modified_count}


@api_router.post("/admin/categories")
async def admin_add_category(req: CategoryReq, user=Depends(get_admin)):
    c = {"id": uid(), "name": {"uz": req.name_uz, "ru": req.name_ru or req.name_uz, "en": req.name_en or req.name_uz},
         "icon": req.icon, "parent_id": req.parent_id, "order": req.order}
    await db.categories.insert_one(dict(c))
    return {k: v for k, v in c.items() if k != "_id"}


@api_router.put("/admin/categories/{cid}")
async def admin_update_category(cid: str, req: CategoryReq, user=Depends(get_admin)):
    existing = await db.categories.find_one({"id": cid}, {"_id": 0})
    if not existing:
        raise HTTPException(404, "Topilmadi")
    upd = {
        "name": {"uz": req.name_uz, "ru": req.name_ru or req.name_uz, "en": req.name_en or req.name_uz},
        "icon": req.icon,
        "parent_id": req.parent_id,
        "order": req.order,
    }
    await db.categories.update_one({"id": cid}, {"$set": upd})
    updated = await db.categories.find_one({"id": cid}, {"_id": 0})
    return updated


@api_router.post("/admin/categories/{cid}")
async def admin_update_category_post(cid: str, req: CategoryReq, user=Depends(get_admin)):
    """POST alias for PUT — works on hosts/proxies that block raw PUT."""
    return await admin_update_category(cid, req)


@api_router.delete("/admin/categories/{cid}")
async def admin_del_category(cid: str, user=Depends(get_admin)):
    await db.categories.delete_many({"$or": [{"id": cid}, {"parent_id": cid}]})
    return {"ok": True}


@api_router.get("/admin/orders")
async def admin_orders(status: Optional[str] = None, user=Depends(get_admin)):
    q = {"status": status} if status else {}
    return await db.orders.find(q, {"_id": 0}).sort("created_at", -1).to_list(500)


@api_router.post("/admin/orders/{oid}/status")
async def admin_order_status(oid: str, req: StatusReq, user=Depends(get_admin)):
    o = await db.orders.find_one({"id": oid})
    if not o:
        raise HTTPException(404, "Topilmadi")
    await set_order_status(o, req.status, "Admin o'zgartirdi")
    return {"ok": True}


@api_router.post("/admin/banners")
async def admin_add_banner(req: BannerReq, user=Depends(get_admin)):
    b = {"id": uid(), **req.dict(), "active": True, "order": 0, "created_at": iso()}
    await db.banners.insert_one(dict(b))
    return {k: v for k, v in b.items() if k != "_id"}


async def _admin_update_banner(bid: str, req: BannerReq):
    existing = await db.banners.find_one({"id": bid}, {"_id": 0})
    if not existing:
        raise HTTPException(404, "Topilmadi")
    # If client didn't send a new image, keep the existing one so
    # "just changing the title" doesn't wipe the banner picture.
    new_image = req.image
    if not new_image or not new_image.strip():
        new_image = existing.get("image")
    upd = {
        "image": new_image,
        "title": req.title,
        "link_type": req.link_type,
        "link_id": req.link_id,
        "expires_at": req.expires_at,
    }
    await db.banners.update_one({"id": bid}, {"$set": upd})
    updated = await db.banners.find_one({"id": bid}, {"_id": 0})
    return updated


@api_router.put("/admin/banners/{bid}")
async def admin_update_banner_put(bid: str, req: BannerReq, user=Depends(get_admin)):
    return await _admin_update_banner(bid, req)


@api_router.post("/admin/banners/{bid}")
async def admin_update_banner_post(bid: str, req: BannerReq, user=Depends(get_admin)):
    return await _admin_update_banner(bid, req)


@api_router.delete("/admin/banners/{bid}")
async def admin_del_banner(bid: str, user=Depends(get_admin)):
    await db.banners.delete_one({"id": bid})
    return {"ok": True}


@api_router.post("/admin/banners/{bid}/delete")
async def admin_del_banner_post_alias(bid: str, user=Depends(get_admin)):
    """POST alias for DELETE on hosts/proxies that block raw DELETE."""
    await db.banners.delete_one({"id": bid})
    return {"ok": True}


@api_router.get("/admin/promocodes")
async def admin_promos(user=Depends(get_admin)):
    return await db.promocodes.find({}, {"_id": 0}).sort("created_at", -1).to_list(100)


@api_router.post("/admin/promocodes")
async def admin_add_promo(req: PromoCreateReq, user=Depends(get_admin)):
    p = {"id": uid(), "code": req.code.upper(), "type": req.type, "value": req.value, "min_cart": req.min_cart,
         "limit": req.limit, "used": 0, "expires_at": req.expires_at, "active": True, "created_at": iso()}
    await db.promocodes.insert_one(dict(p))
    return {k: v for k, v in p.items() if k != "_id"}


@api_router.delete("/admin/promocodes/{pid}")
async def admin_del_promo(pid: str, user=Depends(get_admin)):
    await db.promocodes.delete_one({"id": pid})
    return {"ok": True}


@api_router.post("/admin/flash-sale")
async def admin_flash(req: FlashReq, user=Depends(get_admin)):
    await db.products.update_one({"id": req.product_id}, {"$set": {"flash_sale": {"price": req.price, "ends_at": iso(now() + timedelta(hours=req.hours))}}})
    return {"ok": True}


@api_router.get("/admin/reviews")
async def admin_reviews(user=Depends(get_admin)):
    return await db.reviews.find({}, {"_id": 0}).sort("created_at", -1).to_list(200)


@api_router.delete("/admin/reviews/{rid}")
async def admin_del_review(rid: str, user=Depends(get_admin)):
    await db.reviews.delete_one({"id": rid})
    return {"ok": True}


@api_router.get("/admin/sms-log")
async def admin_sms_log(user=Depends(get_admin)):
    return await db.sms_log.find({}, {"_id": 0}).sort("sent_at", -1).to_list(200)


@api_router.get("/admin/settings")
async def admin_get_settings(user=Depends(get_admin)):
    return await db.settings.find_one({"id": "main"}, {"_id": 0}) or {}


@api_router.put("/admin/settings")
async def admin_set_settings(req: SettingsReq, user=Depends(get_admin)):
    upd = {k: v for k, v in req.dict().items() if v is not None}
    await db.settings.update_one({"id": "main"}, {"$set": upd}, upsert=True)
    s = await db.settings.find_one({"id": "main"}, {"_id": 0})
    SETTINGS_CACHE["default_markup_percent"] = s.get("default_markup_percent", 0) or 0
    return s


@api_router.post("/admin/couriers")
async def admin_add_courier(req: CourierCreateReq, user=Depends(get_admin)):
    phone = re.sub(r"[^\d+]", "", req.phone)
    if await db.users.find_one({"phone": phone}):
        raise HTTPException(400, "Bu raqam ro'yxatda bor")
    c = {"id": uid(), "phone": phone, "first_name": req.first_name, "last_name": "", "role": "courier",
         "language": "uz", "blocked": False, "referral_code": f"UZ{random.randint(10000, 99999)}",
         "favorites": [], "addresses": [], "courier_info": {"online": False, "zone": req.zone, "earnings": 0, "deliveries": 0, "stats_reset_at": None}, "created_at": iso()}
    await db.users.insert_one(dict(c))
    return {k: v for k, v in c.items() if k != "_id"}


@api_router.get("/settings/public")
async def public_settings():
    s = await db.settings.find_one({"id": "main"}, {"_id": 0}) or {}
    return {"delivery_fee": s.get("delivery_fee", 15000), "min_order": s.get("min_order", 0),
            "work_hours": s.get("work_hours", "09:00 - 21:00"), "contact": s.get("contact", "+998 71 200 00 00")}


@api_router.get("/download/source")
async def download_source():
    from fastapi.responses import FileResponse
    path = "/app/uzmarket_source_final.zip"
    if not os.path.exists(path):
        raise HTTPException(404, "Zip topilmadi")
    return FileResponse(path, filename="uzmarket_source_final.zip", media_type="application/zip")


app.include_router(api_router)

app.add_middleware(MethodOverrideMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- Seed ----------
IMG = {
    "phone": "https://images.unsplash.com/photo-1623824204241-f851d3bcfaf5?w=600&q=80",
    "phone2": "https://images.unsplash.com/photo-1610945265064-0e34e5519bbf?w=600&q=80",
    "laptop": "https://images.unsplash.com/photo-1496181133206-80ce9b88a853?w=600&q=80",
    "headphones": "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=600&q=80",
    "watch": "https://images.unsplash.com/photo-1523275335684-37898b6baf30?w=600&q=80",
    "tshirt": "https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?w=600&q=80",
    "sneakers": "https://images.unsplash.com/photo-1542291026-7eec264c27ff?w=600&q=80",
    "jacket": "https://images.unsplash.com/photo-1551028719-00167b16eac5?w=600&q=80",
    "sofa": "https://images.unsplash.com/photo-1555041469-a586c61ea9bc?w=600&q=80",
    "lamp": "https://images.unsplash.com/photo-1507473885765-e6ed057f782c?w=600&q=80",
    "kettle": "https://images.unsplash.com/photo-1594213114663-d94db9b17125?w=600&q=80",
    "perfume": "https://images.unsplash.com/photo-1541643600914-78b084683601?w=600&q=80",
    "cream": "https://images.unsplash.com/photo-1556228720-195a672e8a03?w=600&q=80",
    "ball": "https://images.unsplash.com/photo-1614632537190-23e4146777db?w=600&q=80",
    "dumbbell": "https://images.unsplash.com/photo-1517836357463-d25dfeac3438?w=600&q=80",
    "honey": "https://images.unsplash.com/photo-1587049352846-4a222e784d38?w=600&q=80",
    "nuts": "https://images.unsplash.com/photo-1508061253366-f7da158b6d46?w=600&q=80",
    "banner1": "https://images.unsplash.com/photo-1558769132-cb1aea458c5e?w=1200&q=80",
    "banner2": "https://images.unsplash.com/photo-1607082348824-0a96f2a4b9da?w=1200&q=80",
    "banner3": "https://images.unsplash.com/photo-1472851294608-062f824d29cc?w=1200&q=80",
}


REMINDER_TASK: Optional[asyncio.Task] = None


async def send_pending_order_reminders_once():
    cutoff = iso(now() - timedelta(hours=1))
    pending_orders = await db.orders.find({
        "status": "new",
        "created_at": {"$lte": cutoff},
        "seller_confirmation_reminder_sent_at": {"$exists": False},
    }, {"_id": 0}).to_list(500)
    if not pending_orders:
        return 0
    admins = await db.users.find({"role": "admin"}, {"_id": 0}).to_list(50)
    sent = 0
    for order in pending_orders:
        await notify(order["seller_id"], "Buyurtmani tasdiqlang", f"{order['number']} buyurtmasi 1 soatdan beri tasdiqlanmagan")
        for admin_u in admins:
            await notify(admin_u["id"], "Sotuvchi hali tasdiqlamadi", f"{order['number']} buyurtmasi hali ham tasdiqlanmagan")
        await db.orders.update_one({"id": order["id"]}, {"$set": {"seller_confirmation_reminder_sent_at": iso()}})
        sent += 1
    return sent


async def reminder_worker():
    while True:
        try:
            await send_pending_order_reminders_once()
        except Exception:
            logger.exception("Pending-order reminder worker failed")
        await asyncio.sleep(300)


@app.on_event("startup")
async def load_settings_cache():
    s = await db.settings.find_one({"id": "main"}) or {}
    SETTINGS_CACHE["default_markup_percent"] = s.get("default_markup_percent", 0) or 0


@app.on_event("startup")
async def start_reminder_worker():
    global REMINDER_TASK
    if REMINDER_TASK is None or REMINDER_TASK.done():
        REMINDER_TASK = asyncio.create_task(reminder_worker())


@app.on_event("startup")
async def seed():
    if await db.users.find_one({"phone": "+998900000000"}):
        return
    logger.info("Seeding demo data...")

    def mkuser(phone, fn, ln, role, extra=None):
        u = {"id": uid(), "phone": phone, "first_name": fn, "last_name": ln, "role": role, "language": "uz",
             "blocked": False, "referral_code": f"UZ{random.randint(10000, 99999)}", "favorites": [],
             "addresses": [{"id": uid(), "label": "Uy", "text": "Toshkent, Chilonzor tumani, 12-kvartal", "lat": 41.28, "lng": 69.2}],
             "created_at": iso()}
        if extra:
            u.update(extra)
        return u

    admin = mkuser("+998900000000", "Admin", "Boshqaruvchi", "admin")
    seller1 = mkuser("+998901111111", "Aziz", "Karimov", "client", {"seller_info": {"shop_name": "TechnoPlaza", "approved": True, "rejected": False, "commission": 10, "balance": 1250000, "rating": 4.8, "applied_at": iso()}})
    seller2 = mkuser("+998904444444", "Malika", "Yusupova", "client", {"seller_info": {"shop_name": "Fashion House", "approved": True, "rejected": False, "commission": 12, "balance": 830000, "rating": 4.6, "applied_at": iso()}})
    seller3 = mkuser("+998905555555", "Bobur", "Aliyev", "client", {"seller_info": {"shop_name": "Organic Market", "approved": False, "rejected": False, "commission": None, "balance": 0, "rating": 5.0, "applied_at": iso()}})
    courier = mkuser("+998902222222", "Jasur", "Toshmatov", "courier", {"courier_info": {"online": True, "zone": "Chilonzor", "earnings": 345000, "deliveries": 23, "stats_reset_at": None}})
    client_u = mkuser("+998903333333", "Dilnoza", "Rahimova", "client")
    for u in (admin, seller1, seller2, seller3, courier, client_u):
        await db.users.insert_one(dict(u))

    cats_def = [
        ("Elektronika", "Электроника", "Electronics", "devices", [("Telefonlar", "Телефоны", "Phones"), ("Noutbuklar", "Ноутбуки", "Laptops"), ("Aksessuarlar", "Аксессуары", "Accessories")]),
        ("Kiyim", "Одежда", "Clothing", "checkroom", [("Erkaklar", "Мужчинам", "Men"), ("Ayollar", "Женщинам", "Women")]),
        ("Uy-ro'zg'or", "Дом и быт", "Home", "chair", [("Mebel", "Мебель", "Furniture"), ("Oshxona", "Кухня", "Kitchen")]),
        ("Go'zallik", "Красота", "Beauty", "spa", [("Parfyumeriya", "Парфюмерия", "Perfume"), ("Parvarish", "Уход", "Care")]),
        ("Sport", "Спорт", "Sport", "fitness-center", [("Trenajyor", "Тренажёры", "Fitness"), ("Sport anjomlar", "Инвентарь", "Equipment")]),
        ("Oziq-ovqat", "Продукты", "Food", "restaurant", [("Shirinliklar", "Сладости", "Sweets"), ("Sog'lom oziq", "Здоровое питание", "Healthy")]),
    ]
    cat_ids = {}
    for i, (uz_, ru_, en_, icon, subs) in enumerate(cats_def):
        cid = uid()
        cat_ids[uz_] = cid
        await db.categories.insert_one({"id": cid, "name": {"uz": uz_, "ru": ru_, "en": en_}, "icon": icon, "parent_id": None, "order": i})
        for j, (suz, sru, sen) in enumerate(subs):
            scid = uid()
            cat_ids[suz] = scid
            await db.categories.insert_one({"id": scid, "name": {"uz": suz, "ru": sru, "en": sen}, "icon": icon, "parent_id": cid, "order": j})

    def mkprod(seller, nuz, nru, nen, cat, sub, price, old, img, stock, sold, rating, rcount, pinned=False, variations=None, flash=None):
        return {"id": uid(), "seller_id": seller["id"],
                "name": {"uz": nuz, "ru": nru, "en": nen},
                "desc": {"uz": f"{nuz} — yuqori sifatli mahsulot. Rasmiy kafolat bilan. Tez yetkazib berish.",
                         "ru": f"{nru} — товар высокого качества с официальной гарантией.",
                         "en": f"{nen} — high quality product with official warranty."},
                "category_id": cat_ids[cat], "subcategory_id": cat_ids.get(sub), "price": price, "old_price": old,
                "images": [img], "stock": stock, "variations": variations or [], "status": "approved", "hidden": False,
                "pinned": pinned, "rating": rating, "reviews_count": rcount, "views": random.randint(50, 900),
                "sold": sold, "flash_sale": flash, "created_at": iso()}

    flash_end = iso(now() + timedelta(hours=8))
    color_var = [{"name": "Rang", "options": [{"label": "Qora", "price_delta": 0, "stock": 5}, {"label": "Oq", "price_delta": 0, "stock": 3}, {"label": "Yashil", "price_delta": 50000, "stock": 2}]}]
    mem_var = [{"name": "Xotira", "options": [{"label": "128 GB", "price_delta": 0, "stock": 4}, {"label": "256 GB", "price_delta": 1500000, "stock": 3}]}]
    size_var = [{"name": "O'lcham", "options": [{"label": "S", "price_delta": 0, "stock": 4}, {"label": "M", "price_delta": 0, "stock": 6}, {"label": "L", "price_delta": 0, "stock": 2}, {"label": "XL", "price_delta": 10000, "stock": 3}]}]

    products = [
        mkprod(seller1, "Smartfon Galaxy A55 5G", "Смартфон Galaxy A55 5G", "Galaxy A55 5G Smartphone", "Elektronika", "Telefonlar", 4200000, 4800000, IMG["phone"], 12, 156, 4.7, 42, True, mem_var, {"price": 3990000, "ends_at": flash_end}),
        mkprod(seller1, "iPhone 15 Pro 256GB", "iPhone 15 Pro 256GB", "iPhone 15 Pro 256GB", "Elektronika", "Telefonlar", 14500000, None, IMG["phone2"], 5, 89, 4.9, 31, True, mem_var),
        mkprod(seller1, "Noutbuk Lenovo IdeaPad 5", "Ноутбук Lenovo IdeaPad 5", "Lenovo IdeaPad 5 Laptop", "Elektronika", "Noutbuklar", 8900000, 9900000, IMG["laptop"], 7, 64, 4.6, 18),
        mkprod(seller1, "Simsiz quloqchin Sony WH-1000", "Беспроводные наушники Sony", "Sony Wireless Headphones", "Elektronika", "Aksessuarlar", 2100000, 2600000, IMG["headphones"], 20, 203, 4.8, 57, False, color_var, {"price": 1890000, "ends_at": flash_end}),
        mkprod(seller1, "Smart soat Amazfit GTR 4", "Смарт-часы Amazfit GTR 4", "Amazfit GTR 4 Smart Watch", "Elektronika", "Aksessuarlar", 1650000, 1900000, IMG["watch"], 15, 134, 4.5, 29, False, color_var),
        mkprod(seller2, "Erkaklar futbolkasi Premium", "Мужская футболка Premium", "Men's Premium T-Shirt", "Kiyim", "Erkaklar", 145000, 195000, IMG["tshirt"], 40, 312, 4.4, 88, False, size_var, {"price": 119000, "ends_at": flash_end}),
        mkprod(seller2, "Krossovka Nike Air Zoom", "Кроссовки Nike Air Zoom", "Nike Air Zoom Sneakers", "Kiyim", "Erkaklar", 1250000, 1550000, IMG["sneakers"], 18, 178, 4.7, 45, True, size_var),
        mkprod(seller2, "Ayollar kurtkasi Winter", "Женская куртка Winter", "Women's Winter Jacket", "Kiyim", "Ayollar", 890000, 1200000, IMG["jacket"], 3, 95, 4.6, 22, False, size_var),
        mkprod(seller2, "Divan Comfort 3-o'rinli", "Диван Comfort 3-местный", "Comfort 3-seat Sofa", "Uy-ro'zg'or", "Mebel", 5600000, 6500000, IMG["sofa"], 4, 27, 4.5, 9),
        mkprod(seller2, "Stol lampasi Loft", "Настольная лампа Loft", "Loft Table Lamp", "Uy-ro'zg'or", "Mebel", 320000, None, IMG["lamp"], 25, 68, 4.3, 15),
        mkprod(seller1, "Elektr choynak Bosch 1.7L", "Электрочайник Bosch 1.7л", "Bosch Electric Kettle 1.7L", "Uy-ro'zg'or", "Oshxona", 480000, 560000, IMG["kettle"], 30, 142, 4.6, 38),
        mkprod(seller2, "Atir Dior Sauvage 100ml", "Духи Dior Sauvage 100мл", "Dior Sauvage Perfume 100ml", "Go'zallik", "Parfyumeriya", 1850000, 2100000, IMG["perfume"], 8, 76, 4.8, 21),
        mkprod(seller2, "Yuz kremi Nivea Care", "Крем для лица Nivea Care", "Nivea Care Face Cream", "Go'zallik", "Parvarish", 95000, 120000, IMG["cream"], 50, 254, 4.4, 63),
        mkprod(seller1, "Futbol to'pi Adidas Pro", "Футбольный мяч Adidas Pro", "Adidas Pro Football", "Sport", "Sport anjomlar", 380000, 450000, IMG["ball"], 22, 118, 4.5, 27),
        mkprod(seller1, "Gantellar to'plami 20kg", "Набор гантелей 20кг", "Dumbbell Set 20kg", "Sport", "Trenajyor", 750000, None, IMG["dumbbell"], 10, 54, 4.7, 12),
        mkprod(seller2, "Tog' asali 1kg", "Горный мёд 1кг", "Mountain Honey 1kg", "Oziq-ovqat", "Sog'lom oziq", 150000, 180000, IMG["honey"], 35, 198, 4.9, 74),
        mkprod(seller2, "Quruq mevalar to'plami", "Набор сухофруктов", "Dried Fruits Mix", "Oziq-ovqat", "Sog'lom oziq", 220000, None, IMG["nuts"], 28, 87, 4.6, 19),
        mkprod(seller1, "Powerbank Xiaomi 20000mAh", "Повербанк Xiaomi 20000mAh", "Xiaomi Powerbank 20000mAh", "Elektronika", "Aksessuarlar", 350000, 420000, IMG["phone2"], 0, 167, 4.5, 33),
    ]
    pending = mkprod(seller1, "Yangi planshet Tab S9", "Новый планшет Tab S9", "New Tab S9 Tablet", "Elektronika", "Telefonlar", 6200000, None, IMG["laptop"], 6, 0, 0, 0)
    pending["status"] = "pending"
    products.append(pending)
    for p in products:
        await db.products.insert_one(dict(p))

    banners = [
        {"id": uid(), "image": IMG["banner1"], "title": "Yangi mavsum kolleksiyasi — 40% gacha chegirma", "link_type": "category", "link_id": cat_ids["Kiyim"], "active": True, "order": 0, "expires_at": None, "created_at": iso()},
        {"id": uid(), "image": IMG["banner2"], "title": "Elektronika festivali boshlandi", "link_type": "category", "link_id": cat_ids["Elektronika"], "active": True, "order": 1, "expires_at": None, "created_at": iso()},
        {"id": uid(), "image": IMG["banner3"], "title": "Flash Sale — bugun tugaydi!", "link_type": "flash", "link_id": None, "active": True, "order": 2, "expires_at": None, "created_at": iso()},
    ]
    for b in banners:
        await db.banners.insert_one(dict(b))

    await db.promocodes.insert_one({"id": uid(), "code": "WELCOME10", "type": "percent", "value": 10, "min_cart": 100000, "limit": 100, "used": 3, "expires_at": None, "active": True, "created_at": iso()})
    await db.promocodes.insert_one({"id": uid(), "code": "SALE50K", "type": "amount", "value": 50000, "min_cart": 500000, "limit": 50, "used": 1, "expires_at": None, "active": True, "created_at": iso()})
    await db.settings.update_one({"id": "main"}, {"$set": {"delivery_fee": 15000, "min_order": 50000, "commission_default": 10, "default_markup_percent": 0, "work_hours": "09:00 - 21:00", "contact": "+998 71 200 00 00"}}, upsert=True)

    # sample delivered order for demo client so reviews work
    p0 = products[0]
    o = {"id": uid(), "number": "#1000", "group_id": uid(), "client_id": client_u["id"], "client_name": "Dilnoza Rahimova",
         "client_phone": client_u["phone"], "seller_id": seller1["id"],
         "items": [{"product_id": p0["id"], "name": p0["name"], "image": p0["images"][0], "price": p0["price"], "qty": 1, "variation": "128 GB"}],
         "subtotal": p0["price"], "delivery_fee": 15000, "discount": 0, "total": p0["price"] + 15000, "promo_code": None,
         "status": "delivered", "address_text": "Toshkent, Chilonzor tumani, 12-kvartal", "delivery_method": "courier",
         "payment_method": "cash", "comment": "", "courier_id": courier["id"],
         "status_history": [{"status": s, "at": iso(now() - timedelta(days=2, hours=5 - i))} for i, s in enumerate(STATUS_FLOW)],
         "created_at": iso(now() - timedelta(days=2))}
    await db.orders.insert_one(dict(o))
    await db.reviews.insert_one({"id": uid(), "product_id": p0["id"], "client_id": client_u["id"], "client_name": "Dilnoza Rahimova", "rating": 5, "text": "Juda zo'r telefon, tez yetkazib berishdi. Tavsiya qilaman!", "verified": True, "created_at": iso(now() - timedelta(days=1))})
    logger.info("Seed complete")


@app.on_event("shutdown")
async def shutdown_db_client():
    global REMINDER_TASK
    if REMINDER_TASK and not REMINDER_TASK.done():
        REMINDER_TASK.cancel()
        try:
            await REMINDER_TASK
        except asyncio.CancelledError:
            pass
    client.close()
