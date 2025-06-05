from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, create_engine, Float
from sqlalchemy.orm import relationship, sessionmaker, declarative_base, Session
import time

# Basic settings
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# SQLAlchemy setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./marketplace.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Models
class User(Base):
    tablename = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True)
    hashed_password = Column(String)
    is_seller = Column(Boolean, default=False)

class Item(Base):
    tablename = "items"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    description = Column(String)
    price = Column(Float)
    seller_id = Column(Integer, ForeignKey("users.id"))
    seller = relationship("User")

class BasketItem(Base):
    tablename = "basket_items"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    item_id = Column(Integer, ForeignKey("items.id"))

Base.metadata.create_all(bind=engine)

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Pydantic Schemas
class UserCreate(BaseModel):
    username: str
    password: str
    is_seller: Optional[bool] = False

class UserProfile(BaseModel):
    id: int
    username: str
    is_seller: bool

class Token(BaseModel):
    access_token: str
    token_type: str

class ItemBase(BaseModel):
    title: str
    description: str
    price: float

class ItemOut(ItemBase):
    id: int
    seller_id: int

class BasketAction(BaseModel):
    item_id: int

# Utility functions
def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[int] = None):
    to_encode = data.copy()
    expire = time.time() + (expires_delta if expires_delta else ACCESS_TOKEN_EXPIRE_MINUTES * 60)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(lambda: SessionLocal())):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401)
    except JWTError:
        raise HTTPException(status_code=401)
    user = get_user(db, username=username)
    if user is None:
        raise HTTPException(status_code=401)
    return user

# FastAPI App
app = FastAPI()

@app.post("/register", response_model=UserProfile)
def register(user: UserCreate, db: Session = Depends(lambda: SessionLocal())):
    db_user = get_user(db, user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already taken")
    hashed_password = get_password_hash(user.password)
    new_user = User(username=user.username, hashed_password=hashed_password, is_seller=user.is_seller)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return UserProfile(id=new_user.id, username=new_user.username, is_seller=new_user.is_seller)

@app.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(lambda: SessionLocal())):
    user = get_user(db, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    token = create_access_token(data={"sub": user.username})
    return Token(access_token=token, token_type="bearer")

@app.get("/me", response_model=UserProfile)
def read_users_me(current_user: User = Depends(get_current_user)):
    return UserProfile(id=current_user.id, username=current_user.username, is_seller=current_user.is_seller)

@app.post("/items", response_model=ItemOut)
def add_item(item: ItemBase, current_user: User = Depends(get_current_user), db: Session = Depends(lambda: SessionLocal())):
    if not current_user.is_seller:
        raise HTTPException(status_code=403, detail="Not authorized to sell")
    db_item = Item(**item.dict(), seller_id=current_user.id)
    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    return db_item

@app.get("/items", response_model=List[ItemOut])
def list_items(db: Session = Depends(lambda: SessionLocal())):
    return db.query(Item).all()

@app.post("/basket/add")
def add_to_basket(data: BasketAction, current_user: User = Depends(get_current_user), db: Session = Depends(lambda: SessionLocal())):
    basket_item = BasketItem(user_id=current_user.id, item_id=data.item_id)
    db.add(basket_item)
    db.commit()
    return {"message": "Item added to basket"}

@app.post("/basket/remove")
def remove_from_basket(data: BasketAction, current_user: User = Depends(get_current_user), db: Session = Depends(lambda: SessionLocal())):
    item = db.query(BasketItem).filter_by(user_id=current_user.id, item_id=data.item_id).first()
    if item:
        db.delete(item)
        db.commit()
    return {"message": "Item removed"}

@app.get("/basket", response_model=List[ItemOut])
def view_basket(current_user: User = Depends(get_current_user), db: Session = Depends(lambda: SessionLocal())):
    items = db.query(Item).join(BasketItem, BasketItem.item_id == Item.id).filter(BasketItem.user_id == current_user.id).all()
    return items

@app.post("/purchase")
def purchase(current_user: User = Depends(get_current_user), db: Session = Depends(lambda: SessionLocal())):
    # Example payment flow
    items = db.query(Item).join(BasketItem).filter(BasketItem.user_id == current_user.id).all()
    total = sum(item.price for item in items)
    if total <= 0:
        raise HTTPException(status_code=400, detail="Basket is empty")
    
    # Placeholder for actual payment integration
    print(f"Charging user {current_user.username} a total of ${total}")

    db.query(BasketItem).filter_by(user_id=current_user.id).delete()
    db.commit()
    return {"message": "Purchase successful", "total_charged": total}