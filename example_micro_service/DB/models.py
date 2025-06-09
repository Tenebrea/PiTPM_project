from sqlalchemy import Column, Integer, String
from .database import Base

class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(40), nullable = False)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)
    email = Column(String(100), unique=True, index=True)
    hashed_password = Column(String(100))
    disabled = Column(Boolean, default=False)

class Category(Base):
    __tablename__ = "categories"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), nullable = False)

class Product(Base):
    __tablename__ = "products"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable = False)
    description = Column(String(500), nullable=True)
    price = Column(Integer, nullable = False)
    amount = Column(Integer, nullable = False)
    user_id = Column(Integer, foreign_key = User.id, nullable = False)

class Product_category(Base):
    __tablename__ = "Products_categories"

    id = Column(Integer, primary_key=True, index=True)
    category_id = Column(Integer, foreign_key = Category.id, nullable = False)
    product_id = Column(Integer, foreign_key = Product.id, nullable = False)

class Cart(Base):
    __tablename__ = "carts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, foreign_key = User.id, nullable = False)
    product_id = Column(Integer, foreign_key = Product.id, nullable = False)
    amount = Column(Integer, nullable = False)

class Order(Base):
    __tablename__ = "orders"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, foreign_key = User.id, nullable = False)

Base.metadata.create_all(bind=engine)


