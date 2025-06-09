from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base

SQLALCHEMY_DATABASE_URL = "mysql+pymysql://isp_p_Chesnokov:12345@77.91.86.135/isp_p_Bulatov"

engine = create_async_engine(
    SQLALCHEMY_DATABASE_URL,
    echo=True,  
    pool_size=5,
    max_overflow=10
)

AsyncSessionLocal = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False
)

Base = declarative_base()

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session