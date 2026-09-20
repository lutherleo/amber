"""Fixture — bare-call constructors after ``from X import Y``.

Expected discovery:
- 3 DiscoveredDataStore records (redis, mongodb, sqlalchemy) via
  bare-call form after from-imports.
"""

from pymongo import MongoClient
from redis import Redis
from sqlalchemy import create_engine

cache = Redis(host="localhost", port=6379)
db = MongoClient("mongodb://localhost:27017")
engine = create_engine("postgresql://localhost/app")
