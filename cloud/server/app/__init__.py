"""Deus Witness Cloud server. Importing the package routes the kernel's Merkle functions through the bounded cache (app/merklecache.py)."""
from app import _paths  # noqa: F401
from app import merklecache

merklecache.install()
