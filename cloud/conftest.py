import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import testshim


def pytest_configure(config):
    testshim.install()
