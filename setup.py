#!/usr/bin/env python3

from setuptools import setup

setup(install_requires=open("requirements.txt", "r", encoding="utf-8").read().splitlines())