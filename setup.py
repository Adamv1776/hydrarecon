#!/usr/bin/env python3
"""
HydraRecon - Enterprise Security Assessment Suite
Setup script for pip installation
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8")

setup(
    name="hydrarecon",
    version="1.0.0",
    author="HydraRecon Team",
    author_email="support@hydrarecon.io",
    description="Enterprise Security Assessment Suite",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://hydrarecon.io",
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.10",
    install_requires=[
        "PyQt6>=6.6.0",
        "python-nmap>=0.7.1",
        "paramiko>=3.4.0",
        "requests>=2.31.0",
        "aiohttp>=3.9.0",
        "pandas>=2.1.0",
        "numpy>=1.26.0",
        "sqlalchemy>=2.0.23",
        "matplotlib>=3.8.0",
        "networkx>=3.2.1",
        "reportlab>=4.0.7",
        "jinja2>=3.1.2",
        "rich>=13.7.0",
        "click>=8.1.7",
        "cryptography>=41.0.7",
        "pyyaml>=6.0.1",
        "psutil>=5.9.0",
    ],
    entry_points={
        "console_scripts": [
            "hydrarecon=main:main",
            "hydrarecon-lite=lite:main",
        ],
        "gui_scripts": [
            "hydrarecon-gui=launcher:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: X11 Applications :: Qt",
        "Intended Audience :: Information Technology",
        "License :: Other/Proprietary License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ],
)
