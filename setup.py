#!/usr/bin/env python3
"""
Setup script for CyberVisionVAPT
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the contents of README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(
    name="cybervision-vapt",
    version="1.0.0",
    author="CyberVisionVAPT Team",
    author_email="",
    description="Automated Vulnerability Assessment and Penetration Testing tool for CCTV cameras & DVRs",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Parthpatil7/CyberVisionVAPT",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.7",
    install_requires=[
        "requests>=2.31.0",
        "urllib3>=2.0.0",
    ],
    entry_points={
        "console_scripts": [
            "cybervision-scanner=cybervision_scanner:main",
        ],
    },
    keywords="security vapt penetration-testing cctv dvr ip-camera vulnerability-scanner",
    project_urls={
        "Bug Reports": "https://github.com/Parthpatil7/CyberVisionVAPT/issues",
        "Source": "https://github.com/Parthpatil7/CyberVisionVAPT",
    },
)
