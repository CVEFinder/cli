#!/usr/bin/env python3
"""
CVEFinder CLI Setup
Official command-line interface for CVEFinder.io API
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="cvefinder-io",
    version="1.0.0",
    author="CVEFinder.io",
    author_email="support@cvefinder.io",
    description="Official CLI for CVEFinder.io API - CVE scans, dependency analysis, bulk scans, and exports",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/CVEFinder/cli",
    project_urls={
        "Bug Tracker": "https://github.com/CVEFinder/cli/issues",
        "Documentation": "https://docs.cvefinder.io",
        "Source Code": "https://github.com/CVEFinder/cli",
        "Website": "https://cvefinder.io",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    install_requires=[
        "aiohttp>=3.9.0",
        "click>=8.1.0",
        "rich>=13.0.0",
        "tabulate>=0.9.0",
        "pyyaml>=6.0",
    ],
    entry_points={
        "console_scripts": [
            "cvefinder=cvefinder.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
