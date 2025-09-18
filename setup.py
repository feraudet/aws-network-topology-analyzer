"""
Setup script for AWS Network Discovery and Analysis Tool
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="aws-network-discovery",
    version="1.0.0",
    author="AXA Network Team",
    author_email="network-team@axa.com",
    description="Comprehensive AWS network topology discovery and analysis tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/axa/aws-network-discovery",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: DevOps Engineers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: System :: Systems Administration",
        "Topic :: System :: Networking",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-mock>=3.11.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "aws-network-discovery=main:cli",
        ],
    },
    include_package_data=True,
    package_data={
        "aws_network_discovery": [
            "templates/*.html",
            "templates/*.jinja2",
        ],
    },
)
