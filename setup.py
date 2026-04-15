from setuptools import setup, find_packages

setup(
    name="clawguard",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "fastapi>=0.100.0",
        "uvicorn[standard]>=0.23.0",
        "pydantic>=2.0.0",
        "pyyaml>=6.0",
        "sse-starlette>=1.6.0",
        "httpx>=0.24.0",
    ],
    entry_points={
        "console_scripts": [
            "clawguard=clawguard.cli:main",
        ],
    },
)
