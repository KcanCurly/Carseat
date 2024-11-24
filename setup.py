from setuptools import setup, find_packages

setup(
    name="Carseat",
    version="1.0.0",
    author="KcanCurly",
    description="lateral movement script that leverages the CcmExec service to remotely hijack user sessions.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/KcanCurly/Carseat",
    packages=find_packages(),
    install_requires=[
        "impacket",
        "pefile"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "carseat.py=src.CarSeat:main",
        ],
    },
)