from setuptools import setup

setup(
    name="hbd",
    version="0.1.0",
    py_modules=["hbd"],
    install_requires=[
        "Click",
    ],
    entry_points={
        "console_scripts": [
            "hbd = hbd:cli",
        ],
    },
)
