from setuptools import setup, find_packages

setup(
    name="vulnvas",
    version="1.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "requests",
        "python-nmap",
        "beautifulsoup4",
        "pandas",
        "matplotlib",
        "scikit-learn",
        "joblib"
    ],
    entry_points={
        "console_scripts": [
            "vulnvas=vulnvas_package.cli:main"
        ]
    },
)
