from setuptools import setup, find_packages

setup(
    name="aegis-waf",
    version="2.0.0",
    description="Next-Gen AI-Driven Web Application Security & Threat Defense Platform",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    install_requires=[
        "flask>=2.0.0",
        "joblib>=1.0.0",
        "numpy>=1.20.0",
        "scipy>=1.7.0",
        "scikit-learn>=1.0.0",
    ],
)
