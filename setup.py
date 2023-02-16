from setuptools import find_packages, setup

setup(
    name='cidr',
    version='0.0.1',
    description='Experimental library for storing and manipulating sets of CIDR format IP ranges.',
    author='Ben Wallberg',
    author_email="wallberg@umd.edu",
    platforms=["any"],
    license="Apache 2.0",
    url="https://github.com/wallberg-umd/cidr",
    packages=find_packages(),
    install_requires=[i.strip() for i in open("requirements.txt").readlines()],
    python_requires='>=3.10',
    extras_require={  # Optional
       'dev': ['pycodestyle==2.10.0'],
       'test': ['pytest==7.2.1', 'pytest-cov==2.12.1'],
    }
)
