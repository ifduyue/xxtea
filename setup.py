from setuptools import setup, Extension
import os

with open('xxtea.c') as f:
    for line in f:
        if line.startswith("#define VERSION "):
            VERSION = eval(line.rsplit(None, 1)[-1])

extension = Extension('xxtea', ['xxtea.c'])

setup(
    name="xxtea",
    version=VERSION,
    author='Yue Du',
    author_email='ifduyue@gmail.com',
    url='https://github.com/ifduyue/xxtea',
    description="xxtea is a simple block cipher",
    long_description=open('README.rst', 'rb').read().decode('utf8'),
    license="BSD",
    keywords="xxtea",
    ext_modules=[extension],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
    ],
    python_requires=">=3.7",
)
