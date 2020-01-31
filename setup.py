from setuptools import setup, Extension
import os

with open('xxtea.c') as f:
    for line in f:
        if line.startswith("#define VERSION "):
            VERSION = eval(line.rsplit(None, 1)[-1])

if os.name == 'posix':
    extra_compile_args = [
        "-std=c99",
        "-O3",
        "-Wall",
        "-W",
        "-Wundef",
        # ref: http://bugs.python.org/issue21121
        "-Wno-error=declaration-after-statement",
    ]
else:
    extra_compile_args = None

extension = Extension('xxtea', ['xxtea.c'],
                      extra_compile_args=extra_compile_args)

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
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
    python_requires=">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*",
    test_suite="tests",
)
