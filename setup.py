from setuptools import setup, Extension
import os

VERSION = "1.2.0"

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

define_macros = [
    ('VERSION', VERSION),
]

extension = Extension('xxtea', ['xxtea.c'],
                      extra_compile_args=extra_compile_args,
                      define_macros=define_macros)

setup(
    name="xxtea",
    version=VERSION,
    author='Yue Du',
    author_email='ifduyue@gmail.com',
    url='https://github.com/ifduyue/xxtea',
    description="xxtea",
    long_description=open('README.rst').read(),
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
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
    setup_requires=["nose>=1.3.0"],
    test_suite='nose.collector',
)
