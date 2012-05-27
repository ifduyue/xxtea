from setuptools import setup
import xxtea
import re

setup(
    name = "xxtea",
    version = xxtea.__version__,
    author = re.sub(r'\s+<.*', r'', xxtea.__author__),
    author_email = re.sub(r'(^.*<)|(>.*$)', r'', xxtea.__author__),
    url = xxtea.__url__,
    description = ("xxtea implemented in pure Python."),
    long_description = open('README.rst').read(),
    license = "BSD",
    keywords = "xxtea",
    py_modules = ['xxtea'],
    classifiers = [
        'Development Status :: 4 - Beta',
        'Programming Language :: Python',
        #'Programming Language :: Python :: 3',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: POSIX',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    include_package_data = True,
)

