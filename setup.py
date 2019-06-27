from setuptools import setup, find_packages
import os

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.md')).read()

version = '1.0.0'

setup(
    name='ehsm',
    version=version,
    description='Python bindings for the ellipticSecure PKCS11 shared library',
    long_description=README,
    long_description_content_type='text/markdown',
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
    ],
    keywords='',
    author='Kobus Grobler',
    author_email='kobus.grobler@gmail.com',
    url='https://github.com/ellipticSecure/python-libehsm',
    license='MIT',
    packages=find_packages(),
    install_requires=[
       'base58'
    ],
    zip_safe=False
)
