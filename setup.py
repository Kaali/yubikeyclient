# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
import sys, os

version = '0.1'

try:
    f = open('README.txt')
    long_description = f.read() + '\n\n'
finally:
    f.close()

setup(name='yubikeyclient',
      version=version,
      description="Yubikey Client library",
      long_description=long_description,
      classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Utilities'
        ],
      keywords='yubico yubikey client',
      author=u'Väinö Järvelä',
      author_email='vaino at complexusage.net',
      url='',
      license='MIT',
      packages=find_packages('src'),
      package_dir={'': 'src'},
      include_package_data=True,
      zip_safe=False,
      install_requires=[
        'setuptools'
      ],
      entry_points="""
# -*- Entry points: -*-
[console_scripts]
query_otp = yubikeyclient.cmdline:query_yubico_wsapi
      """,
      )
