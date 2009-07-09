from setuptools import setup, find_packages
import sys, os

version = '0.1'

setup(name='yubikeyclient',
      version=version,
      description="foobar",
      long_description="""\
bar""",
      classifiers=[], # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      keywords='yubico yubikey client',
      author='V\xc3\xa4in\xc3\xb6 J\xc3\xa4rvel\xc3\xa4',
      author_email='',
      url='',
      license='MIT',
      packages=find_packages('src'),
      package_dir = {'': 'src'},include_package_data=True,
      zip_safe=False,
      install_requires=[
          # -*- Extra requirements: -*-
      ],
      entry_points="""
      # -*- Entry points: -*-
      """,
      )
