from setuptools import setup
import sys

setup(name='dnsq',
      version='1.1.6',
      description='DNS Query Tool',
      long_description=open("README.rst").read(),
      author='Rackspace',
      author_email='admin@mailgunhq.com',
      license='Apache 2',
      url='http://www.mailgun.com',
      py_modules=['dnsq'],
      classifiers=[
                   'Development Status :: 5 - Production/Stable',
                   'Intended Audience :: Developers',
                   'License :: OSI Approved :: Apache Software License',
                   'Programming Language :: Python',
                   'Programming Language :: Python :: 2.7',
                   'Programming Language :: Python :: 3.3',
                   'Programming Language :: Python :: 3.4',
                   'Programming Language :: Python :: 3.5',
                   'Topic :: Internet :: Name Service (DNS)',
                   'Topic :: Software Development :: Libraries',
                   'Topic :: Software Development :: Libraries :: Python Modules'],
      zip_safe=True,
      install_requires=[
        'dnspython>=1.11.1' if (sys.version_info < (3,0)) else 'dnspython3>=1.11.1',
        'expiringdict>=1.1',
      ],
      )
