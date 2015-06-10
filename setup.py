from setuptools import setup

setup(name='dnsq',
      version='1.1.3',
      description='DNS Query Tool',
      long_description=open("README.rst").read(),
      author='Rackspace',
      author_email='admin@mailgunhq.com',
      license='Apache 2',
      url='http://www.mailgun.com',
      py_modules=['dnsq'],
      zip_safe=True,
      install_requires=[
        'dnspython==1.12.0',
        'expiringdict>=1.1',
      ],
      )
