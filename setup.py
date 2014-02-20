from setuptools import setup

setup(name='dnsq',
      version='1.1',
      description='DNS Query Tool',
      author='Rackspace',
      author_email='admin@mailgunhq.com',
      license='Apache 2',
      url='http://www.mailgun.com',
      py_modules=['dnsq'],
      zip_safe=True,
      install_requires=[
        'dnspython==1.11.1',
      ],
      )
