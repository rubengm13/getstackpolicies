from setuptools import setup, find_packages

setup(
    name='getstackpolicies',
    version='0.1.0',
    author='Ruben Gutierrez',
    author_email='rugutierrez@paloaltonetworks.com',
    packages=find_packages(),
    url='https://github.com/rubengm13/getstackpolicies',
    license='',
    description='Class to pull the SD-WAN policies',
    install_requires=[
        'cloudgenix',
        'unipath'
    ]
)
