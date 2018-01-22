import codecs
from setuptools import setup
import os.path as path

install_requires = ['requests']
cwd = path.dirname(__file__)
version = '0.1.4'

setup(
    name='dispatchsdk',
    author='Jason Raede',
    author_email='jason@dispatch.me',
    version=version,
    license='MIT',
    description='SDK for interacting with the Dispatch platform',
    url='https://github.com/DispatchMe/python-sdk',
    packages=['dispatchsdk'],
    platforms='ANY',
    python_requires='>=3',
    requires=['requests', 'urllib3']
)
