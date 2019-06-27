from setuptools import setup, find_packages


setup(name='poc-sender',
    version='0.0.1',
    description='a simple way to run poc',
    url='https://github.com/f0cklinux/poc_sender.git',
    author='f0cklinux',
    author_email='hasdsaf@gmail.com',
    license='MIT',
    zip_safe=False,
    packages=find_packages(),
    install_requires=[],
    entry_points={
    	'console_scripts': ['Poc=poc_sender.sender:run']
    },

)


