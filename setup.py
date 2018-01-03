# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.

import os
import sys
from setuptools import setup

# Get location of this file at runtime
HERE = os.path.abspath(os.path.dirname(__file__))

# Eval the version tuple and string from the source
VERSION_NS = {}
with open(os.path.join(HERE, 'nb2kg', '_version.py')) as f:
    exec(f.read(), {}, VERSION_NS)

install_requires=[
    'notebook>=4.2.0,<6.0',
]

setup_args = dict(
    name='nb2kg',
    author='Jupyter Development Team',
    author_email='jupyter@googlegroups.com',
    description='Extension for Jupyter Notebook 4.2.x to enable remote kernels hosted by Kernel Gateway or Enterprise Gateway',
    long_description = '''\
NB2KG is a Jupyter Notebook extension for versions >= 4.2 that enables remote kernels hosted 
by `Jupyter Kernel Gateway <https://pypi.org/project/jupyter_kernel_gateway>`_ 
or `Jupyter Enterprise Gateway <https://pypi.org/project/jupyter_enterprise_gateway>`_.  
See `README <https://github.com/jupyter-incubator/nb2kg>`_ for more information.
''',
    url='https://github.com/jupyter-incubator/nb2kg',
    version=VERSION_NS['__version__'],
    license='BSD',
    platforms=['Jupyter Notebook 4.2.x'],
    packages=[
        'nb2kg'
    ],
    include_package_data=True,
    scripts=[
    ],
    install_requires=install_requires,
    classifiers=[
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
    ]
)

if __name__ == '__main__':
    setup(**setup_args)
