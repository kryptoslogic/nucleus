#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import glob
import sys
import setuptools

from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext

PYNUCLEUS_VERSION = '0.65'
PYNUCLEUS_REPOSITORY_URL = 'https://bitbucket.org/vusec/nucleus'

# Description
PYNUCLEUS_DESCRIPTION = """PyNucleus
=========

.. image:: https://img.shields.io/pypi/v/pynucleus.svg
    :target: https://pypi.python.org/pypi/pynucleus

Nucleus function detector bindings for Python 2.x and 3.x.
More information at: https://bitbucket.org/vusec/nucleus
"""

__version__ = PYNUCLEUS_VERSION

class get_pybind_include(object):
    """
    Helper class to determine the pybind11 include path

    The purpose of this class is to postpone importing pybind11
    until it is actually installed, so that the ``get_include()``
    method can be invoked.
    """
    def __init__(self, user=False):
        self.user = user

    def __str__(self):
        import pybind11
        return pybind11.get_include(self.user)


# As of Python 3.6, CCompiler has a `has_flag` method.
# cf http://bugs.python.org/issue26689
def has_flag(compiler, flagname):
    """
    Return a boolean indicating whether a flag name is supported on
    the specified compiler.
    """
    import tempfile
    with tempfile.NamedTemporaryFile('w', suffix='.cpp') as f:
        f.write('int main (int argc, char **argv) { return 0; }')
        try:
            compiler.compile([f.name], extra_postargs=[flagname])
        except setuptools.distutils.errors.CompileError:
            return False
    return True


def cpp_flag(compiler):
    """
    Return the -std=c++[11/14] compiler flag.
    The c++14 is prefered over c++11 (when it is available).
    """
    if has_flag(compiler, '-std=c++14'):
        return '-std=c++14'
    elif has_flag(compiler, '-std=c++11'):
        return '-std=c++11'
    else:
        raise RuntimeError(
            'Unsupported compiler -- at least C++11 support is needed!')


class BuildExt(build_ext):
    """
    A custom build extension for adding compiler-specific options.
    """
    c_opts = {
        'msvc': ['/EHsc'],
        'unix': [],
    }
    if sys.platform == 'darwin':
        c_opts['unix'] += ['-stdlib=libc++', '-mmacosx-version-min=10.7']

    def build_extensions(self):
        ct = self.compiler.compiler_type
        opts = self.c_opts.get(ct, [])
        if ct == 'unix':
            opts.append('-DVERSION_INFO="%s"' % self.distribution.get_version())
            opts.append(cpp_flag(self.compiler))
            if has_flag(self.compiler, '-fvisibility=hidden'):
                opts.append('-fvisibility=hidden')
        elif ct == 'msvc':
            opts.append('/DVERSION_INFO=\\"%s\\"' % self.distribution.get_version())
        for ext in self.extensions:
            ext.extra_compile_args = opts
        build_ext.build_extensions(self)

# Sources
sources = ['bindings.cc']
for name in glob.glob('../../*.cc'):
    sources.append(name)

# Modules
ext_modules = [
    Extension(
        'nucleus',
        sources,
        include_dirs=[
            # Path to pybind11 headers
            get_pybind_include(),
            get_pybind_include(user=True)
        ],
        libraries=[
            'capstone',
            'bfd-multiarch'
        ],
        language='c++'
    ),
]

setup(
    name='pynucleus',
    version=PYNUCLEUS_VERSION,
    description='Bindings for the Nucleus function detector',
    long_description=PYNUCLEUS_DESCRIPTION,
    license='BSD (3-clause)',
    author='Dennis Andriesse',
    maintainer='Alexandro Sanchez Bach',
    maintainer_email='alexandro@phi.nz',
    url=PYNUCLEUS_REPOSITORY_URL,
    ext_modules=ext_modules,
    install_requires=['pybind11>=2.2'],
    cmdclass={'build_ext': BuildExt},
    zip_safe=False,
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
        'Natural Language :: English',
    ],
)
