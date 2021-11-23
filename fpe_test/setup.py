from distutils.core import setup
from Cython.Build import cythonize

setup(ext_modules = cythonize('src/ff1.pyx'))