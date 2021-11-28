from setuptools import setup
from Cython.Build import cythonize

setup(
	ext_modules = cythonize(["src/FPE/ff1.pyx","src/FPE/ff3.pyx"])

)