from Cython.Build import cythonize
from setuptools import setup

setup(
	ext_modules = cythonize(["src/FPE/ff1.pyx","src/FPE/ff3.pyx"])

)