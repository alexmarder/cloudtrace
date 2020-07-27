from Cython.Distutils import build_ext
from setuptools import setup, find_packages
from setuptools.extension import Extension
from Cython.Build import cythonize

extensions_names = {
    'cloudtrace.utils': ['cloudtrace/utils.pyx'],
    'cloudtrace.probe': ['cloudtrace/probe.pyx']
}

extensions = [Extension(k, v) for k, v in extensions_names.items()]
package_data = {k: ['*.pxd'] for k in extensions_names}

setup(
    name="cloudtrace",
    version='0.0.5',
    author='Alex Marder',
    # author_email='notlisted',
    description="Various packages for traceroute and BGP dump analysis.",
    url="https://github.com/alexmarder/traceutils",
    packages=find_packages(),
    install_requires=['cython', 'scapy', 'traceutils'],
    cmdclass={'build_ext': build_ext},
    ext_modules=cythonize(
        extensions,
        compiler_directives={
            'language_level': '3',
            'embedsignature': True
        },
        annotate=True,
        gdb_debug=True
    ),
    entry_points={
        'console_scripts': ['fasttrace=cloudtrace.fasttrace:main'],
    },
    zip_safe=False,
    package_data=package_data,
    include_package_data=True,
    python_requires='>3.6'
)
