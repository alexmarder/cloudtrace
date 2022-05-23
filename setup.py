import os
import sys

from setuptools import setup, find_packages
from setuptools.extension import Extension

exec(open('cloudtrace/version.py').read())

print(sys.argv)
if 'build_ext' in sys.argv:
    from Cython.Distutils import build_ext
    use_cython = True
else:
    use_cython = False


print(use_cython)

ext_pyx = '.pyx' if use_cython else '.c'
ext_py = '.py' if use_cython else '.c'

extensions_names = {
    'cloudtrace.trace.utils': ['cloudtrace/trace/utils' + ext_pyx],
    'cloudtrace.trace.probe': ['cloudtrace/trace/probe' + ext_pyx],
    'cloudtrace.trace.fasttrace': ['cloudtrace/trace/fasttrace' + ext_py],
    'cloudtrace.trace.scampertrace': ['cloudtrace/trace/scampertrace' + ext_py],
    'cloudtrace.trace.cloudscamper': ['cloudtrace/trace/cloudscamper' + ext_py],
    'cloudtrace.trace.randomize': ['cloudtrace/trace/randomize' + ext_py],

    'cloudtrace.read.utils': ['cloudtrace/read/utils' + ext_pyx],
    'cloudtrace.read.pcap': ['cloudtrace/read/pcap' + ext_pyx],
    'cloudtrace.read.combine': ['cloudtrace/read/combine' + ext_pyx],
    'cloudtrace.read.packet': ['cloudtrace/read/packet' + ext_pyx],
    'cloudtrace.read.convert': ['cloudtrace/read/convert' + ext_pyx],
    'cloudtrace.read.linkedlist': ['cloudtrace/read/linkedlist' + ext_pyx],
    'cloudtrace.read.reader': ['cloudtrace/read/reader' + ext_py],
}

extensions = [Extension(k, v) for k, v in extensions_names.items()]
package_data = {k: ['*.pxd', '*pyx', '*.py'] for k in extensions_names}

if use_cython:
    from Cython.Build import cythonize
    extensions = cythonize(
        extensions,
        compiler_directives={'language_level': '3', 'embedsignature': True},
        annotate=True,
        gdb_debug=True
    )


setup(
    name="cloudtrace",
    version=__version__,
    author='Alex Marder',
    # author_email='notlisted',
    description="Various packages for traceroute and BGP dump analysis.",
    url="https://github.com/alexmarder/traceutils",
    packages=find_packages(),
    # setup_requires=["cython"],
    install_requires=['scapy', 'file2', 'pb_amarder'],
    # cmdclass={'build_ext': build_ext},
    ext_modules=extensions,
    entry_points={
        'console_scripts': [
            'fasttrace=cloudtrace.trace.fasttrace:main',
            'scampertrace=cloudtrace.trace.scampertrace:main',
            'cloudscamper=cloudtrace.trace.cloudscamper:main',
            'cloudshuffle=cloudtrace.scripts.trace:main',
            'fastread=cloudtrace.read.reader:main',
            'ct-randomize=cloudtrace.trace.randomize:main'
        ],
    },
    zip_safe=False,
    package_data=package_data,
    include_package_data=True,
    python_requires='>3.6,<3.9'
)
