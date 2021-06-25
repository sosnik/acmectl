from setuptools import setup

setup(
    name="acme-hooked",
    version="0.2.0",
    url="https://github.com/mmorak/acme-hooked",
    author="Michael Morak",
    author_email="michael@morak.net",
    description="A script to issue TLS certificates via ACME",
    license="MIT",
    packages=['acme_hooked'],
    package_dir={'acme_hooked': '.'},
    package_data={'acme_hooked': ['hooks/acme_tiny.sh']},
    entry_points={'console_scripts': [
        'acme-hooked = acme_hooked.acme_hooked:main',
        'acme-tiny = acme_hooked.acme_tiny:main',
    ]},
    classifiers = [
        'Development Status :: 4 - Beta',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
    ]
)
