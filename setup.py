import setuptools
import io
import os


package_root = os.path.abspath(os.path.dirname(__file__))

readme_filename = os.path.join(package_root, 'README.md')
with io.open(readme_filename, encoding='utf-8') as readme_file:
    readme = readme_file.read()


setuptools.setup(
    name="pyjwt_tpm",
    version="0.0.1",
    author="Sal Rashid",
    author_email="salrashid123@gmail.com",
    description="PyJWT signer for TPM based keys",
    long_description=readme,
    long_description_content_type='text/markdown',
    url="https://github.com/salrashid123/pyjwt_tpm",
    install_requires=[
          'tpm2_pytss>=3.0.0',
          'cryptography',
          'PyJWT'
    ],  
    packages=setuptools.find_packages(),
    classifiers=[
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',

        "Programming Language :: Python",
        "Programming Language :: Python :: 3.0",

        "Topic :: Software Development :: Libraries",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
