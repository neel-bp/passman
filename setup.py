from setuptools import setup


setup(
   name='passman',
   version='0.3',
   description='simple commandline password manager that uses commandline arguments to do what its meant to do, manage passwords',
   author='Neelu',
   author_email='neelu0@protonmail.com',
   packages=['passman'],  #same as name
   install_requires=['cryptography>=2.7', 'pyperclip>=1.7.0', 'tabulate>=0.8.5', 'pyYAML>=5.1.1'],  #external packages as dependencies
   url='https://github.com/neelu0/passman',
   entry_points={
        "console_scripts": [
            "passman=passman.passman:main",
        ]
    }
)
