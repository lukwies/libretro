from setuptools import setup,find_packages

# TODO python versions

setup(
	name='libretro',
	version='0.1.0',
	description='core library of the retro messenger',
	url='https://github.com/lukwies/libretro',
	author='Lukas Wiese',
	author_email='luken@gmx.net',
	licence='GPLv3+',
	packages=['libretro'],
	install_requires=[
		'cryptography',
		'sqlcipher3-binary'
	],
	python_requires='>=3.6',
	classifiers=[
		"Development Status :: 3 - Alpha",
		"Environment :: Console",
		"Environment :: Console :: Curses",

		"Intended Audience :: Developers",
		"Intended Audience :: Education",
		"Intended Audience :: End Users/Desktop",

		"License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
		'Operating System :: POSIX',
		'Programming Language :: Python :: 3.11',
		'Topic :: Software Development',
		'Topic :: Utilities',
	]
)
