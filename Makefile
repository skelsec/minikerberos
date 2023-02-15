clean:
	rm -f -r build/
	rm -f -r dist/
	rm -f -r *.egg-info
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f  {} +

publish: clean build
	python3 -m twine upload dist/*

rebuild: clean
	pip install .

build:
	pip wheel . -w dist --no-deps
	python3 setup.py sdist