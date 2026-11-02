.PHONY: starter test
starter:
	python tools/starter_build.py
test:
	python -m unittest discover -s tests -v
