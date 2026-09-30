CC     ?= clang
PYTHON ?= python3

.PHONY: all run clean

all: render trigger.pdf

render: render.c
	$(CC) -O2 -g -o $@ $< -framework ImageIO -framework CoreGraphics -framework CoreFoundation

trigger.ttf: gen_font.py
	$(PYTHON) gen_font.py $@

trigger.pdf: gen_pdf.py trigger.ttf
	$(PYTHON) gen_pdf.py $@ trigger.ttf

run: all
	./render trigger.pdf ; echo "exit=$$?"

clean:
	rm -f render trigger.ttf trigger.pdf
	rm -rf render.dSYM
