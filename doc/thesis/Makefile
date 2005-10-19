all: thesis.ps
	gv thesis.ps

thesis.ps: thesis.dvi
	dvips thesis.dvi -o thesis.ps

thesis.dvi: thesis.tex
	latex thesis.tex
	latex thesis.tex

clean:
	rm -f *~ *.dvi *.aux *.log *.toc *.bak *.lof thesis.ps

