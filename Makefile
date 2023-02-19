test:
	pytest
	pycodestyle *.py

doc: doc/fig1.svg doc/fig2.svg doc/fig3.svg doc/fig4.svg

%.dot: %.gv
	dot -Tdot $< | gvpr -c -f doc/binaryTree.gvpr -o $@

%.svg: %.dot
	neato -n -Tsvg $< -o $@

clean:
	rm doc/*.svg doc/*.dot
