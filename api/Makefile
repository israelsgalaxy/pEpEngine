all: basic_api.h

YML2=$(wildcard *.yml2)
YSL2=$(wildcard *.ysl2)

%.xml: %.yml2
	yml2proc -P $< -o $@

%.xsl: %.ysl2
	yml2proc -DP $< -o $@

%.h: $(YML2) $(YSL2)
	yml2proc -y gen_c_header.ysl2 pEp.yml2

.PHONY: clean

clean:
	rm -f *.xml *.xsl *.h
