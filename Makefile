tipa: all
	cp Fugu15/Fugu15.ipa Fugu15.tipa

all %:
	$(MAKE) -C Fugu15 $@
