tipa: all
	cp Fugu15/Fugu15.ipa Fugu15.tipa

all %:
	$(MAKE) -C bootstrapFS $@
	$(MAKE) -C jbinjector $@
	$(MAKE) -C FuFuGuGu $@
	$(MAKE) -C stashd $@
	$(MAKE) -C MachOMerger $@
	$(MAKE) -C libdyldhook $@
	CryptexManager buildTrustCache TrustCache Fugu15/Fugu15_test.tc
	$(MAKE) -C Fugu15 $@
