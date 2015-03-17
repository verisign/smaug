################################################################################
# 
################################################################################
.PHONY : all build clean package test_me

SRCDIR     =$(PWD)/src $(PWD)/extensions/thunderbird
INCLUDEDIR =$(PWD/include

BUILDDIR   =$(PWD)/build  
BINDIR     =$(PWD)/bin 

PROJ       = dane-email   

SUBDIRS    = ${SRCDIR}

all: build

test:
	@mkdir -p ${BUILDDIR}
	for dir in $(SUBDIRS);   do     \
		$(MAKE) -C $$dir test;    \
	done

build:
	@mkdir -p ${BUILDDIR}
	for dir in $(SUBDIRS);   do     \
		$(MAKE) -C $$dir all;    \
	done

# Other Targets
clean:
	rm -fr *~ *.o
	rm build/*
	for dir in $(SUBDIRS); do	\
		$(MAKE) -C $$dir clean;	\
	done
	rm -f include/*~
	


