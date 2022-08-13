SRCDIR = ./src
INCDIR = ./include
BINDIR = ./bin
OBJDIR = ./obj
CPP=g++
LIBS= ./lib/libcrypto.so.3


all: $(BINDIR)/q1 $(BINDIR)/q2 

$(BINDIR)/q1 : $(SRCDIR)/q1.cpp
	$(CPP) -o $@ $^ $(LIBS)

$(BINDIR)/q2 : $(SRCDIR)/q2.cpp
	$(CPP) -o $@ $^

clean: 
	rm -fr $(BINDIR)/* 	$(OBJDIR)/*
