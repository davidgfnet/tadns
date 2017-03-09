
CXX=g++
CFLAGS=-O2 -ggdb -Wall
CXXFLAGS=$(CFLAGS)

all:	tadns-dig tadns-server

tadns-dig:
	$(CXX) -o tadns-dig tadns.cc tadns_common.cc -DADIG $(CXXFLAGS)

tadns-server:
	$(CXX)-o tadns-server tadns-server.cc tadns.cc tadns_common.cc $(CXXFLAGS)

clean:
	rm -f tadns-dig tadns-server

