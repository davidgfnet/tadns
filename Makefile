
all:	tadns-dig tadns-server

tadns-dig:
	g++ -o tadns-dig tadns.cc tadns_common.cc -DADIG -O2 -ggdb -Wall

tadns-server:
	g++ -o tadns-server tadns-server.cc tadns.cc tadns_common.cc -O2 -ggdb -Wall

clean:
	rm -f tadns-dig tadns-server

