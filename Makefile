
all:	tadns-dig

tadns-dig:
	g++ -o tadns-dig tadns.cc tadns_common.cc -DADIG -O2 -ggdb -Wall

clean:
	rm -f tadns-dig

