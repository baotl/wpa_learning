CC=gcc
CFLAG+=-L./
DEPS = wpa_ctrl.h
INC+=-I./
LIBS+=-lwpa_client -lrt

test: main.c
	$(CC) $(INC) $< $(CFLAG) $(LIBS) -o $@

clean:
	rm -f *.o
	rm -f test
