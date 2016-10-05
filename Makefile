CC=g++
CFLAGS=-Wall
SOURCES=tcptrace.c
EXECUTABLE=tcptrace

all:
	$(CC) $(CFLAGS) $(SOURCES) -o $(EXECUTABLE)

clean:
	rm -f *.o
	rm $(EXECUTABLE)

run: all
	./$(EXECUTABLE)
