CC=g++
CFLAGS=-Wall -shared -fPIC -ldl 
SOURCES=netspy.c lib.c data_collection.c
EXECUTABLE=netspy.so

all:
	$(CC) $(CFLAGS) $(SOURCES) -o $(EXECUTABLE)

clean:
	rm -f *.o
	rm $(EXECUTABLE)

run: all
	LD_PRELOAD=./$(EXECUTABLE) curl -s google.com > /dev/null
