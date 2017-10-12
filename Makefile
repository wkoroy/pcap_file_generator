APP = ./pcap_file_generator
CC=gcc
CFLAGS=-ldl -lrt -lpthread -Wall -Wextra

all: $(APP)

$(APP): sample.o  pcap_file_generator.o
	$(CC) sample.o pcap_file_generator.o -o $(APP) $(CFLAGS)
sample.o: sample.c	
	$(CC) sample.c -c -Wall

pcap_file_generator.o: pcap_file_generator.c	
	$(CC) pcap_file_generator.c -c -Wall



clean:
	rm -f *.o ; rm $(APP)
