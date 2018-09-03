LIB = ./libpcap_file_generator.a
CC=gcc
CFLAGS=-D_FILE_OFFSET_BITS=64  -ldl -lrt -lpthread -Wall -Wextra
AR=ar
all: $(LIB)

$(LIB): pcap_file_generator.o pcap_file_reader.o utils.o
	$(AR) r $(LIB) pcap_file_generator.o pcap_file_reader.o utils.o

pcap_file_generator.o: pcap_file_generator.c 	
	$(CC) pcap_file_generator.c -c -Wall  $(CFLAGS)  

pcap_file_reader.o: pcap_file_reader.c
	$(CC) pcap_file_reader.c -c -Wall $(CFLAGS)

utils.o: utils.c
	$(CC) utils.c -c -Wall $(CFLAGS)
clean:
	rm -f *.o ; rm $(LIB)
