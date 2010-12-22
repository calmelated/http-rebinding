EXEC = web-rebinding
OBJS += recv_pkt.o
OBJS += send_pkt.o
OBJS += web_rebinding.o

LIBPATH = -L../$(TARGET_PREFIX)lib
LDFLAGS += $(LIBPATH) -lcsman

INCPATH = -I./ -I../../include -I../../../include
CFLAGS += $(INCPATH) 

all: $(EXEC)
	$(STRIP) $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $(EXEC)

%.o: %.c 
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	-rm -f $(EXEC) *.o
