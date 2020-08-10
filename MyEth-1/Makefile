PROGRAM=MyEth
OBJS=main.o param.o sock.o ether.o arp.o ip.o icmp.o cmd.o
SRCS=$(OBJS:%.o=%.c)
CFLAGS=-Wall -g
# ubuntu環境ではフラグが違う
# LDFLAGS=-lpthread
LDFLAGS=-pthread
$(PROGRAM):$(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(PROGRAM) $(OBJS) $(LDLIBS)
