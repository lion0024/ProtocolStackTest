PROGRAM=MyEth
OBJS=main.o param.o sock.o ether.o arp.o ip.o icmp.o udp.o dhcp.o cmd.o
SRCS=$(OBJS:%.o=%.c)
CFLAGS=-Wall -g
#LDFLAGS=-lpthread
LDFLAGS=-pthread
$(PROGRAM):$(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(PROGRAM) $(OBJS) $(LDLIBS)
