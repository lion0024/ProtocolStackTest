#ifndef SOC_DEV_H
#define SOC_DEV_H

#include <stdint.h>
#include <signal.h>
#include <stddef.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

struct soc_dev;

struct soc_dev *soc_dev_open(char *name);
void soc_dev_close(struct soc_dev *dev);
void soc_dev_rx(struct soc_dev *dev,
                void (*callback)(uint8_t *, size_t, void *), void *arg,
                int timeout);
ssize_t soc_dev_tx(struct soc_dev *dev, const uint8_t *buf, size_t len);
int soc_dev_addr(char *name, uint8_t *dst, size_t size);

#endif
