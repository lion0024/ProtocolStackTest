#include "soc.h"

struct soc_dev {
    int fd;
};

struct soc_dev *soc_dev_open(char *name) {
    struct soc_dev *dev;
    struct ifreq ifr;
    struct sockaddr_ll sockaddr;

    dev = malloc(sizeof(struct soc_dev));
    dev->fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (dev->fd == -1) {
      perror("socket");
      goto ERROR;  // gotoはあまり使いたくないので修正も考える
    }

    // find device interface index
    strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name) - 1);
    if (ioctl(dev->fd, SIOCGIFINDEX, &ifr) == -1) {
      perror("ioctl [SIOCGIFINDEX]");
      goto ERROR;
    }

    // bind device interface
    memset(&sockaddr, 0, sizeof(sockaddr));
    sockaddr.sll_family = AF_PACKET;
    sockaddr.sll_protocol = htons(ETH_P_ALL);
    sockaddr.sll_ifindex = ifr.ifr_ifindex;
    if (bind(dev->fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) == -1) {
      perror("bind");
      goto ERROR;
    }

    // set IFF_PROMISC flag
    if (ioctl(dev->fd, SIOCGIFFLAGS, &ifr) == -1) {
      perror("ioctl [SIOCGIFFLAGS]");
      goto ERROR;
    }
    ifr.ifr_flags = ifr.ifr_flags | IFF_PROMISC;
    if (ioctl(dev->fd, SIOCGIFFLAGS, &ifr) == -1) {
      perror("ioctl [SIOCSFFLAGS]");
      goto ERROR;
    }

    return dev;

ERROR:
  if (dev) {
    soc_dev_close(dev);
  }
  return NULL;
}

void soc_dev_close(struct soc_dev *dev) {
  if (dev->fd != -1) {
      close(dev->fd);
    }
    free(dev);
}

void soc_dev_rx(struct soc_dev *dev,
                void (*callback)(uint8_t *, size_t, void *),
                void *arg, int timeout) {
  struct pollfd pfd;
  int ret;
  ssize_t len;
  uint8_t buf[2048];

  // wait until packet arrives
  pfd.fd = dev->fd;
  pfd.events = POLLIN;
  ret = poll(&pfd, 1, timeout);
  switch (ret) {
    case -1:
      if (errno != EINTR) {
        perror("poll");
      }
    case 0: /* timeout */
      return;
  }

  len = read(dev->fd, buf, sizeof(buf));
  switch (len) {
    case -1:
      perror("read");

    case 0:
      return;
  }
  callback(buf, len, arg);
}

ssize_t soc_dev_tx(struct soc_dev *dev, const uint8_t *buf, size_t len) {
  return write(dev->fd, buf, len);
}

int soc_dev_addr(char *name, uint8_t *dst, size_t size) {
  int fd;
  struct ifreq ifr;

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd == -1) {
    perror("socket");
    return -1;
  }
  ifr.ifr_addr.sa_family = AF_INET;
  strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name) - 1);
  if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
    perror("ioctl [SIOCGIFHWADDR]");
    close(fd);
    return -1;
  }
  memcpy(dst, ifr.ifr_hwaddr.sa_data, size);
  close(fd);
  return 0;
}
