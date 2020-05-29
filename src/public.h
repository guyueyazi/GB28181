#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define LOGI(fmt, args...) printf("%s:%d(%s) $ "fmt"\n", __FILENAME__, __LINE__, __FUNCTION__, ##args)
#define LOGE(fmt, args...) printf("\e[0;31m%s:%d(%s)$ "fmt"\n\e[0m", __FILENAME__, __LINE__, __FUNCTION__, ##args)
