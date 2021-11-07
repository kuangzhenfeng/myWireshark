#ifndef COMMONDEBUG_H
#define COMMONDEBUG_H

#define DEBUG(fmt, ...) do {printf("\033[1;32m" "[DEBUG]<%s>(%d): " fmt "\033[0m\n", __FUNCTION__,  __LINE__, ##__VA_ARGS__); fflush(stdout);} while(0)

#endif // COMMONDEBUG_H
