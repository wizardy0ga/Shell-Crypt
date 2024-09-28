#include <windows.h>
#include <stdio.h>

#define apierror(api)   printf("[Error] - " api " failed with error: %d\n", GetLastError())
#define error(msg, ...) printf("[Error] - " msg "\n", ##__VA_ARGS__)
#define info(msg, ...)  printf("[Info] - " msg "\n", ##__VA_ARGS__)