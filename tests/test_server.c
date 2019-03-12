#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "xqc_cmake_config.h"
#include "transport/xqc_conn.h"

int main (int argc, char *argv[])
{
    printf("Usage: %s XQUIC:%d.%d Transport:%s\n", argv[0], xquic_VERSION_MAJOR, xquic_VERSION_MINOR, XQC_TRANSPORT_VERSION);

    return 0;
}
