#include <unistd.h>
#include <packetgraph/packetgraph.h>
#include <string.h>
#include <glib.h>
#include <stdlib.h>


int main(int argc, char **argv)
{
	pg_start(argc, argv);
	fork();
	printf("OK\n");
}
