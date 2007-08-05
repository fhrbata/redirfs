#include "../av.h"
#include <signal.h>
#include <stdio.h>
#include <string.h>

int intr = 0;

void sighandler(int sig)
{
	intr = 1;
}

int main(int argc, char *argv[])
{
	struct sigaction sa;
	struct av_con avc;
	struct av_req avr;
	int rv;

	sa.sa_handler = sighandler;
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGTERM);
	sigaddset(&sa.sa_mask, SIGINT);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	rv = av_register(&avc);
	if (rv) {
		fprintf(stderr, "av_register failed: %s(%d)\n", strerror(rv), rv);
		return 1;
	}

	rv = av_include("/tmp");
	if (rv) {
		fprintf(stderr, "av_include failed: %s(%d)\n", strerror(rv), rv);
		return 1;
	}

	while (!intr) {
		rv = av_request(&avc, &avr);
		if (rv) {
			fprintf(stderr, "av_request failed: %s(%d)\n", strerror(rv), rv);
			return 1;
		}

		printf("access control: %s\n", avr.fn);

		rv = av_access(&avc, &avr, 1); 
		if (rv) {
			fprintf(stderr, "av_access failed: %s(%d)\n", strerror(rv), rv);
			return 1;
		}

		rv = av_reply(&avc, &avr);
		if (rv) {
			fprintf(stderr, "av_reply failed: %s(%d)\n", strerror(rv), rv);
			return 1;
		}
	}

	rv = av_exclude("/tmp");
	if (rv) {
		fprintf(stderr, "av_exclude failed: %s(%d)\n", strerror(rv), rv);
		return 1;
	}

	rv = av_unregister(&avc);
	if (rv) {
		fprintf(stderr, "av_unregister failed: %s(%d)\n", strerror(rv), rv);
		return 1;
	}

	return 0;
}

