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
	const char *fn;
	const char *en;
	int event;
	int rv;

	memset(&sa, 0, sizeof(struct sigaction));
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

		rv = av_get_filename(&avr, &fn);
		if (rv) {
			fprintf(stderr, "av_get_filename failed: %s(%d)\n", strerror(rv), rv);
			return 1;
		}

		rv = av_get_event(&avr, &event);
		if (rv) {
			fprintf(stderr, "av_get_event failed: %s(%d)\n", strerror(rv), rv);
			return 1;
		}

		switch (event) {
			case AV_EVENT_OPEN:
				en = "OPEN";
				break;
			case AV_EVENT_EXEC:
				en = "EXEC";
				break;
			case AV_EVENT_CLOSE:
				en = "CLOSE";
				break;
			case AV_EVENT_CLOSE_MODIFIED:
				en = "CLOSE_MODIFIED";
				break;
			default:
				en = "UNKNOWN";
		}

		printf("access control: %s: %s\n", en, fn);

		rv = av_set_access(&avr, AV_ACCESS_ALLOW); 
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

