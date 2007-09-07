#include "../av.h"
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#define THREADS_NUM 10

struct av_con avc;
int intr = 0;

void sighandler(int sig)
{
	intr = 1;
}

void *check(void *data)
{
	struct av_req avr;
	sigset_t sigmask;
	const char *fn;
	const char *en;
	int event;
	int fd;
	int rv;

	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGINT);
	sigaddset(&sigmask, SIGTERM);
	pthread_sigmask(SIG_BLOCK, &sigmask, NULL);

	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGUSR1);
	pthread_sigmask(SIG_UNBLOCK, &sigmask, NULL);

	while (!intr) {
		rv = av_request(&avc, &avr);
		if (rv) {
			fprintf(stderr, "av_request failed: %s(%d)\n", strerror(rv), rv);
			return NULL;
		}

		rv = av_get_fn(&avc, &avr, &fn);
		if (rv) {
			fprintf(stderr, "av_get_fn failed: %s(%d)\n", strerror(rv), rv);
			goto reply;
		}

		rv = av_get_fd(&avr, &fd);
		if (rv) {
			fprintf(stderr, "av_get_fd failed: %s(%d)\n", strerror(rv), rv);
			goto reply;
		}

		rv = av_get_event(&avr, &event);
		if (rv) {
			fprintf(stderr, "av_get_event failed: %s(%d)\n", strerror(rv), rv);
			goto reply;
		}

		switch (event) {
			case AV_EVENT_OPEN:
				en = "OPEN";
				break;

			case AV_EVENT_CLOSE:
				en = "CLOSE";
				break;
			default:
				en = "UNKNOWN";
		}

		printf("%lu: access control: %s: %s\n", pthread_self(), en, fn);

		rv = av_set_access(&avr, AV_ACCESS_ALLOW); 
		if (rv) {
			fprintf(stderr, "av_access failed: %s(%d)\n", strerror(rv), rv);
			goto reply;
		}

		rv = av_reply(&avc, &avr);
		if (rv) {
			fprintf(stderr, "av_reply failed: %s(%d)\n", strerror(rv), rv);
			goto reply;
		}
	}

	return NULL;

reply:
	rv = av_reply(&avc, &avr);
	if (rv)
		fprintf(stderr, "av_reply in exit failed: %s(%d)\n", strerror(rv), rv);

	return NULL;

}

int main(int argc, char *argv[])
{
	struct sigaction sa;
	pthread_t threads[THREADS_NUM];
	int rv;
	int i;

	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_handler = sighandler;
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGTERM);
	sigaddset(&sa.sa_mask, SIGINT);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGUSR1, &sa, NULL);

	rv = av_register(&avc);
	if (rv) {
		fprintf(stderr, "av_register failed: %s(%d)\n", strerror(rv), rv);
		return 1;
	}

	rv = av_include("/tmp");
	if (rv) {
		av_unregister(&avc);
		fprintf(stderr, "av_include failed: %s(%d)\n", strerror(rv), rv);
		return 1;
	}

	for (i = 0; i < THREADS_NUM; i++) {
		rv = pthread_create(&threads[i], NULL, check, NULL);
		if (rv)
			fprintf(stderr, "pthread_create failed: %s(%d)\n", strerror(rv), rv);
	}

	pause();

	for (i = 0; i < THREADS_NUM; i++) {
		rv = pthread_kill(threads[i], SIGUSR1);
		if (rv)
			fprintf(stderr, "pthread_kill failed: %s(%d)\n", strerror(rv), rv);
	}

	for (i = 0; i < THREADS_NUM; i++) {
		rv = pthread_join(threads[i], NULL);
		if (rv)
			fprintf(stderr, "pthread_join failed: %s(%d)\n", strerror(rv), rv);
	}

	rv = av_exclude("/tmp");
	if (rv) {
		av_unregister(&avc);
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

