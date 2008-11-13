#include <pthread.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <av.h>

#define THREADS_COUNT 10

static struct av_connection av_conn;
static int stop = 0;

void sighandler(int sig)
{
	stop = 1;
}

static void *check(void *data)
{
	struct av_event av_event;
	char fn[PATH_MAX];

	while (!stop) {
		if (av_request(&av_conn, &av_event)) {
			perror("av_request failed");
			return NULL;
		}

		if (av_get_filename(&av_event, fn, PATH_MAX)) {
			perror("av_request failed");
			return NULL;
		}

		if (av_set_result(&av_event, AV_ACCESS_ALLOW)) {
			perror("av_request failed");
			return NULL;
		}

		printf("thread[%lu]: id: %d, type: %d, fd: %d, pid: %d, tgid: \
				%d, res: %d, fn: %s\n", pthread_self(),
				av_event.id, av_event.type, av_event.fd,
				av_event.pid, av_event.tgid, av_event.res, fn);

		if (av_reply(&av_conn, &av_event)) {
			perror("av_request failed");
			return NULL;
		}

	}

	return NULL;
}

int main(int argc, char *argv[])
{

	pthread_t threads[THREADS_COUNT];
	struct sigaction sa;
	int i;
	int rv;

	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_handler = sighandler;
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGTERM);
	sigaddset(&sa.sa_mask, SIGINT);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	if (av_register(&av_conn)) {
		perror("av_register failed");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < THREADS_COUNT; i++) {
		rv = pthread_create(&threads[i], NULL, check, NULL);
		if (rv) {
			fprintf(stderr, "pthread_create failed: %d\n", rv);
			exit(EXIT_FAILURE);
		}
	}

	pause();

	for (i = 0; i < THREADS_COUNT; i++) {
		rv = pthread_join(threads[i], NULL);
		if (rv) {
			fprintf(stderr, "pthread_join failed: %d\n", rv);
			exit(EXIT_FAILURE);
		}
	}

	if (av_unregister(&av_conn)) {
		perror("av_unregister failed");
		exit(EXIT_FAILURE);
	}

	exit(EXIT_SUCCESS);
}

