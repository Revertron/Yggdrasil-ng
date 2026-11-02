/*
 * Echo server on the Yggdrasil network using plain poll(2) on the sockets
 * returned by libygg.
 *
 *   cc -o ygg_echo ygg_echo.c -I../../include -L<target dir> -lygg
 *   ./ygg_echo node.toml 7000
 */
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ygg.h"

#define MAX_CLIENTS 64

static volatile sig_atomic_t running = 1;
static void on_signal(int sig) { (void)sig; running = 0; }

static void on_log(void *userdata, int level, const char *message) {
    (void)userdata;
    if (level <= YGG_LOG_INFO) fprintf(stderr, "[ygg] %s\n", message);
}

static char *read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)n + 1);
    if (buf && fread(buf, 1, (size_t)n, f) == (size_t)n) buf[n] = 0;
    fclose(f);
    return buf;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s CONFIG.toml PORT\n", argv[0]);
        return 2;
    }
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    ygg_set_logger(on_log, NULL, "info");

    char *config = read_file(argv[1]);
    ygg_node *node = ygg_node_start(config, 0);
    free(config);
    if (!node) {
        fprintf(stderr, "start failed: %s\n", ygg_last_error_message());
        return 1;
    }

    char addr[64], key[80];
    ygg_node_address(node, addr, sizeof addr);
    ygg_node_public_key(node, key, sizeof key);
    int port = atoi(argv[2]);
    ygg_socket listener = ygg_tcp_listen(node, (uint16_t)port);
    if (listener == YGG_INVALID_SOCKET) {
        fprintf(stderr, "listen failed: %s\n", ygg_last_error_message());
        return 1;
    }
    printf("echo server on [%s]:%d  (%s.pk.ygg)\n", addr, port, key);
    fflush(stdout);

    struct pollfd fds[1 + MAX_CLIENTS];
    int nclients = 0;
    fds[0].fd = listener;
    fds[0].events = POLLIN;

    while (running) {
        int r = poll(fds, 1 + nclients, 500);
        if (r < 0 && errno != EINTR) break;
        if (r <= 0) continue;

        if (fds[0].revents & POLLIN) {
            char peer[80];
            ygg_socket c;
            while ((c = ygg_tcp_accept(node, listener, peer, sizeof peer, 0)) != YGG_INVALID_SOCKET) {
                if (nclients == MAX_CLIENTS) { close(c); continue; }
                printf("accepted %s\n", peer);
                fflush(stdout);
                fds[1 + nclients].fd = c;
                fds[1 + nclients].events = POLLIN;
                fds[1 + nclients].revents = 0;
                nclients++;
            }
        }
        for (int i = 1; i <= nclients; i++) {
            if (!(fds[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            char buf[16384];
            ssize_t n = read(fds[i].fd, buf, sizeof buf);
            if (n > 0 && write(fds[i].fd, buf, (size_t)n) == n) continue;
            close(fds[i].fd);              /* EOF or error: drop client */
            fds[i] = fds[nclients--];
            i--;
        }
    }

    for (int i = 1; i <= nclients; i++) close(fds[i].fd);
    ygg_tcp_listener_close(node, listener);
    ygg_node_stop(node);
    printf("bye\n");
    return 0;
}
