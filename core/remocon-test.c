/*
 * Copyright (c) 2012 Toshihiro Kobayashi <kobacha@mwa.biglobe.ne.jp>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <libgen.h>
#include <errno.h>
#include <termios.h>
#include "PC-OP-RS1.h"

#define DEBUG_HEAD_REMOCON_TEST		"[remocon-test] "
#ifndef DEBUG_LEVEL_REMOCON_TEST
#define DEBUG_LEVEL_REMOCON_TEST	0
#endif
#include "debug.h"

#define ARRAY_SIZE(a)		(sizeof(a) / sizeof(a[0]))

#define BAUDRATE		B115200

static struct remocon_data {
	char *tag;
	unsigned char data[PCOPRS1_DATA_LEN];
} remocon_data[] = {
	{
		.tag = "example",
		.data = {
			0xff, 0xff, 0xff, 0xff, 0x0f, 0x00, 0x00, 0x00,
			0x80, 0xff, 0x00, 0xff, 0x01, 0xfc, 0x07, 0x00,
			0x00, 0xe0, 0x3f, 0x00, 0x00, 0x00, 0xff, 0x00,
			0xfe, 0x03, 0xfc, 0x07, 0xf0, 0x1f, 0xe0, 0x3f,
			0x00, 0x00, 0x00, 0xff, 0x01, 0x00, 0x00, 0xf8,
			0x0f, 0xf0, 0x1f, 0xc0, 0x7f, 0x80, 0xff, 0x00,
			0xfe, 0x01, 0xfc, 0x07, 0xf0, 0x0f, 0xe0, 0x3f,
			0xc0, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x80, 0x7f, 0x00, 0x00, 0x00, 0xfe,
			0x03, 0x00, 0x00, 0xf0, 0x1f, 0xc0, 0x7f, 0x80,
			0xff, 0x00, 0x00, 0x00, 0xfc, 0x07, 0x00, 0x00,
			0xe0, 0x3f, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00,
			0x00, 0xf8, 0x07, 0xf0, 0x1f, 0xe0, 0x3f, 0x00,
			0x00, 0x00, 0xff, 0x01, 0x00, 0x00, 0xf8, 0x0f,
			0x00, 0x00, 0xc0, 0x7f, 0x00, 0x00, 0x00, 0xfe,
			0x03, 0x00, 0x00, 0xf0, 0x0f, 0x00, 0x00, 0xc0,
			0x7f, 0x00, 0x00, 0x00, 0xfe, 0x03, 0x00, 0x00,
			0xf0, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0xff, 0x00,
			0x00, 0x00, 0x00, 0xf8, 0x07, 0xf0, 0x1f, 0xe0,
			0x3f, 0x00, 0x00, 0x00, 0xff, 0x01, 0x00, 0x00,
			0xf8, 0x0f, 0xe0, 0x1f, 0xc0, 0x7f, 0x80, 0xff,
			0x00, 0xfe, 0x03, 0x00, 0x00, 0xf0, 0x1f, 0x00,
			0x00, 0x80, 0x7f, 0x00, 0xff, 0x01, 0xfe, 0x03,
			0xf8, 0x0f, 0xf0, 0x1f, 0xc0, 0x3f, 0x80, 0xff,
			0x00, 0xfe, 0x01, 0xfc, 0x07, 0x00, 0x00, 0x00
		},
	},
};

static struct app {
	char *devname;
	char *cmd;
	int ch;
	int receive_mode;
} app;

#if (DEBUG_LEVEL_REMOCON_TEST >= 1)
static char *hexdump(char *s, unsigned char *data, size_t sz) {
	int i;
	for (i = 0; i < sz; i++)
		sprintf(&s[i * 2], "%02x", data[i]);
	return s;
}
#endif

static int remocon_send(int fd, unsigned char *data, size_t sz)
{
	unsigned char *wp;
	int rest, wcnt;

	for (wp = data, rest = sz; rest; wp += wcnt, rest -= wcnt) {
		wcnt = write(fd, wp, rest);
		if (wcnt < 0) {
			app_error("write error: %s\n", strerror(errno));
			return wcnt;
		}
	}
	return sz;
}

static int remocon_read(int fd, unsigned char *data, size_t sz,
			unsigned long timeout)
{
	unsigned char *rp;
	int rest, rcnt;

	if (timeout == 0)
		timeout = 10;

	/* FIXME: timeout */
	for (rp = data, rest = sz; rest; rp += rcnt, rest -= rcnt) {
		rcnt = read(fd, rp, rest);
		if (rcnt < 0) {
			app_error("read error: %s\n", strerror(errno));
			return rcnt;
		}
	}

#if (DEBUG_LEVEL_REMOCON_TEST >= 1)
{
	char s[sz * 2 + 1];
	app_debug(REMOCON_TEST, 1, "read: %s\n", hexdump(s, data, sz));
}
#endif

	return sz;
}

static int remocon_expect(int fd, unsigned char expect)
{
	unsigned char c;

	remocon_read(fd, &c, 1, -1);
	if (c != expect) {
		app_error("expect 0x%02x, but got 0x%02x\n", expect, c);
		return -1;
	}
	return 0;
}

static int transmit(int fd, int ch, unsigned char *data, size_t sz)
{
	unsigned char c;

	c = PCOPRS1_CMD_TRANSMIT;
	if (remocon_send(fd, &c, 1) < 0)
		return -1;
	if (remocon_expect(fd, PCOPRS1_CMD_OK) < 0)
		return -1;
	c = PCOPRS1_CMD_CHANNEL(ch);
	if (remocon_send(fd, &c, 1) < 0)
		return -1;
	if (remocon_expect(fd, PCOPRS1_CMD_OK) < 0)
		return -1;
	if (remocon_send(fd, data, sz) < 0)
		return -1;
	if (remocon_expect(fd, PCOPRS1_CMD_DATA_COMPLETION) < 0)
		return -1;

	return 0;
}

static int receive(int fd, unsigned char *data, size_t sz)
{
	unsigned char c;

	if (sz < PCOPRS1_DATA_LEN) {
		app_error("not enough receive data buffer size\n");
		return -1;
	}

	c = PCOPRS1_CMD_RECEIVE;
	if (remocon_send(fd, &c, 1) < 0)
		return -1;
	if (remocon_expect(fd, PCOPRS1_CMD_OK) < 0)
		return -1;
	if (remocon_expect(fd, PCOPRS1_CMD_RECEIVE_DATA) < 0)
		return -1;
	if ((sz = remocon_read(fd, data, PCOPRS1_DATA_LEN, -1)) < 0)
		return -1;
	if (remocon_expect(fd, PCOPRS1_CMD_DATA_COMPLETION) < 0)
		return -1;

	return sz;
}

static void usage(const char *cmd_path)
{
	char *cpy_path = strdup(cmd_path);

	fprintf(stderr,
		"usage: %s\n"
		"        -s <serial device> (default is /dev/ttyUSB)\n"
		"        [-ch <channel>]\n"
		"        [-r]\n"
		"        <command tag>\n"
		"        [-h]\n",
		basename(cpy_path));
	free(cpy_path);
}

/*
 * parse command line options
 * return value:
 *   0: success
 *  -1: error
 *   1: show usage and exit
 */
static int parse_arg(int argc, char *argv[])
{
	int str_id = 0;
	int i;

	/* init */
	app.devname = "/dev/ttyUSB0";
	app.ch = 1;
	app.receive_mode = 0;
	app.cmd = NULL;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-s")) {
			if (++i == argc)
				return -1;
			app.devname = argv[i];
		} else if (!strcmp(argv[i], "-ch")) {
			if (++i == argc)
				return -1;
			app.ch = atoi(argv[i]);
		} else if (!strcmp(argv[i], "-r")) {
			app.receive_mode = 1;
		} else if (!strcmp(argv[i], "-h")) {
			return 1;
		} else {
			/* string options */
			switch (str_id) {
			case 0:
				app.cmd = argv[i];
				break;
			default:
				return -1;
			}
			str_id++;
		}
	}

	/* sanity check */
	if (app.devname == NULL)
		return -1;
	if ((!app.receive_mode) && (app.cmd == NULL))
		return 1;

	return 0;
}

int main(int argc, char **argv)
{
	int fd;
	struct termios newtio, oldtio;
	unsigned char c;
	unsigned char rbuf[PCOPRS1_DATA_LEN];
	int i;
	int r;

	r = parse_arg(argc, argv);
	if (r < 0) {
		usage(argv[0]);
		return 1;
	} else if (r == 1) {
		usage(argv[0]);
		return 0;
	}

	fd = open(app.devname, O_RDWR | O_NOCTTY);
	if (fd < 0) {
		app_error("device open failed: %s (%s)\n",
			  app.devname, strerror(errno));
		return 1;
	}

	tcgetattr(fd,&oldtio);

	newtio.c_cflag = BAUDRATE | CS8 | CLOCAL | CREAD;
	newtio.c_iflag = 0;
	newtio.c_oflag = 0;
	newtio.c_lflag = 0;
	newtio.c_cc[VMIN] = 1;
	newtio.c_cc[VTIME] = 0;

	tcflush(fd, TCIFLUSH);
	tcsetattr(fd, TCSANOW, &newtio);

	/* main */
	c = PCOPRS1_CMD_LED;
	remocon_send(fd, &c, 1);
	remocon_expect(fd, PCOPRS1_CMD_LED_OK);
	if (app.receive_mode) {
		r = receive(fd, rbuf, PCOPRS1_DATA_LEN);
		for (i = 0; i < r; i++) {
			printf("%02x", rbuf[i]);
		}
		printf("\n");
	} else {
		for (i = 0; i < ARRAY_SIZE(remocon_data); i++) {
			if (!strcmp(app.cmd, remocon_data[i].tag)) {
				app_debug(REMOCON_TEST, 1, "Tx: %s\n", app.cmd);
				transmit(fd, app.ch, remocon_data[i].data,
					 PCOPRS1_DATA_LEN);
				goto out;
			}
		}
		app_error("Unknown command: %s\n", app.cmd);
	}

out:
	tcsetattr(fd, TCSANOW, &oldtio);
	close(fd);

	return 0;
}
