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
#include <sys/stat.h>
#include "remocon_format.h"
#include "file_util.h"
#include "string_util.h"
#include "PC-OP-RS1.h"

#define DEBUG_HEAD_LEMON_CORN	"[lemon_corn] "
#ifndef DEBUG_LEVEL_LEMON_CORN
#define DEBUG_LEVEL_LEMON_CORN	0
#endif
#include "debug.h"

#define DEFAULT_TTY_DEV		"/dev/ttyUSB0"
#define ARDUINO_TTY_DEV		"/dev/ttyACM0"

#define TAG_LEN			32
#define CMD_MAX			50
#define BAUDRATE		B115200
#define DATA_FN			"lemon_corn.data"

#define APP_MODE_TRANSMIT	0
#define APP_MODE_RECEIVE	1
#define APP_MODE_LIST		2
#define APP_MODE_DELETE		3
#define APP_MODE_FORGE		4

#define LIST_MODE_NONE		0
#define LIST_MODE_HEX		1
#define LIST_MODE_WAVE		2
#define LIST_MODE_FORMATTED	3

struct remocon_data {
	char tag[TAG_LEN];
	unsigned char data[PCOPRS1_DATA_LEN];
};

static struct app {
	char *devname;
	char *cmd[CMD_MAX + 1];
	int cmd_cnt;
	int ch;
	unsigned long mode;
	unsigned long list_mode;
	char *data_dir, *data_fn;
	struct remocon_data *data;
	char *forge_fmt;
	int data_cnt;
	int trunc_len;
	int dont_save;
	int is_arduino;
	int is_virtual;
} app;

static int serial_open(const char *devname, struct termios *tio_old)
{
	struct termios tio_new;
	int fd;

	fd = open(devname, O_RDWR | O_NOCTTY);
	if (fd < 0) {
		app_error("device open failed: %s (%s)\n",
			  devname, strerror(errno));
		return -1;
	}

	tcgetattr(fd, tio_old);

	tio_new.c_cflag = BAUDRATE | CS8 | CLOCAL | CREAD;
	tio_new.c_iflag = 0;
	tio_new.c_oflag = 0;
	tio_new.c_lflag = 0;
	tio_new.c_cc[VMIN] = 1;
	tio_new.c_cc[VTIME] = 0;

	tcflush(fd, TCIFLUSH);
	tcsetattr(fd, TCSANOW, &tio_new);

	return fd;
}

static int serial_close(int fd, const struct termios *tio_old)
{
	tcsetattr(fd, TCSANOW, tio_old);
	return close(fd);
}

static char *hexdump(char *dst, const unsigned char *data, size_t sz)
{
	int i;

	for (i = 0; i < sz; i++)
		sprintf(&dst[i * 2], "%02x", data[i]);

	return dst;
}

static char *wavedump(char *dst, const unsigned char *data, size_t sz)
{
	int i, j = 0;
	unsigned char bit;

	for (i = 0; i < sz; i++)
		for (bit = 0x01; bit != 0x00; j++, bit <<= 1)
			dst[j] = (data[i] & bit) ? '-' : '.';

	return dst;
}

static int find_cmd_idx(const char *tag, const struct remocon_data *data,
			int data_cnt)
{
	int i;

	for (i = 0; i < data_cnt; i++)
		if (!strcmp(tag, data[i].tag))
			return i;
	/* did not match */
	return -1;
}

static int remocon_send(int fd, const unsigned char *data, size_t sz)
{
	const unsigned char *rp;
	int rest, wcnt;

	if (app.is_virtual)
		return sz;

	for (rp = data, rest = sz; rest; rp += wcnt, rest -= wcnt) {
		wcnt = write(fd, rp, rest);
		if (wcnt < 0) {
			app_error("write error: %s\n", strerror(errno));
			return wcnt;
		}
	}

#if (DEBUG_LEVEL_LEMON_CORN >= 1)
{
	char s[sz * 2 + 1];
	app_debug(LEMON_CORN, 1, "sent: %s\n", hexdump(s, data, sz));
}
#endif

	return sz;
}

static int remocon_read(int fd, unsigned char *data, size_t sz)
{
	unsigned char *rp;
	int rest, rcnt;

	app_debug(LEMON_CORN, 1, "waiting for data...\n");
	for (rp = data, rest = sz; rest; rp += rcnt, rest -= rcnt) {
		rcnt = read(fd, rp, rest);
		if (rcnt < 0) {
			app_error("read error: %s\n", strerror(errno));
			return rcnt;
		}
	}

#if (DEBUG_LEVEL_LEMON_CORN >= 1)
{
	char s[sz * 2 + 1];
	app_debug(LEMON_CORN, 1, "read: %s\n", hexdump(s, data, sz));
}
#endif

	return sz;
}

static int remocon_expect(int fd, unsigned char expect)
{
	unsigned char c;

	if (app.is_virtual)
		return 0;

	remocon_read(fd, &c, 1);
	if (c != expect) {
		app_error("expect '%c'(0x%02x), but got '%c'(0x%02x)\n",
			  expect, expect, c, c);
		return -1;
	}
	return 0;
}

static int remocon_expect2(int fd, unsigned char *expect_ary, int len)
{
	unsigned char c;
	char buf[256];
	int i;

	if (app.is_virtual)
		return 0;

	remocon_read(fd, &c, 1);
	for (i = 0; i < len; i++)
		if (c == expect_ary[i])
			return 0;

	for (i = 0; i < len; i++)
		strcatf(buf, " '%c'(0x%02x)", expect_ary[i], expect_ary[i]);
	app_error("expect %s\n", buf);
	app_error("but got '%c'(0x%02x)\n", c, c);
	return -1;
}

static int transmit(int fd, int ch, const unsigned char *data, size_t sz)
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
	if ((sz = remocon_read(fd, data, PCOPRS1_DATA_LEN)) < 0)
		return -1;
	if (remocon_expect(fd, PCOPRS1_CMD_DATA_COMPLETION) < 0)
		return -1;

	return sz;
}

static int transmit_cmd(int fd, const char *cmd)
{
	if (!strncmp(cmd, "_sleep", 6)) {
		int time = atoi(&cmd[6]);
		printf("sleeping %d sec(s)...\n", time);
		sleep(time);
	} else {
		int d_idx = find_cmd_idx(cmd, app.data, app.data_cnt);
		if (d_idx < 0) {
			app_error("Unknown command: %s\n", cmd);
			return -1;
		}
		printf("transmitting %s ...\n", cmd);
		transmit(fd, app.ch, app.data[d_idx].data, PCOPRS1_DATA_LEN);
		usleep(500000);
	}

	return 0;
}

static void transmit_cmdline(int fd)
{
	int i;

	for (i = 0; i < app.cmd_cnt; i++)
		transmit_cmd(fd, app.cmd[i]);
}

static char *fgets_prompt(char *s, int size, FILE *stream)
{
	printf("> ");
	return fgets(s, size, stream);
}

static void transmit_interactive(int fd)
{
	char s[64];

	while (fgets_prompt(s, sizeof(s), stdin)) {
		strchomp(s);
		if (!strcmp(s, "quit"))
			break;
		if (transmit_cmd(fd, s) == 0)
			printf("OK\n");
	}
}

static void transmit_main(int fd)
{
	unsigned char c;
	unsigned char ex_ary[2];

	if (app.is_arduino) {	/* need serial setup time */
		printf("wait for arduino serial setup...\n");
		sleep(2);
	}
	c = PCOPRS1_CMD_LED;
	remocon_send(fd, &c, 1);
	ex_ary[0] = PCOPRS1_CMD_LED_OK;
	ex_ary[1] = PCOPRS1_CMD_OK;
	remocon_expect2(fd, ex_ary, sizeof(ex_ary));

	if (app.cmd_cnt > 0)
		transmit_cmdline(fd);
	else
		transmit_interactive(fd);
}

static void save_cmd(const struct remocon_data *new_data, int cnt)
{
	struct stat st;
	int fd;

	if (stat(app.data_dir, &st) < 0) {
		if (mkdir(app.data_dir, 0755) < 0) {
			app_error("mkdir failed: %s (%s)\n",
				  app.data_fn, strerror(errno));
			return;
		}
	}
	if ((fd = open(app.data_fn, O_WRONLY | O_CREAT, 0644)) < 0) {
		app_error("data file open failed: %s (%s)\n",
			  app.data_fn, strerror(errno));
		return;
	}
	write(fd, app.data, sizeof(struct remocon_data) * app.data_cnt);
	write(fd, new_data, sizeof(struct remocon_data) * cnt);
	close(fd);
	printf("written new data to %s.\n", app.data_fn);
}

static void receive_main(int fd)
{
	struct remocon_data *new_data;
	int new_data_cnt;
	unsigned char c;
	unsigned char ex_ary[2];
	int r;
	int i;

	if (app.is_arduino) {	/* need serial setup time */
		printf("wait for arduino serial setup...\n");
		sleep(2);
	}
	c = PCOPRS1_CMD_LED;
	remocon_send(fd, &c, 1);
	ex_ary[0] = PCOPRS1_CMD_LED_OK;
	ex_ary[1] = PCOPRS1_CMD_OK;
	remocon_expect2(fd, ex_ary, sizeof(ex_ary));

	if (app.cmd_cnt == 0) {
		unsigned char rbuf[PCOPRS1_DATA_LEN];
		char s[PCOPRS1_DATA_LEN * 2 + 1];
		r = receive(fd, rbuf, PCOPRS1_DATA_LEN);
		if (r < 0)
			return;
		if (app.trunc_len < PCOPRS1_DATA_LEN)
			memset(rbuf + app.trunc_len, 0,
			       PCOPRS1_DATA_LEN - app.trunc_len);
		hexdump(s, rbuf, r);
		puts(s);
		return;
	}

	new_data = malloc(sizeof(struct remocon_data) * app.cmd_cnt);
	if (new_data == NULL) {
		app_error("memory allocation failed.\n");
		return;
	}

	new_data_cnt = 0;
	for (i = 0; i < app.cmd_cnt; i++) {
		struct remocon_data *dst;
		int d_idx;
		char fmt_tag_s[32];
		char fmt_data_s[PCOPRS1_DATA_LEN * 8 + 1];

		printf("waiting ir data for %s ...\n", app.cmd[i]);

		d_idx = find_cmd_idx(app.cmd[i], app.data, app.data_cnt);
		if (d_idx >= 0) {
			dst = &app.data[d_idx];
		} else {
			dst = &new_data[new_data_cnt++];
			memset(dst->tag, 0, TAG_LEN);
			strcpy(dst->tag, app.cmd[i]);
		}
		r = receive(fd, dst->data, PCOPRS1_DATA_LEN);
		if (r < 0)
			return;
		if (app.trunc_len < PCOPRS1_DATA_LEN)
			memset(dst->data + app.trunc_len, 0,
			       PCOPRS1_DATA_LEN - app.trunc_len);
		printf("received.\n");

		/* print received data format */
		if (remocon_format_analyze(fmt_tag_s, fmt_data_s,
					   dst->data, PCOPRS1_DATA_LEN) == 0) {
			printf("format = %s, data = %s\n",
			       fmt_tag_s, fmt_data_s);
		} else {
			hexdump(fmt_data_s, dst->data, PCOPRS1_DATA_LEN);
			printf("unknown format!\n%s\n", fmt_data_s);
		}
	}

	/* data file write */
	if (!app.dont_save)
		save_cmd(new_data, new_data_cnt);

	free(new_data);
}

static void list_main(void)
{
	char fmt_tag[32];
	char s[PCOPRS1_DATA_LEN * 8 + 1];
	int d_idx;
	int i;

	for (d_idx = 0; d_idx < app.data_cnt; d_idx++) {
		if (app.cmd_cnt) {
			int hit = 0;
			for (i = 0; i < app.cmd_cnt; i++) {
				if (!strcmp(app.cmd[i], app.data[d_idx].tag))
					hit = 1;
			}
			if (!hit)
				continue;
		}
		switch (app.list_mode) {
		case LIST_MODE_NONE:
			printf("%s\n", app.data[d_idx].tag);
			break;
		case LIST_MODE_HEX:
			hexdump(s, app.data[d_idx].data, PCOPRS1_DATA_LEN);
			printf("%s:\n%s\n", app.data[d_idx].tag, s);
			break;
		case LIST_MODE_WAVE:
			wavedump(s, app.data[d_idx].data, PCOPRS1_DATA_LEN);
			printf("%s:\n%s\n", app.data[d_idx].tag, s);
			break;
		case LIST_MODE_FORMATTED:
			printf("%s:\n", app.data[d_idx].tag);
			if (remocon_format_analyze(fmt_tag, s,
						   app.data[d_idx].data,
						   PCOPRS1_DATA_LEN) == 0) {
				printf("format = %s, data = %s\n", fmt_tag, s);
			} else {
				hexdump(s, app.data[d_idx].data,
					PCOPRS1_DATA_LEN);
				printf("unknown format!\n%s\n", s);
			}
			break;
		}
	}
}

static void delete_main(void)
{
	char flag[app.data_cnt];
	int data_fd;
	int i, d_idx;

	memset(flag, 0, app.data_cnt);
	for (i = 0; i < app.cmd_cnt; i++) {
		d_idx = find_cmd_idx(app.cmd[i], app.data, app.data_cnt);
		if (d_idx < 0) {
			app_error("Unknown command: %s\n", app.cmd[i]);
			continue;
		}
		printf("deleting %s\n", app.cmd[i]);
		flag[d_idx] = 1;
	}

	/* data file write */
	if ((data_fd = open(app.data_fn, O_WRONLY | O_TRUNC)) < 0) {
		app_error("data file open failed: %s (%s)\n",
			  app.data_fn, strerror(errno));
		return;
	}
	for (d_idx = 0; d_idx < app.data_cnt; d_idx++) {
		if (!flag[d_idx])
			write(data_fd, &app.data[d_idx],
			      sizeof(struct remocon_data));
	}
	close(data_fd);
	printf("written new data.\n");
}

static void forge_main(void)
{
	struct remocon_data new_data;
	struct remocon_data *dst;
	int d_idx;
	char *p0, *p1, *p2;

	p0 = app.forge_fmt;
	for (p1 = p0; *p1 != ','; p1++)
		if (!*p1)
			goto format_err;
	p1++;
	for (p2 = p1; *p2 != ','; p2++)
		if (!*p2)
			goto format_err;
	p2++;

	d_idx = find_cmd_idx(app.cmd[0], app.data, app.data_cnt);
	if (d_idx >= 0) {
		dst = &app.data[d_idx];
	} else {
		dst = &new_data;
		memset(dst->tag, 0, TAG_LEN);
		strcpy(dst->tag, app.cmd[0]);
	}

	if (!strncmp(p0, "AEHA,", p1 - p0)) {
		unsigned long custom, cmd;
		custom = strtol(p1, NULL, 16);
		cmd    = strtol(p2, NULL, 16);
		remocon_format_forge_aeha(dst->data, PCOPRS1_DATA_LEN,
					  custom, cmd);
	} else if (!strncmp(p0, "NEC,", p1 - p0)) {
		unsigned long custom, cmd;
		custom = strtol(p1, NULL, 16);
		cmd    = strtol(p2, NULL, 16);
		remocon_format_forge_nec(dst->data, PCOPRS1_DATA_LEN,
					 (unsigned short)custom,
					 (unsigned char)cmd);
	} else if (!strncmp(p0, "SONY,", p1 - p0)) {
		unsigned long prod, cmd;
		prod = strtol(p1, NULL, 16);
		cmd  = strtol(p2, NULL, 16);
		remocon_format_forge_sony(dst->data, PCOPRS1_DATA_LEN,
					  prod, cmd);
	} else {
		goto format_err;
	}

	/* data file write */
	if (dst == &new_data)
		save_cmd(&new_data, 1);	/* append new_data */
	else
		save_cmd(NULL, 0);	/* save modified data */


	return;

format_err:
	printf("invalid forge format\n");
}

static void usage(const char *cmd_path)
{
	char *cpy_path = strdup(cmd_path);

	fprintf(stderr,
"usage: %s\n"
"        [-r <command(s)>]    (receive)\n"
"        [-cl]                (command list)\n"
"        [-l]                 (list with hex)\n"
"        [-p]                 (list with waveform)\n"
"        [-f]                 (list with format analysis)\n"
"        [-d <command(s)>]    (delete)\n"
"        [command(s)]         (send)\n"
"        [-ns]                (do not save with -r)\n"
"        [-s <serial device>] (default is " DEFAULT_TTY_DEV ")\n"
"        [-ch <channel>]      (default is 1)\n"
"        [-dd <data_dir>]     (searches default locations if not specified)\n"
"        [-trunc <trunc_len>] (truncate received signal)\n"
"        [-forge <format> <command>]  (forge command with known format)\n"
"                 format: AEHA,<custom_hex>,<cmd_hex>\n"
"                         NEC,<custom_hex>,<cmd_hex>\n"
"                         SONY,<prod_hex>,<cmd_hex>\n"
"        [-arduino]           (arduino mode)\n"
"        [-virtual]           (virtual mode)\n"
"        [-h]                 (help)\n",
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
	app.data_dir = NULL;
	app.devname = NULL;
	app.ch = 1;
	app.mode = APP_MODE_TRANSMIT;
	memset(app.cmd, 0, sizeof(app.cmd));
	app.cmd_cnt = 0;
	app.trunc_len = PCOPRS1_DATA_LEN;
	app.dont_save = 0;
	app.is_arduino = 0;
	app.is_virtual = 0;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-s")) {
			if (++i == argc)
				return -1;
			app.devname = argv[i];
		} else if (!strcmp(argv[i], "-r")) {
			app.mode = APP_MODE_RECEIVE;
		} else if (!strcmp(argv[i], "-cl")) {
			app.mode = APP_MODE_LIST;
			app.list_mode = LIST_MODE_NONE;
		} else if (!strcmp(argv[i], "-l")) {
			app.mode = APP_MODE_LIST;
			app.list_mode = LIST_MODE_HEX;
		} else if (!strcmp(argv[i], "-p")) {
			app.mode = APP_MODE_LIST;
			app.list_mode = LIST_MODE_WAVE;
		} else if (!strcmp(argv[i], "-f")) {
			app.mode = APP_MODE_LIST;
			app.list_mode = LIST_MODE_FORMATTED;
		} else if (!strcmp(argv[i], "-d")) {
			app.mode = APP_MODE_DELETE;
		} else if (!strcmp(argv[i], "-ns")) {
			app.dont_save = 1;
		} else if (!strcmp(argv[i], "-ch")) {
			if (++i == argc)
				return -1;
			app.ch = atoi(argv[i]);
		} else if (!strcmp(argv[i], "-dd")) {
			if (++i == argc)
				return -1;
			app.data_dir = argv[i];
		} else if (!strcmp(argv[i], "-trunc")) {
			if (++i == argc)
				return -1;
			app.trunc_len = atoi(argv[i]);
		} else if (!strcmp(argv[i], "-forge")) {
			app.mode = APP_MODE_FORGE;
			if (++i == argc)
				return -1;
			app.forge_fmt = argv[i];
		} else if (!strcmp(argv[i], "-arduino")) {
			app.is_arduino = 1;
		} else if (!strcmp(argv[i], "-virtual")) {
			app.is_virtual = 1;
		} else if (!strcmp(argv[i], "-h")) {
			return 1;
		} else {
			/* string options */
			switch (str_id) {
			case 0 ... CMD_MAX:
				app.cmd[app.cmd_cnt++] = argv[i];
				break;
			default:
				return -1;
			}
			str_id++;
		}
	}

	/* sanity check */
	if ((app.mode == APP_MODE_DELETE) && (app.cmd_cnt == 0))
		return -1;
	if ((app.mode == APP_MODE_FORGE) && (app.cmd_cnt != 1))
		return -1;
	if (app.dont_save) {
		if (app.mode != APP_MODE_RECEIVE) {
			app_error("unrecognized -ns\n");
			return -1;
		}
		if (app.cmd_cnt != 0) {
			app_error("commmand specified with -ns\n");
			return -1;
		}
	}
	if ((app.ch < 1) || (app.ch > 4)) {
		app_error("bad channel (%d)\n", app.ch);
		return -1;
	}

	/* defaults */
	if (app.devname == NULL) {
		app.devname =
			app.is_arduino ? ARDUINO_TTY_DEV : DEFAULT_TTY_DEV;
	}
	if (app.data_dir == NULL) {
		char *home_dir = getenv("HOME");
		if (home_dir) {
			char *subdir = ".lemon_corn";
			app.data_dir =
				malloc(strlen(home_dir) + strlen(subdir) + 2);
			if (app.data_dir == NULL) {
				app_error("%s(): memory allocation failed.\n",
					  __func__);
				return -1;
			}
			sprintf(app.data_dir, "%s/%s", home_dir, subdir);
		} else
			app.data_dir = "/var/lemon_corn";
	}

	app.data_fn = malloc(strlen(app.data_dir) + sizeof(DATA_FN) + 2);
	if (app.data_fn == NULL) {
		app_error("%s(): memory allocation failed.\n", __func__);
		return -1;
	}
	sprintf(app.data_fn, "%s/%s", app.data_dir, DATA_FN);

	return 0;
}

int main(int argc, char **argv)
{
	int fd;
	struct termios tio_old;
	struct stat st;
	ssize_t data_sz;
	int r;

	r = parse_arg(argc, argv);
	if (r < 0) {
		usage(argv[0]);
		return 1;
	} else if (r == 1) {
		usage(argv[0]);
		return 0;
	}

	/* device file setup */
	if (app.is_virtual ||
	    (app.mode == APP_MODE_LIST) ||
	    (app.mode == APP_MODE_DELETE) ||
	    (app.mode == APP_MODE_FORGE))
		fd = 0;
	else {
		if ((fd = serial_open(app.devname, &tio_old)) < 0)
			return 1;
	}

	/* data */
	if ((app.mode != APP_MODE_RECEIVE) && (stat(app.data_fn, &st) < 0)) {
		app_error("data file not found: %s\n", app.data_fn);
		goto out;
	}
	if ((data_sz = try_get_file_image((void **)&app.data, app.data_fn)) < 0)
		data_sz = 0;
	app.data_cnt = data_sz / sizeof(struct remocon_data);

	/* main */
	switch (app.mode) {
	case APP_MODE_TRANSMIT:
		transmit_main(fd);
		break;
	case APP_MODE_RECEIVE:
		receive_main(fd);
		break;
	case APP_MODE_LIST:
		list_main();
		break;
	case APP_MODE_DELETE:
		delete_main();
		break;
	case APP_MODE_FORGE:
		forge_main();
		break;
	}

out:
	if (fd)
		serial_close(fd, &tio_old);

	return 0;
}
