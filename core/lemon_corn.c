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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "lemon_corn_data.h"
#include "file_util.h"
#include "string_util.h"
#include "PC-OP-RS1.h"
#include "lemon_squash.h"
#include "format/remocon_format.h"

#define DEBUG_HEAD_LEMON_CORN	"[lemon_corn] "
#ifndef DEBUG_LEVEL_LEMON_CORN
#define DEBUG_LEVEL_LEMON_CORN	0
#endif
#include "debug.h"

#define DEFAULT_TTY_DEV		"/dev/ttyUSB0"
#define ARDUINO_TTY_DEV		"/dev/ttyACM0"
#define PORT_STR		"26851"

#define CMD_MAX			50
#define BAUDRATE		B115200
#define DATA_FN			"lemon_corn.data"

#define APP_MODE_TRANSMIT	0
#define APP_MODE_RECEIVE	1
#define APP_MODE_LIST		2
#define APP_MODE_DELETE		3
#define APP_MODE_FORGE		4
#define APP_MODE_FORGE_TRANSMIT	5

#define LIST_MODE_NONE		0
#define LIST_MODE_HEX		1
#define LIST_MODE_WAVE		2
#define LIST_MODE_FORMATTED	3

static struct app {
	const char *devname;
	char *cmd[CMD_MAX + 1];
	int cmd_cnt;
	int ch;
	unsigned long mode;
	unsigned long list_mode;
	char *data_dir, *data_fn;
	struct lcdata data;
	char *forge_fmt;
	size_t data_len, trunc_len;
	int dont_save;
	const char *proxy_host;
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

static int proxy_open(const char *host_name, const char *port_str)
{
	int fd;
	struct addrinfo ai_hint, *aip;
	int r;

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		app_error("socket() failed\n");
		return -1;
	}

	memset(&ai_hint, 0, sizeof(struct addrinfo));
	ai_hint.ai_family = AF_INET;
	ai_hint.ai_socktype = SOCK_STREAM;
	ai_hint.ai_flags = 0;
	ai_hint.ai_protocol = 0;

	if ((r = getaddrinfo(host_name, port_str, &ai_hint, &aip)) < 0) {
		app_error("getaddrinfo: %s\n", gai_strerror(r));
		close(fd);
		return -1;
	}

	if (connect(fd, aip->ai_addr, aip->ai_addrlen) < 0) {
		app_error("connect() failed\n");
		close(fd);
		freeaddrinfo(aip);
		return -1;
	}

	freeaddrinfo(aip);

	return fd;
}

static int proxy_close(int fd)
{
	return close(fd);
}

static char *hexdump(char *dst, const unsigned char *data, size_t sz)
{
	unsigned int i;

	for (i = 0; i < sz; i++)
		sprintf(&dst[i * 2], "%02x", data[i]);
	dst[sz * 2] = '\0';

	return dst;
}

static char *wavedump(char *dst, const unsigned char *data, size_t sz)
{
	unsigned int i, j = 0;
	unsigned char bit;

	for (i = 0; i < sz; i++)
		for (bit = 0x01; bit != 0x00; j++, bit <<= 1)
			dst[j] = (data[i] & bit) ? '-' : '.';
	dst[sz * 8] = '\0';

	return dst;
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

static void save_cmd_with_new(const struct lcdata *new_lcdata)
{
	struct stat st;

	if (stat(app.data_dir, &st) < 0) {
		if (mkdir(app.data_dir, 0755) < 0) {
			app_error("mkdir failed: %s (%s)\n",
				  app.data_fn, strerror(errno));
			return;
		}
	}
	lcdata_save(&app.data, app.data_fn);
	if (new_lcdata)
		lcdata_save_append(new_lcdata, app.data_fn);
	printf("written new data to %s.\n", app.data_fn);
}

#define save_cmd()	 save_cmd_with_new(NULL)

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

	if (sz == PCOPRS1_DATA_LEN) {
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
	} else {
		if (sz % LEMON_SQUASH_DATA_UNIT_LEN != 0) {
			app_error("invalid data len %d\n", sz);
			return -1;
		}
		c = LEMON_SQUASH_CMD_TRANSMIT2;
		if (remocon_send(fd, &c, 1) < 0)
			return -1;
		if (remocon_expect(fd, PCOPRS1_CMD_OK) < 0)
			return -1;
		c = sz / LEMON_SQUASH_DATA_UNIT_LEN;
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
	}

	return 0;
}

static int receive(int fd, unsigned char *data, size_t sz)
{
	unsigned char c;
	int read_len;

	if (sz == PCOPRS1_DATA_LEN) {
		c = PCOPRS1_CMD_RECEIVE;
		if (remocon_send(fd, &c, 1) < 0)
			return -1;
		if (remocon_expect(fd, PCOPRS1_CMD_OK) < 0)
			return -1;
		if (remocon_expect(fd, PCOPRS1_CMD_RECEIVE_DATA) < 0)
			return -1;
		if ((read_len = remocon_read(fd, data, PCOPRS1_DATA_LEN)) < 0)
			return -1;
		if (remocon_expect(fd, PCOPRS1_CMD_DATA_COMPLETION) < 0)
			return -1;
	} else {
		if (sz % LEMON_SQUASH_DATA_UNIT_LEN != 0) {
			app_error("invalid data len %d\n", sz);
			return -1;
		}
		c = LEMON_SQUASH_CMD_RECEIVE2;
		if (remocon_send(fd, &c, 1) < 0)
			return -1;
		if (remocon_expect(fd, PCOPRS1_CMD_OK) < 0)
			return -1;
		c = sz / LEMON_SQUASH_DATA_UNIT_LEN;
		if (remocon_send(fd, &c, 1) < 0)
			return -1;
		if (remocon_expect(fd, PCOPRS1_CMD_OK) < 0)
			return -1;
		if (remocon_expect(fd, PCOPRS1_CMD_RECEIVE_DATA) < 0)
			return -1;
		if ((read_len = remocon_read(fd, data, sz)) < 0)
			return -1;
		if (remocon_expect(fd, PCOPRS1_CMD_DATA_COMPLETION) < 0)
			return -1;
	}

	return read_len;
}

static int transmit_cmd(int fd, const char *cmd)
{
	if (!strncmp(cmd, "_sleep", 6)) {
		int time = atoi(&cmd[6]);
		printf("sleeping %d sec(s)...\n", time);
		sleep(time);
	} else {
		struct lcdata_ent ent;

		if (lcdata_get_cmd_by_tag(&app.data, cmd, &ent) < 0) {
			app_error("Unknown command: %s\n", cmd);
			return -1;
		}
		printf("transmitting %s ...\n", cmd);
		transmit(fd, app.ch, ent.data, ent.data_size);
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

static void delete_main(void)
{
	int i;

	for (i = 0; i < app.cmd_cnt; i++) {
		if (lcdata_delete_by_tag(&app.data, app.cmd[i]) < 0)
			app_error("Unknown command: %s\n", app.cmd[i]);
		else
			printf("deleting %s\n", app.cmd[i]);
	}
	save_cmd();
}

static void receive_main(int fd)
{
	struct lcdata new_lcdata;
	size_t ent_img_struct_size;
	unsigned char c;
	unsigned char ex_ary[2];
	unsigned char rbuf[app.data_len];
	char fmt_tag_s[32];
	char fmt_data_s[app.data_len * 2 + 1];
	void *p;
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
		// FIXME: merge with the below
		printf("waiting ir data for ...\n");
		r = receive(fd, rbuf, app.data_len);
		if (r < 0)
			return;
		if (app.trunc_len < app.data_len)
			memset(rbuf + app.trunc_len, 0,
			       app.data_len - app.trunc_len);

		/* print received data format */
		if (remocon_format_analyze(fmt_tag_s, fmt_data_s,
					   rbuf, app.data_len) == 0) {
			printf("format = %s, data = %s\n",
			       fmt_tag_s, fmt_data_s);
		} else {
			hexdump(fmt_data_s, rbuf, app.data_len);
			printf("unknown format!\n%s\n", fmt_data_s);
		}
		return;
	}

	ent_img_struct_size =
		(app.data_len == PCOPRS1_DATA_LEN) ?
			sizeof(struct lcdata_ent_img_fxd) :
			sizeof(struct lcdata_ent_img_var);
	new_lcdata.img_size =
		(ent_img_struct_size + app.data_len) * app.cmd_cnt;
	new_lcdata.ent_img = malloc(new_lcdata.img_size);
	if (new_lcdata.ent_img == NULL) {
		app_error("memory allocation failed.\n");
		return;
	}

	p = new_lcdata.ent_img;
	for (i = 0; i < app.cmd_cnt; i++) {
		char *tag;
		unsigned char *data;

		if (app.data_len == PCOPRS1_DATA_LEN) {
			struct lcdata_ent_img_fxd *fent =
				(struct lcdata_ent_img_fxd *)p;
			tag  = fent->tag;
			data = fent->data;
		} else {
			struct lcdata_ent_img_var *vent =
				(struct lcdata_ent_img_var *)p;
			lcdata_ent_img_var_initialize(vent, app.data_len);
			tag  = vent->tag;
			data = vent->data;
		}

		lcdata_delete_by_tag(&app.data, app.cmd[i]);

		memset(tag, 0, LEMON_CORN_TAG_LEN);
		strcpy(tag, app.cmd[i]);

		printf("waiting ir data for %s ...\n", app.cmd[i]);
		r = receive(fd, rbuf, app.data_len);
		if (r < 0)
			goto out;
		if (app.trunc_len < app.data_len)
			memset(rbuf + app.trunc_len, 0,
			       app.data_len - app.trunc_len);

		/* print received data format */
		if (remocon_format_analyze(fmt_tag_s, fmt_data_s,
					   rbuf, app.data_len) == 0) {
			printf("format = %s, data = %s\n",
			       fmt_tag_s, fmt_data_s);
		} else {
			hexdump(fmt_data_s, rbuf, app.data_len);
			printf("unknown format!\n%s\n", fmt_data_s);
		}
		memcpy(data, rbuf, app.data_len);
		p = data + app.data_len;
	}

	/* data file write */
	if (!app.dont_save)
		save_cmd_with_new(&new_lcdata);

out:
	free(new_lcdata.ent_img);
}

static void list_main(void)
{
	void *p, *nextp, *endp;
	struct lcdata_ent ent;

	lcdata_for_each_entry(&app.data, &ent, p, nextp, endp) {
		char fmt_tag[32];
		char *outbuf;

		/* max size for LIST_MODE_WAVE */
		outbuf = malloc(ent.data_size * 8 + 1);
		if (app.cmd_cnt) {
			int hit = 0;
			int i;
			for (i = 0; i < app.cmd_cnt; i++) {
				if (!strcmp(app.cmd[i], ent.tag))
					hit = 1;
			}
			if (!hit)
				continue;
		}
		switch (app.list_mode) {
		case LIST_MODE_NONE:
			printf("%s\n", ent.tag);
			break;
		case LIST_MODE_HEX:
			hexdump(outbuf, ent.data, ent.data_size);
			printf("%s:\n%s\n", ent.tag, outbuf);
			break;
		case LIST_MODE_WAVE:
			wavedump(outbuf, ent.data, ent.data_size);
			printf("%s:\n%s\n", ent.tag, outbuf);
			break;
		case LIST_MODE_FORMATTED:
			printf("%s:\n", ent.tag);
			if (remocon_format_analyze(fmt_tag, outbuf,
						   ent.data,
						   ent.data_size) == 0) {
				printf("format = %s, data = %s\n",
				       fmt_tag, outbuf);
			} else {
				hexdump(outbuf, ent.data, ent.data_size);
				printf("unknown format!\n%s\n", outbuf);
			}
			break;
		}
		free(outbuf);
	}
}

static void forge_main(int fd)
{
	struct lcdata_ent_img_fxd new_ent_img;
	struct lcdata new_lcdata = {
		.img_size = sizeof(struct lcdata_ent_img_fxd),
		.ent_img = &new_ent_img,
	};
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

	memset(new_ent_img.tag, 0, LEMON_CORN_TAG_LEN);
	if (app.mode == APP_MODE_FORGE) {
		lcdata_delete_by_tag(&app.data, app.cmd[0]);
		strcpy(new_ent_img.tag, app.cmd[0]);
	}

	if (!strncmp(p0, "AEHA,", p1 - p0)) {
		unsigned long custom, cmd;
		custom = strtol(p1, NULL, 16);
		cmd    = strtol(p2, NULL, 16);
		remocon_format_forge_aeha(new_ent_img.data, PCOPRS1_DATA_LEN,
					  custom, cmd);
	} else if (!strncmp(p0, "NEC,", p1 - p0)) {
		unsigned long custom, cmd;
		custom = strtol(p1, NULL, 16);
		cmd    = strtol(p2, NULL, 16);
		remocon_format_forge_nec(new_ent_img.data, PCOPRS1_DATA_LEN,
					 (unsigned short)custom,
					 (unsigned char)cmd);
	} else if (!strncmp(p0, "SONY,", p1 - p0)) {
		unsigned long prod, cmd;
		prod = strtol(p1, NULL, 16);
		cmd  = strtol(p2, NULL, 16);
		remocon_format_forge_sony(new_ent_img.data, PCOPRS1_DATA_LEN,
					  prod, cmd);
	} else {
		goto format_err;
	}

	/* data file write */
	if (app.mode == APP_MODE_FORGE_TRANSMIT) {
		printf("transmitting ...\n");
		transmit(fd, app.ch, new_ent_img.data, PCOPRS1_DATA_LEN);
	} else {
		char s[PCOPRS1_DATA_LEN * 2 + 1];
		hexdump(s, new_ent_img.data, PCOPRS1_DATA_LEN);
		puts(s);
		save_cmd_with_new(&new_lcdata);
	}

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
"        [-len <data_len>]    (data length to receive)\n"
"        [-trunc <trunc_len>] (truncate received signal)\n"
"        [-forge <format> [<command>]]  (forge command with known format)\n"
"                 format: AEHA,<custom_hex>,<cmd_hex>\n"
"                         NEC,<custom_hex>,<cmd_hex>\n"
"                         SONY,<prod_hex>,<cmd_hex>\n"
"        [-arduino]           (arduino mode)\n"
"        [-proxy <host>]      (specify serial proxy)\n"
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
	app.data_len = PCOPRS1_DATA_LEN;
	app.trunc_len = PCOPRS1_DATA_LEN;
	app.dont_save = 0;
	app.proxy_host = NULL;
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
		} else if (!strcmp(argv[i], "-len")) {
			if (++i == argc)
				return -1;
			app.data_len = atoi(argv[i]);
		} else if (!strcmp(argv[i], "-trunc")) {
			if (++i == argc)
				return -1;
			app.trunc_len = atoi(argv[i]);
		} else if (!strcmp(argv[i], "-forge")) {
			app.mode = APP_MODE_FORGE;
			if (++i == argc)
				return -1;
			app.forge_fmt = argv[i];
		} else if (!strcmp(argv[i], "-proxy")) {
			if (++i == argc)
				return -1;
			app.proxy_host = argv[i];
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
	if (app.mode == APP_MODE_FORGE) {
		if (app.cmd_cnt == 0) {
			app.mode = APP_MODE_FORGE_TRANSMIT;
		} else if (app.cmd_cnt > 1) {
			app_error("too many commmands specified"
				  " with -forge.\n");
			return -1;
		}
	}
	if ((app.ch < 1) || (app.ch > 4)) {
		app_error("bad channel (%d)\n", app.ch);
		return -1;
	}
	if ((!app.is_arduino) && (app.data_len != PCOPRS1_DATA_LEN)) {
		app_error("bad data length (%d)\n", app.data_len);
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
	else if (app.proxy_host) {
		if ((fd = proxy_open(app.proxy_host, PORT_STR)) < 0)
			return 1;
	} else {
		if ((fd = serial_open(app.devname, &tio_old)) < 0)
			return 1;
	}

	/* data */
	lcdata_load(&app.data, app.data_fn);
	if ((app.mode != APP_MODE_RECEIVE) && (app.data.img_size == 0)) {
		app_error("data file not found: %s\n", app.data_fn);
		goto out;
	}

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
	case APP_MODE_FORGE_TRANSMIT:
		forge_main(fd);
		break;
	}

out:
	if (fd) {
		if (app.proxy_host)
			proxy_close(fd);
		else
			serial_close(fd, &tio_old);
	}
	lcdata_free(&app.data);

	return 0;
}
