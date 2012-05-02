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
#include "../string_util.h"
#include "format_util.h"
#include "analyzer_common.h"
#include "forger_common.h"

/*
 * SONY format
 * | leader | data | trailer |
 *
 * leader:  ------------------------......  2.4ms / 0.6ms
 * data0:   ------......                    0.6ms / 0.6ms
 * data1:   ------------......              1.2ms / 0.6ms
 * trailer: ..............................  leader + data + trailer = 45.0ms
 *
 * data: 7 bit for command, 5/8/13 bit for product ID
 */
#define SONY_LEADER_H_LEN_MIN	 2100
#define SONY_LEADER_H_LEN_TYP	 2400
#define SONY_LEADER_H_LEN_MAX	 2700
#define SONY_LEADER_L_LEN_MIN	  400
#define SONY_LEADER_L_LEN_TYP	  600
#define SONY_LEADER_L_LEN_MAX	  800
#define SONY_DATA0_H_LEN_MIN	  400
#define SONY_DATA0_H_LEN_TYP	  600
#define SONY_DATA0_H_LEN_MAX	  800
#define SONY_DATA1_H_LEN_MIN	 1000
#define SONY_DATA1_H_LEN_TYP	 1200
#define SONY_DATA1_H_LEN_MAX	 1400
#define SONY_DATA_L_LEN_MIN	  400
#define SONY_DATA_L_LEN_TYP	  600
#define SONY_DATA_L_LEN_MAX	  800
#define SONY_TRAILER_L_LEN_MIN	 6000	/* FIXME: arbitrary */
/* #define SONY_TRAILER_L_LEN_TYP */
#define SONY_TRAILER_L_LEN_MAX	50000	/* no condition. */
#define SONY_CYCLE_LEN_MIN	40000
#define SONY_CYCLE_LEN_TYP	45000
#define SONY_CYCLE_LEN_MAX	50000

static int sony_on_flip_up(const analyzer_t *azer)
{
	if (azer->state == ANALYZER_STATE_LEADER) {
		/* didn't have enough 0 for leader */
	} else if (azer->state == ANALYZER_STATE_DATA) {
		if ((azer->dur >= SONY_DATA_L_LEN_MIN) &&
		    (azer->dur <= SONY_DATA_L_LEN_MAX))
			return 0;
	} else if (azer->state == ANALYZER_STATE_TRAILER)
		return DETECTED_PATTERN_TRAILER;

	app_debug(ANALYZER, 1,
		  "[%s] unmatched LOW duration (%4.1fms) at %d (state = %d)\n",
		  azer->cfg->fmt_tag, azer->dur / 1000.0,
		  azer->src_idx, azer->state);
	return -1;
}

static int sony_on_flip_dn(const analyzer_t *azer)
{
	if (azer->state == ANALYZER_STATE_LEADER) {
		if ((azer->dur >= azer->cfg->leader_h_len_min) &&
		    (azer->dur <= azer->cfg->leader_h_len_max))
			return 0;
	} else
		return 0;

	app_debug(ANALYZER, 1,
		  "[%s] unmatched HIGH duration (%4.1fms) at %d (state = %d)\n",
		   azer->cfg->fmt_tag, azer->dur / 1000.0,
		   azer->src_idx, azer->state);
	return -1;
}

static int sony_on_each_sample(const analyzer_t *azer)
{
	if ((azer->state == ANALYZER_STATE_LEADER) &&
	    (azer->level == 0) &&
	    (azer->dur == azer->cfg->leader_l_len_min)) {
		app_debug(ANALYZER, 2, "[%s] leader detected at %d\n",
			  azer->cfg->fmt_tag, azer->src_idx);
		return DETECTED_PATTERN_LEADER;
	} else if ((azer->state == ANALYZER_STATE_DATA) &&
		   (azer->level == 0) &&
		   (azer->dur == SONY_DATA_L_LEN_MIN)) {
		if ((azer->dur_prev >= SONY_DATA0_H_LEN_MIN) &&
		    (azer->dur_prev <= SONY_DATA0_H_LEN_MAX)) {
			app_debug(ANALYZER, 2, "[%s] data0 (bit%d) at %d\n",
				  azer->cfg->fmt_tag,
				  azer->dst_idx, azer->src_idx);
			return DETECTED_PATTERN_DATA0;
		} else if ((azer->dur_prev >= SONY_DATA1_H_LEN_MIN) &&
			   (azer->dur_prev <= SONY_DATA1_H_LEN_MAX)) {
			app_debug(ANALYZER, 2, "[%s] data1 (bit%d) at %d\n",
				  azer->cfg->fmt_tag,
				  azer->dst_idx, azer->src_idx);
			return DETECTED_PATTERN_DATA1;
		}
	} else
		return 0;

	app_debug(ANALYZER, 1,
		  "[%s] unmatched HIGH duration (%4.1fms) at %d (state = %d)\n",
		  azer->cfg->fmt_tag, azer->dur_prev / 1000.0,
		  azer->src_idx - azer->dur / 100, azer->state);
	return -1;
}

int sony_on_end_cycle(const analyzer_t *azer,
		      unsigned char *buf0, const unsigned char *buf,
		      char *dst_str)
{
	char tmp_str[ANALYZER_DATA_LEN_MAX * 2 + 1] = "";
	int bytes_got = (azer->dst_idx + 7) / 8;
	int i;

	for (i = bytes_got - 1; i >= 0; i--)
		strcatf(tmp_str, "%02x", buf[i]);

	app_debug(ANALYZER, 1, "[%s] cycle %d data got: %s (%d bits)\n",
		  azer->cfg->fmt_tag, azer->cycle, tmp_str, azer->dst_idx);

	if (azer->cycle == 0) {
		unsigned char cmd;
		unsigned short prod;

		cmd = buf[0] & 0x7f;
		prod = ((unsigned short)buf[2] << 9) |
		       ((unsigned short)buf[1] << 1) |
		       (buf[0] >> 7);
		sprintf(dst_str, "prod=%04x cmd=%02x", prod, cmd);

		memcpy(buf0, buf, azer->cfg->data_len);
	} else {
		if (memcmp(buf0, buf, azer->cfg->data_len)) {
			char tmp0_str[ANALYZER_DATA_LEN_MAX * 2 + 1] = "";

			for (i = bytes_got - 1; i >= 0; i--)
				strcatf(tmp0_str, "%02x", buf0[i]);
			app_debug(ANALYZER, 1,
				  "[%s] data unmatched in cycles:\n"
				  " data 1: %s\n"
				  " data %d: %s\n",
				  azer->cfg->fmt_tag, tmp0_str,
				  azer->cycle + 1, tmp_str);
			return -1;
		}
	}

	return 0;
}

/* bit len = 12, 15, 20 */
struct analyzer_config sony_azer_cfg = {
	.fmt_tag = "SONY",
	.data_len = 3,
	.leader_h_len_min  = SONY_LEADER_H_LEN_MIN,
	.leader_h_len_max  = SONY_LEADER_H_LEN_MAX,
	.leader_l_len_min  = SONY_LEADER_L_LEN_MIN,
	.leader_l_len_max  = SONY_LEADER_L_LEN_MAX,
	.trailer_l_len_min = SONY_TRAILER_L_LEN_MIN,
	.trailer_l_len_max = SONY_TRAILER_L_LEN_MAX,
	.cycle_len_min     = SONY_CYCLE_LEN_MIN,
	.cycle_len_max     = SONY_CYCLE_LEN_MAX,
};

struct analyzer_ops sony_azer_ops = {
	.on_flip_up = sony_on_flip_up,
	.on_flip_dn = sony_on_flip_dn,
	.on_each_sample = sony_on_each_sample,
	.on_end_cycle = sony_on_end_cycle,
	.on_exit = NULL,
};

#define sony_forge_leader(fger) \
	forge_pulse(fger, SONY_LEADER_H_LEN_TYP, SONY_LEADER_L_LEN_TYP)
#define sony_forge_data0(fger) \
	forge_pulse(fger, SONY_DATA0_H_LEN_TYP, SONY_DATA_L_LEN_TYP)
#define sony_forge_data1(fger) \
	forge_pulse(fger, SONY_DATA1_H_LEN_TYP, SONY_DATA_L_LEN_TYP)

int remocon_format_forge_sony(unsigned char *ptn, size_t sz,
			      unsigned long prod, unsigned long cmd)
{
	unsigned char cmd_concat[3];	/* 20 bit at max */
	int data_bit_len;
	int idx;
	int repeat;
	forger_t fger;

	cmd_concat[0] = ((prod & 0x0001) << 7) | cmd;
	cmd_concat[1] =  (prod & 0x01fe) >> 1;
	cmd_concat[2] =  (prod & 0x1e00) >> 9;	/* 13 bit at max */

	data_bit_len = (prod & 0x1e00) ? 20 :
		       (prod & 0x00e0) ? 15 : 12;

	forger_init(&fger, ptn, sz);

	for (repeat = 0; repeat < 3; repeat++) {
		unsigned long t_start = fger.t;

		/* leader */
		sony_forge_leader(&fger);
		/* data */
		for (idx = 0; idx < data_bit_len; idx++) {
			if (get_bit_in_ary(cmd_concat, idx))
				sony_forge_data1(&fger);
			else
				sony_forge_data0(&fger);
		}
		/* trailer */
		forge_until(&fger, 0, t_start + SONY_CYCLE_LEN_TYP);
	}

	return 0;
}
