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
 * Koizumi ceiling fan
 *
 * | start bit | data | trailer |
 * start bit:  ---------                            0.83ms
 * data0:   ................--------                1.67ms / 0.83ms
 * data1:   ........----------------                0.83ms / 1.67ms
 * separator: ...................................   5.0ms
 * trailer: .....................................  13.2ms
 *
 * data: 48 bit
 */
#define KOIZ_DATA0_L_LEN_MIN	1500
#define KOIZ_DATA0_L_LEN_TYP	1670
#define KOIZ_DATA0_L_LEN_MAX	1850
#define KOIZ_DATA0_H_LEN_MIN	 700
#define KOIZ_DATA0_H_LEN_TYP	 830
#define KOIZ_DATA0_H_LEN_MAX	1000
#define KOIZ_DATA1_L_LEN_MIN	 700
#define KOIZ_DATA1_L_LEN_TYP	 830
#define KOIZ_DATA1_L_LEN_MAX	1000
#define KOIZ_DATA1_H_LEN_MIN	1500
#define KOIZ_DATA1_H_LEN_TYP	1670
#define KOIZ_DATA1_H_LEN_MAX	1850
#define KOIZ_MARKER_L_LEN_MIN	4500
#define KOIZ_MARKER_L_LEN_TYP	5000
#define KOIZ_MARKER_L_LEN_MAX	5500
#define KOIZ_MARKER_BIT_POS1	9
#define KOIZ_MARKER_BIT_POS2	12

static int koiz_on_flip_up(const analyzer_t *azer)
{
	if (azer->state == ANALYZER_STATE_TRAILER)
		return DETECTED_PATTERN_TRAILER;
	return 0;
}

static int koiz_on_flip_dn(const analyzer_t *azer)
{
	if (azer->state == ANALYZER_STATE_LEADER) {
		if ((azer->dur >= azer->cfg->leader_h_len_min) &&
		    (azer->dur <= azer->cfg->leader_h_len_max))
			return 0;
	} else if (azer->state == ANALYZER_STATE_DATA) {
		if ((azer->dur_prev >= KOIZ_DATA0_L_LEN_MIN) &&
		    (azer->dur_prev <= KOIZ_DATA0_L_LEN_MAX) &&
		    (azer->dur >= KOIZ_DATA0_H_LEN_MIN) &&
		    (azer->dur <= KOIZ_DATA0_H_LEN_MAX)) {
			app_debug(ANALYZER, 2, "[%s] data0 (bit%d) at %d\n",
				  azer->cfg->fmt_tag,
				  azer->dst_idx, azer->src_idx);
			return DETECTED_PATTERN_DATA0;
		} else if ((azer->dur_prev >= KOIZ_DATA1_L_LEN_MIN) &&
			   (azer->dur_prev <= KOIZ_DATA1_L_LEN_MAX) &&
			   (azer->dur >= KOIZ_DATA1_H_LEN_MIN) &&
			   (azer->dur <= KOIZ_DATA1_H_LEN_MAX)) {
			app_debug(ANALYZER, 2, "[%s] data1 (bit%d) at %d\n",
				  azer->cfg->fmt_tag,
				  azer->dst_idx, azer->src_idx);
			return DETECTED_PATTERN_DATA1;
		} else if ((azer->dur_prev >= KOIZ_MARKER_L_LEN_MIN) &&
			   (azer->dur_prev <= KOIZ_MARKER_L_LEN_MAX) &&
			   (azer->dur >= azer->cfg->leader_h_len_min) &&
			   (azer->dur <= azer->cfg->leader_h_len_max)) {
			if ((azer->dst_idx != KOIZ_MARKER_BIT_POS1) &&
			    (azer->dst_idx != KOIZ_MARKER_BIT_POS2)) {
				app_debug(ANALYZER, 2,
					  "[%s] unexpected marker position (%d)"
					  " at %d\n",
					  azer->cfg->fmt_tag, azer->dst_idx,
					  azer->src_idx);
				return -1;
			}
			app_debug(ANALYZER, 2, "[%s] marker at %d\n",
				  azer->cfg->fmt_tag, azer->src_idx);
			return DETECTED_PATTERN_MARKER;
		}
	} else
		return 0;

	app_debug(ANALYZER, 1,
		  "[%s] unmatched pattern:"
		  " LOW duration (%4.1fms) / HIGH duration (%4.1fms)"
		  " at %d (state = %d)\n",
		   azer->cfg->fmt_tag,
		   azer->dur_prev / 1000.0, azer->dur / 1000.0,
		   azer->src_idx, azer->state);
	return -1;
}

static int koiz_on_each_sample(const analyzer_t *azer)
{
	if ((azer->state == ANALYZER_STATE_LEADER) &&
	    (azer->level == 0) &&
	    (azer->dur == azer->cfg->leader_l_len_min)) {
		app_debug(ANALYZER, 2, "[%s] leader detected at %d\n",
			  azer->cfg->fmt_tag, azer->src_idx);
		return DETECTED_PATTERN_LEADER;
	} else
		return 0;

	app_debug(ANALYZER, 1,
		  "[%s] unmatched HIGH duration (%4.1fms) at %d (state = %d)\n",
		  azer->cfg->fmt_tag, azer->dur_prev / 1000.0,
		  azer->src_idx - azer->dur / 100, azer->state);
	return -1;
}

static int koiz_on_end_cycle(const analyzer_t *azer,
			     unsigned char *buf0, const unsigned char *buf,
			     char *dst_str)
{
	char tmp_str[ANALYZER_DATA_LEN_MAX * 2 + 1] = "";
	int bytes_got = (azer->dst_idx + 7) / 8;
	int i;

	for (i = bytes_got - 1; i >= 0; i--)
		strcatf(tmp_str, "%02x", buf[i]);

	app_debug(ANALYZER, 1, "[%s] cycle %d data got: %s\n",
		  azer->cfg->fmt_tag, azer->cycle, tmp_str);

	/*
	 * cycle1:           command only
	 * cycle2 and after: command + id + command
	 */
	if (azer->cycle == 0)
		memcpy(buf0, buf, azer->cfg->data_len);
	else if (azer->cycle == 1) {
		unsigned short dst_cmd, tmp_cmd1, tmp_cmd2;
		unsigned char id;

		id = (buf[1] >> 1) & 0x7;
		dst_cmd = (buf[1] << 8) | buf[0];
		tmp_cmd1 = (((unsigned short)buf[1] << 8) | buf[0]) & 0x1ff;
		tmp_cmd2 = (((unsigned short)buf[2] << 4) |
			    ((unsigned short)buf[1] >> 4)) & 0x1ff;
		if ((dst_cmd != tmp_cmd1) ||
		    (dst_cmd != tmp_cmd2)) {
			app_debug(ANALYZER, 1,
				  "[%s] command unmatched in second stage:\n"
				  " first cmd: %04x\n"
				  " second cmd1: %04x, cmd2: %04x\n",
				  azer->cfg->fmt_tag,
				  dst_cmd, tmp_cmd1, tmp_cmd2);
			return -1;
		}
		sprintf(dst_str, "id=%02x cmd=%04x", id, tmp_cmd1);
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

/* bit len = 9 or 9 + 3 + 9 */
struct analyzer_config koiz_azer_cfg = {
	.fmt_tag = "KOIZ",
	.data_len = 3,
	.leader_h_len_min = 700,	/* typ = 8.3 */
	.leader_h_len_max = 1000,
	.leader_l_len_min = 700,	/* typ = 8.3 or 16.7 */
	.leader_l_len_max = 1900,
	.trailer_l_len_min = 11900,	/* typ = 132 */
	.trailer_l_len_max = 14500,
	.cycle_len_min = 0,		/* no condition */
	.cycle_len_max = 1000000,	/* no condition */
};

struct analyzer_ops koiz_azer_ops = {
	.on_flip_up = koiz_on_flip_up,
	.on_flip_dn = koiz_on_flip_dn,
	.on_each_sample = koiz_on_each_sample,
	.on_end_cycle = koiz_on_end_cycle,
	.on_exit = NULL,
};
