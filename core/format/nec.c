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
 * NEC format
 * | leader | custom | custom' | data | ~data |
 *   stop bit + frame space |
 *
 * NOTE: custom' is not always ~custom !!
 *
 * leader:  ------------------------------...............  9.0ms / 4.5ms
 * data0:   -----.....                                     0.56ms / 0.56ms
 * data1:   -----.................                         0.56ms / 1.69ms
 * total 108 ms including frame space (checking 36ms for frame space is enough)
 *
 * repeat signal:
 * ------------------------------...............-----   9.0ms / 2.25ms / 0.56ms
 *
 * custom code: 8 bit
 * data code:   8 bit
 */
#define NEC_LEADER_H_LEN_MIN	  8000
#define NEC_LEADER_H_LEN_TYP	  9000
#define NEC_LEADER_H_LEN_MAX	 10000
#define NEC_LEADER_L_LEN_MIN	  4000
#define NEC_LEADER_L_LEN_TYP	  4500
#define NEC_LEADER_L_LEN_MAX	  5000
#define NEC_DATA_H_LEN_MIN	   500
#define NEC_DATA_H_LEN_TYP	   560
#define NEC_DATA_H_LEN_MAX	   620
#define NEC_DATA0_L_LEN_MIN	   500
#define NEC_DATA0_L_LEN_TYP	   560
#define NEC_DATA0_L_LEN_MAX	   620
#define NEC_DATA1_L_LEN_MIN	  1600
#define NEC_DATA1_L_LEN_TYP	  1690
#define NEC_DATA1_L_LEN_MAX	  1800
#define NEC_TRAILER_L_LEN_MIN	 36000
/* #define NEC_TRAILER_L_LEN_TYP */
#define NEC_TRAILER_L_LEN_MAX	150000	/* FIXME */
#define NEC_CYCLE_LEN_MIN	 80000
#define NEC_CYCLE_LEN_TYP	108000
#define NEC_CYCLE_LEN_MAX	150000
#define NEC_REPEATER_H_LEN_MIN	  8000
#define NEC_REPEATER_H_LEN_TYP	  9000
#define NEC_REPEATER_H_LEN_MAX	 10000
#define NEC_REPEATER_L_LEN_MIN	  2100
#define NEC_REPEATER_L_LEN_TYP	  2250
#define NEC_REPEATER_L_LEN_MAX	  2400

static int nec_on_flip_up(const analyzer_t *azer)
{
	if (azer->state == ANALYZER_STATE_LEADER) {
		if (azer->cycle == 0) {
			if ((azer->dur >= azer->cfg->leader_l_len_min) &&
			    (azer->dur <= azer->cfg->leader_l_len_max)) {
				app_debug(ANALYZER, 2,
					  "[%s] leader detected at %d\n",
					  azer->cfg->fmt_tag, azer->src_idx);
				return DETECTED_PATTERN_LEADER;
			}
		} else {	/* expect repeat signal */
			if ((azer->dur >= NEC_REPEATER_L_LEN_MIN) &&
			    (azer->dur <= NEC_REPEATER_L_LEN_MAX))
				return DETECTED_PATTERN_REPEATER_L;
		}
	} else if (azer->state == ANALYZER_STATE_DATA) {
		if ((azer->dur >= NEC_DATA0_L_LEN_MIN) &&
		    (azer->dur <= NEC_DATA0_L_LEN_MAX)) {
			app_debug(ANALYZER, 2, "[%s] data0 (bit%d) at %d\n",
				  azer->cfg->fmt_tag,
				  azer->dst_idx, azer->src_idx);
			return DETECTED_PATTERN_DATA0;
		} else if ((azer->dur >= NEC_DATA1_L_LEN_MIN) &&
			   (azer->dur <= NEC_DATA1_L_LEN_MAX)) {
			app_debug(ANALYZER, 2, "[%s] data1 at %d\n",
				  azer->cfg->fmt_tag, azer->src_idx);
			return DETECTED_PATTERN_DATA1;
		}
	} else if (azer->state == ANALYZER_STATE_TRAILER) {
		return DETECTED_PATTERN_TRAILER;
	}

	app_debug(ANALYZER, 1,
		  "[%s] unmatched LOW duration (%4.1fms) at %d (state = %d)\n",
		  azer->cfg->fmt_tag,
		  azer->dur / 1000.0, azer->src_idx, azer->state);
	return -1;
}

static int nec_on_flip_dn(const analyzer_t *azer)
{
	if (azer->state == ANALYZER_STATE_LEADER) {
		if ((azer->dur >= azer->cfg->leader_h_len_min) &&
		    (azer->dur <= azer->cfg->leader_h_len_max))
			return 0;
	} else if (azer->state == ANALYZER_STATE_REPEATER) {
		if ((azer->dur >= NEC_DATA_H_LEN_MIN) &&
		    (azer->dur <= NEC_DATA_H_LEN_MAX)) {
			app_debug(ANALYZER, 2, "[%s] repeater detected at %d\n",
				  azer->cfg->fmt_tag, azer->src_idx);
			return DETECTED_PATTERN_REPEATER_H;
		}
	} else if (azer->state == ANALYZER_STATE_DATA) {
		if ((azer->dur >= NEC_DATA_H_LEN_MIN) &&
		    (azer->dur <= NEC_DATA_H_LEN_MAX))
			return 0;
	}

	app_debug(ANALYZER, 1,
		  "[%s] unmatched HIGH duration (%4.1fms) at %d (state = %d)\n",
		   azer->cfg->fmt_tag, azer->dur / 1000.0,
		   azer->src_idx, azer->state);
	return -1;
}

static int nec_on_end_cycle(const analyzer_t *azer,
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
		unsigned short custom = ((unsigned short)buf[0] << 8) | buf[1];
		unsigned char cmd = buf[2];
		unsigned char cmd_ = buf[3];

		/* NOTE: custom' is not always ~custom !! */
		if (cmd != (unsigned char)~cmd_) {
			app_debug(ANALYZER, 1,
				  "%s pattern detected, but data is"
				  " inconsistent.\n"
				  "%02x%02x %02x%02x",
				  azer->cfg->fmt_tag,
				  buf[0], buf[1], buf[2], buf[3]);
			return -1;
		}
		sprintf(dst_str, "custom=%04x cmd=%02x", custom, cmd);

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

struct analyzer_config nec_azer_cfg = {
	.fmt_tag = "NEC",
	.data_bit_len_min = 32,
	.data_bit_len_max = 32,
	.data_len = 4,
	.leader_h_len_min  = NEC_LEADER_H_LEN_MIN,
	.leader_h_len_max  = NEC_LEADER_H_LEN_MAX,
	.leader_l_len_min  = NEC_LEADER_L_LEN_MIN,
	.leader_l_len_max  = NEC_LEADER_L_LEN_MAX,
	.trailer_l_len_min = NEC_TRAILER_L_LEN_MIN,
	.trailer_l_len_max = NEC_TRAILER_L_LEN_MAX,
	.cycle_len_min     = NEC_CYCLE_LEN_MIN,
	.cycle_len_max     = NEC_CYCLE_LEN_MAX,
};

struct analyzer_ops nec_azer_ops = {
	.on_flip_up = nec_on_flip_up,
	.on_flip_dn = nec_on_flip_dn,
	.on_each_sample = NULL,
	.on_end_cycle = nec_on_end_cycle,
	.on_exit = NULL,
};

#define nec_forge_leader(fger) \
	forge_pulse(fger, NEC_LEADER_H_LEN_TYP, NEC_LEADER_L_LEN_TYP)
#define nec_forge_data0(fger) \
	forge_pulse(fger, NEC_DATA_H_LEN_TYP, NEC_DATA0_L_LEN_TYP)
#define nec_forge_data1(fger) \
	forge_pulse(fger, NEC_DATA_H_LEN_TYP, NEC_DATA1_L_LEN_TYP)

int remocon_format_forge_nec(unsigned char *ptn, size_t sz,
			     unsigned short custom, unsigned char cmd)
{
	unsigned char custom_char[2] = {
		(unsigned char)(custom >> 8),
		(unsigned char)(custom & 0xff)
	};
	int idx;
	forger_t fger;
	unsigned long t_start;

	forger_init(&fger, ptn, sz);

	t_start = fger.t;

	/* leader */
	nec_forge_leader(&fger);
	/* custom */
	for (idx = 0; idx < 16; idx++) {
		if (get_bit_in_ary(custom_char, idx))
			nec_forge_data1(&fger);
		else
			nec_forge_data0(&fger);
	}
	/* cmd */
	for (idx = 0; idx < 8; idx++) {
		if (get_bit_in_ary(&cmd, idx))
			nec_forge_data1(&fger);
		else
			nec_forge_data0(&fger);
	}
	cmd = ~cmd;
	for (idx = 0; idx < 8; idx++) {
		if (get_bit_in_ary(&cmd, idx))
			nec_forge_data1(&fger);
		else
			nec_forge_data0(&fger);
	}
	/* stop bit */
	forge_dur(&fger, 1, NEC_DATA_H_LEN_TYP);
	/* trailer */
	forge_until(&fger, 0, t_start + NEC_CYCLE_LEN_TYP);
	/* repeat */
	forge_pulse(&fger, NEC_REPEATER_H_LEN_TYP, NEC_REPEATER_L_LEN_TYP);
	forge_dur(&fger, 1, NEC_DATA_H_LEN_TYP);

	return 0;
}
