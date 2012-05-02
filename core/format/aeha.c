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
 * AEHA (Panasonic, SHARP etc.) format
 *
 * | leader | data | stop bit | trailer |
 * leader:  ------------------------------...............  3.4ms / 1.7ms
 * data0:   -----.....                                     0.425ms / 0.425ms
 * data1:   -----.................                         0.425ms / 1.275ms
 * trailer: ..............................                 20.0ms (> 8ms)
 *
 * data: 48 bit
 */
#define AEHA_LEADER_H_LEN_MIN	3100
#define AEHA_LEADER_H_LEN_TYP	3400
#define AEHA_LEADER_H_LEN_MAX	3700
#define AEHA_LEADER_L_LEN_MIN	1500
#define AEHA_LEADER_L_LEN_TYP	1700
#define AEHA_LEADER_L_LEN_MAX	1900
#define AEHA_DATA_H_LEN_MIN	 300
#define AEHA_DATA_H_LEN_TYP	 425
#define AEHA_DATA_H_LEN_MAX	 600
#define AEHA_DATA0_L_LEN_MIN	 300
#define AEHA_DATA0_L_LEN_TYP	 425
#define AEHA_DATA0_L_LEN_MAX	 600
#define AEHA_DATA1_L_LEN_MIN	1150
#define AEHA_DATA1_L_LEN_TYP	1275
#define AEHA_DATA1_L_LEN_MAX	1400
#define AEHA_TRAILER_L_LEN_MIN	8000
#define AEHA_TRAILER_L_LEN_TYP	20000	/* uknown. SHARP DVD */
#define AEHA_TRAILER_L_LEN_MAX	1000000	/* no condition */
#define AEHA_CYCLE_LEN_MIN	0	/* no condition */
/* #define AEHA_CYCLE_LEN_TYP */
#define AEHA_CYCLE_LEN_MAX	1000000	/* no condition */

static int aeha_on_flip_up(const analyzer_t *azer)
{
	if (azer->state == ANALYZER_STATE_LEADER) {
		if ((azer->dur >= azer->cfg->leader_l_len_min) &&
		    (azer->dur <= azer->cfg->leader_l_len_max)) {
			app_debug(ANALYZER, 2, "[%s] leader detected at %d\n",
				  azer->cfg->fmt_tag, azer->src_idx);
			return DETECTED_PATTERN_LEADER;
		}
	} else if (azer->state == ANALYZER_STATE_DATA) {
		if ((azer->dur >= AEHA_DATA0_L_LEN_MIN) &&
		    (azer->dur <= AEHA_DATA0_L_LEN_MAX)) {
			app_debug(ANALYZER, 2, "[%s] data0 (bit%d) at %d\n",
				  azer->cfg->fmt_tag,
				  azer->dst_idx, azer->src_idx);
			return DETECTED_PATTERN_DATA0;
		} else if ((azer->dur >= AEHA_DATA1_L_LEN_MIN) &&
			   (azer->dur <= AEHA_DATA1_L_LEN_MAX)) {
			app_debug(ANALYZER, 2, "[%s] data1 (bit%d) at %d\n",
				  azer->cfg->fmt_tag,
				  azer->dst_idx, azer->src_idx);
			return DETECTED_PATTERN_DATA1;
		}
	} else if (azer->state == ANALYZER_STATE_TRAILER) {
		return DETECTED_PATTERN_TRAILER;
	}

	app_debug(ANALYZER, 1,
		  "[%s] unmatched LOW duration (%4.1fms) at %d (state = %d)\n",
		  azer->cfg->fmt_tag, azer->dur / 1000.0,
		  azer->src_idx, azer->state);
	return -1;
}

static int aeha_on_flip_dn(const analyzer_t *azer)
{
	if (azer->state == ANALYZER_STATE_LEADER) {
		if ((azer->dur >= azer->cfg->leader_h_len_min) &&
		    (azer->dur <= azer->cfg->leader_h_len_max))
			return 0;
	} else if (azer->state == ANALYZER_STATE_DATA) {
		if ((azer->dur >= AEHA_DATA_H_LEN_MIN) &&
		    (azer->dur <= AEHA_DATA_H_LEN_MAX))
			return 0;
	}

	app_debug(ANALYZER, 1,
		  "[%s] unmatched HIGH duration (%4.1fms) at %d (state = %d)\n",
		   azer->cfg->fmt_tag, azer->dur / 1000.0,
		   azer->src_idx, azer->state);
	return -1;
}

static int aeha_on_end_cycle(const analyzer_t *azer,
			     unsigned char *buf0, const unsigned char *buf,
			     char *dst_str)
{
	char tmp_str[ANALYZER_DATA_LEN_MAX * 2 + 1] = "";
	int bytes_got = (azer->dst_idx + 7) / 8;
	unsigned short custom = ((unsigned short)buf[1] << 8) | buf[0];
	char custom_str[5];
	char cmd_str[ANALYZER_DATA_LEN_MAX * 2 + 1];
	unsigned char parity = buf[2] & 0xf;
	unsigned long cmd = ( (unsigned long)buf[5]         << 20) |
			    ( (unsigned long)buf[4]         << 12) |
			    ( (unsigned long)buf[3]         <<  4) |
			    (((unsigned long)buf[2] & 0xf0) >>  4);
	int i;

	for (i = bytes_got - 1; i >= 0; i--)
		strcatf(tmp_str, "%02x", buf[i]);

	app_debug(ANALYZER, 1, "[%s] cycle %d data got: %s (%d bits)\n",
		  azer->cfg->fmt_tag, azer->cycle, tmp_str, azer->dst_idx);

	if ((((buf[0] >> 4) & 0xf) ^
	      (buf[0] & 0xf) ^
	     ((buf[1] >> 4) & 0xf) ^
	      (buf[1] & 0xf)) != parity) {
		app_debug(ANALYZER, 1,
			  "%s pattern detected, but parity is inconsistent.\n"
			  "%04x %01x %07lx",
			  azer->cfg->fmt_tag, custom, parity, cmd);
	}

	if (bytes_got >= 2) {
		memcpy(custom_str, &tmp_str[bytes_got * 2 - 4], 4);
		custom_str[4] = '\0';
	}
	if (bytes_got >= 3) {
		memcpy(cmd_str, tmp_str, bytes_got * 2 - 5);
		cmd_str[bytes_got * 2 - 5] = '\0';
	}

	if (azer->cycle == 0) {
		sprintf(dst_str, "custom=%s cmd=%s", custom_str, cmd_str);
		memcpy(buf0, buf, azer->cfg->data_len);
	} else {
		/* concat if data is different from previous */
		if (memcmp(buf0, buf, azer->cfg->data_len))
			strcatf(dst_str, " + custom=%s cmd=%s",
				custom_str, cmd_str);
	}

	return 0;
}

/*
 * SHARP dvd, Panasonic STB: 48bit
 * Daikin aircon: 80bit,
 * Mitsubishi aircon: 144 bit
 */
struct analyzer_config aeha_azer_cfg = {
	.fmt_tag = "AEHA",
	.data_len = 18,
	.leader_h_len_min  = AEHA_LEADER_H_LEN_MIN,
	.leader_h_len_max  = AEHA_LEADER_H_LEN_MAX,
	.leader_l_len_min  = AEHA_LEADER_L_LEN_MIN,
	.leader_l_len_max  = AEHA_LEADER_L_LEN_MAX,
	.trailer_l_len_min = AEHA_TRAILER_L_LEN_MIN,
	.trailer_l_len_max = AEHA_TRAILER_L_LEN_MAX,
	.cycle_len_min     = AEHA_CYCLE_LEN_MIN,
	.cycle_len_max     = AEHA_CYCLE_LEN_MAX,
};

struct analyzer_ops aeha_azer_ops = {
	.on_flip_up = aeha_on_flip_up,
	.on_flip_dn = aeha_on_flip_dn,
	.on_each_sample = NULL,
	.on_end_cycle = aeha_on_end_cycle,
	.on_exit = NULL,
};

#define aeha_forge_leader(fger) \
	forge_pulse(fger, AEHA_LEADER_H_LEN_TYP, AEHA_LEADER_L_LEN_TYP)
#define aeha_forge_data0(fger) \
	forge_pulse(fger, AEHA_DATA_H_LEN_TYP, AEHA_DATA0_L_LEN_TYP)
#define aeha_forge_data1(fger) \
	forge_pulse(fger, AEHA_DATA_H_LEN_TYP, AEHA_DATA1_L_LEN_TYP)

int remocon_format_forge_aeha(unsigned char *ptn, size_t sz,
			      unsigned long custom, unsigned long cmd)
{
	unsigned char custom_char[2] = {
		(unsigned char)(custom & 0xff),
		(unsigned char)(custom >> 8)
	};
	unsigned char custom_parity = (((custom >> 12) & 0xf) ^
				       ((custom >>  8) & 0xf) ^
				       ((custom >>  4) & 0xf) ^
				       ( custom        & 0xf));
	unsigned char cmd_char[4] = {
		(unsigned char)( cmd        & 0xff),
		(unsigned char)((cmd >>  8) & 0xff),
		(unsigned char)((cmd >> 16) & 0xff),
		(unsigned char)((cmd >> 24) & 0x0f),
	};
	int idx;
	int repeat;
	forger_t fger;

	forger_init(&fger, ptn, sz);

	for (repeat = 0; repeat < 2; repeat++) {
		/* leader */
		aeha_forge_leader(&fger);
		/* custom */
		for (idx = 0; idx < 16; idx++) {
			if (get_bit_in_ary(custom_char, idx))
				aeha_forge_data1(&fger);
			else
				aeha_forge_data0(&fger);
		}
		/* parity */
		for (idx = 0; idx < 4; idx++) {
			if (get_bit_in_ary(&custom_parity, idx))
				aeha_forge_data1(&fger);
			else
				aeha_forge_data0(&fger);
		}
		/* cmd */
		for (idx = 0; idx < 28; idx++) {
			if (get_bit_in_ary(cmd_char, idx))
				aeha_forge_data1(&fger);
			else
				aeha_forge_data0(&fger);
		}
		/* stop bit */
		forge_dur(&fger, 1, AEHA_DATA_H_LEN_TYP);
		/* trailer */
		forge_dur(&fger, 0, AEHA_TRAILER_L_LEN_TYP);
	}

	return 0;
}
