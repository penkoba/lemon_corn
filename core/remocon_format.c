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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "string_util.h"

#define DEBUG_HEAD_REMOCON_FORMAT	"[remocon format] "
#ifndef DEBUG_LEVEL_REMOCON_FORMAT
#define DEBUG_LEVEL_REMOCON_FORMAT	0
#endif
#include "debug.h"

#define UNUSED(x)	(void)(x)
#define ARRAY_SIZE(a)	(sizeof(a) / sizeof(a[0]))

static inline char get_bit_in_ary(const unsigned char *ary, int idx)
{
	return (ary[idx / 8] >> (idx & 0x7)) & 0x01;
}

static inline void set_bit_in_ary(unsigned char *ary, int idx)
{
	ary[idx / 8] |= (1 << (idx & 0x7));
}

/*
 * enum to indicate what data an analyzer detected
 */
enum {
	DETECTED_PATTERN_DATA0 = 1,
	DETECTED_PATTERN_DATA1,
	DETECTED_PATTERN_DATA,
	DETECTED_PATTERN_LEADER,
	DETECTED_PATTERN_TRAILER,
	DETECTED_PATTERN_MARKER,
	DETECTED_PATTERN_REPEATER_L,
	DETECTED_PATTERN_REPEATER_H,
};

/*
 * analyzer state
 */
enum analyzer_state {
	ANALYZER_STATE_LEADER,
	ANALYZER_STATE_DATA,
	ANALYZER_STATE_TRAILER,
	ANALYZER_STATE_MARKER,
	ANALYZER_STATE_REPEATER,
};

/*
 * maximum analyzer data length
 * (data_bit_len_max must be less than ANALYZER_DATA_LEN_MAX * 8)
 */
#define ANALYZER_DATA_LEN_MAX	64

/*
 * analyzer configuration
 */
struct analyzer_config {
	const char *fmt_tag;
	int data_bit_len_min;
	int data_bit_len_max;
	int data_len;
	int leader_h_len_min;
	int leader_h_len_max;
	int leader_l_len_min;
	int leader_l_len_max;
	int trailer_l_len_min;
	int trailer_l_len_max;
	int cycle_len_min;
	int cycle_len_max;
};

/*
 * pre-define analyzer_t
 */
typedef struct analyzer analyzer_t;

/*
 * analyzer operators
 */
struct analyzer_ops {
	int (*on_flip_up)(const analyzer_t *azer);
	int (*on_flip_dn)(const analyzer_t *azer);
	int (*on_each_sample)(const analyzer_t *azer);
	int (*on_end_cycle)(const analyzer_t *azer,
			    unsigned char *buf, const unsigned char *tmp);
	int (*on_exit)(const analyzer_t *azer, unsigned char *buf,
		       char *dst_str);
};

/*
 * analyzer struct
 */
struct analyzer {
	const struct analyzer_config *cfg;
	const struct analyzer_ops *ops;

	/*
	 * state
	 */
	enum analyzer_state state;
	int src_idx, dst_idx;
	int cycle;
	char level;
	int dur;
	int dur_prev;
	int dur_cycle;
};

/*
 * analyzer functions
 */
static void analyzer_init(analyzer_t *azer)
{
	azer->dst_idx = 0;
	azer->cycle = 0;

	azer->state = ANALYZER_STATE_TRAILER;
	/* assuming we had enough 0s */
	azer->level = 0;
	azer->dur = azer->cfg->trailer_l_len_min;
	azer->dur_prev = 0;
	azer->dur_cycle = azer->cfg->cycle_len_min;
}

static int analyzer_on_bit_detected(const analyzer_t *azer, unsigned char *buf,
				    unsigned char bit)
{
	if (azer->dst_idx == azer->cfg->data_bit_len_max) {
		app_debug(REMOCON_FORMAT, 1, "[%s] too long data\n",
			  azer->cfg->fmt_tag);
		return -1;
	}
	if (bit)
		set_bit_in_ary(buf, azer->dst_idx);
	return 0;
}

static inline int analyzer_on_flipped(analyzer_t *azer)
{
	app_debug(REMOCON_FORMAT, 3,
		  "%-4s at %3d, dur = %4.1fms, dur_cycle = %4.1fms\n",
		  (azer->level == 1) ? "HIGH" : "LOW", azer->src_idx,
		  azer->dur / 1000.0, azer->dur_cycle / 1000.0);

	if (azer->level == 0)
		return azer->ops->on_flip_up(azer);
	else	/* azer->level = 1 */
		return azer->ops->on_flip_dn(azer);
}

static int analyzer_on_end_cycle(const analyzer_t *azer,
				 unsigned char *buf, const unsigned char *tmp)
{
	char dst_str[ANALYZER_DATA_LEN_MAX * 2] = "";
	char tmp_str[ANALYZER_DATA_LEN_MAX * 2] = "";
	int bytes_got = (azer->dst_idx + 7) / 8;
	int i;

	for (i = bytes_got - 1; i >= 0; i--) {
		strcatf(dst_str, "%02x", buf[i]);
		strcatf(tmp_str, "%02x", tmp[i]);
	}

	app_debug(REMOCON_FORMAT, 1, "[%s] cycle %d data got: %s (%d bits)\n",
		  azer->cfg->fmt_tag, azer->cycle, tmp_str, azer->dst_idx);

	if (azer->cycle == 0)
		memcpy(buf, tmp, azer->cfg->data_len);
	else {
		if (memcmp(buf, tmp, azer->cfg->data_len)) {
			app_debug(REMOCON_FORMAT, 1,
				  "[%s] data unmatched in cycles:\n"
				  " data 1: %s\n"
				  " data %d: %s\n",
				  azer->cfg->fmt_tag, dst_str,
				  azer->cycle + 1, tmp_str);
			return -1;
		}
	}

	return 0;
}

static inline int analyzer_try_detect_trailer(const analyzer_t *azer)
{
	if ((azer->level == 0) &&
	    (azer->state == ANALYZER_STATE_DATA) &&
	    (azer->dur >= azer->cfg->trailer_l_len_min) &&
	    (azer->dur_cycle >= azer->cfg->cycle_len_min)) {
		if (azer->dst_idx < azer->cfg->data_bit_len_min) {
			app_debug(REMOCON_FORMAT, 1,
				  "[%s] data length (%d) unmatched\n",
				  azer->cfg->fmt_tag, azer->dst_idx);
			return -1;
		}
		app_debug(REMOCON_FORMAT, 2, "[%s] trailer detected at %d\n",
			  azer->cfg->fmt_tag, azer->src_idx);
		return DETECTED_PATTERN_TRAILER;
	}

	return 0;
}

static int analyzer_on_each_sample(const analyzer_t *azer)
{
	int r;

	r = analyzer_try_detect_trailer(azer);
	if (r)
		return r;
	if (azer->ops->on_each_sample)
		r = azer->ops->on_each_sample(azer);
	return r;
}

/*
 * forger
 */
typedef struct {
	unsigned long t;	/* time in us */
	unsigned long t_flip;
	unsigned char *ptn;
	size_t ptn_len;
} forger_t;

static void forger_init(forger_t *fger, unsigned char *ptn, size_t ptn_len)
{
	fger->t = 0;
	fger->t_flip = 0;
	fger->ptn = ptn;
	fger->ptn_len = ptn_len;
	memset(ptn, 0, ptn_len);
}

static void forge_dur(forger_t *fger, int val, int dur)
{
	for (fger->t_flip += dur;
	     fger->t < fger->t_flip;
	     fger->t += 100) {
		if (val)
			set_bit_in_ary(fger->ptn, fger->t / 100);
	}
}

static void forge_until(forger_t *fger, int val, int until)
{
	for (fger->t_flip = until;
	     fger->t < fger->t_flip;
	     fger->t += 100) {
		if (val)
			set_bit_in_ary(fger->ptn, fger->t / 100);
	}
}

static void forge_pulse(forger_t *fger, int h_len, int l_len)
{
	forge_dur(fger, 1, h_len);
	forge_dur(fger, 0, l_len);
}

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
 * ------------------------------...............-----   9.0ms / 2.25m / 0.56ms
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
				app_debug(REMOCON_FORMAT, 2,
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
			app_debug(REMOCON_FORMAT, 2,
				  "[%s] data0 (bit%d) at %d\n",
				  azer->cfg->fmt_tag,
				  azer->dst_idx, azer->src_idx);
			return DETECTED_PATTERN_DATA0;
		} else if ((azer->dur >= NEC_DATA1_L_LEN_MIN) &&
			   (azer->dur <= NEC_DATA1_L_LEN_MAX)) {
			app_debug(REMOCON_FORMAT, 2, "[%s] data1 at %d\n",
				  azer->cfg->fmt_tag, azer->src_idx);
			return DETECTED_PATTERN_DATA1;
		}
	} else if (azer->state == ANALYZER_STATE_TRAILER) {
		return DETECTED_PATTERN_TRAILER;
	}

	app_debug(REMOCON_FORMAT, 1,
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
			app_debug(REMOCON_FORMAT, 2,
				  "[%s] repeater detected at %d\n",
				  azer->cfg->fmt_tag, azer->src_idx);
			return DETECTED_PATTERN_REPEATER_H;
		}
	} else if (azer->state == ANALYZER_STATE_DATA) {
		if ((azer->dur >= NEC_DATA_H_LEN_MIN) &&
		    (azer->dur <= NEC_DATA_H_LEN_MAX))
			return 0;
	}

	app_debug(REMOCON_FORMAT, 1,
		  "[%s] unmatched HIGH duration (%4.1fms) at %d (state = %d)\n",
		   azer->cfg->fmt_tag, azer->dur / 1000.0,
		   azer->src_idx, azer->state);
	return -1;
}

static int nec_on_exit(const analyzer_t *azer, unsigned char *buf,
		       char *dst_str)
{
	unsigned short custom = ((unsigned short)buf[0] << 8) | buf[1];
	unsigned char cmd = buf[2];

	UNUSED(azer);
	/* NOTE: custom' is not always ~custom !! */
	if (buf[2] != (unsigned char)~buf[3]) {
		app_debug(REMOCON_FORMAT, 1,
			  "%s pattern detected, but data is inconsistent.\n"
			  "%02x%02x %02x%02x",
			  azer->cfg->fmt_tag, buf[0], buf[1], buf[2], buf[3]);
		return -1;
	}
	sprintf(dst_str, "custom=%04x cmd=%02x", custom, cmd);
	return 0;
}

static struct analyzer_config nec_azer_cfg = {
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

static struct analyzer_ops nec_azer_ops = {
	.on_flip_up = nec_on_flip_up,
	.on_flip_dn = nec_on_flip_dn,
	.on_each_sample = NULL,
	.on_end_cycle = analyzer_on_end_cycle,
	.on_exit = nec_on_exit,
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
			app_debug(REMOCON_FORMAT, 2,
				  "[%s] leader detected at %d\n",
				  azer->cfg->fmt_tag, azer->src_idx);
			return DETECTED_PATTERN_LEADER;
		}
	} else if (azer->state == ANALYZER_STATE_DATA) {
		if ((azer->dur >= AEHA_DATA0_L_LEN_MIN) &&
		    (azer->dur <= AEHA_DATA0_L_LEN_MAX)) {
			app_debug(REMOCON_FORMAT, 2,
				  "[%s] data0 (bit%d) at %d\n",
				  azer->cfg->fmt_tag,
				  azer->dst_idx, azer->src_idx);
			return DETECTED_PATTERN_DATA0;
		} else if ((azer->dur >= AEHA_DATA1_L_LEN_MIN) &&
			   (azer->dur <= AEHA_DATA1_L_LEN_MAX)) {
			app_debug(REMOCON_FORMAT, 2,
				  "[%s] data1 (bit%d) at %d\n",
				  azer->cfg->fmt_tag,
				  azer->dst_idx, azer->src_idx);
			return DETECTED_PATTERN_DATA1;
		}
	} else if (azer->state == ANALYZER_STATE_TRAILER) {
		return DETECTED_PATTERN_TRAILER;
	}

	app_debug(REMOCON_FORMAT, 1,
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

	app_debug(REMOCON_FORMAT, 1,
		  "[%s] unmatched HIGH duration (%4.1fms) at %d (state = %d)\n",
		   azer->cfg->fmt_tag, azer->dur / 1000.0,
		   azer->src_idx, azer->state);
	return -1;
}

static int aeha_on_exit(const analyzer_t *azer, unsigned char *buf,
			char *dst_str)
{
	unsigned short custom = ((unsigned short)buf[1] << 8) | buf[0];
	unsigned char parity = buf[2] & 0xf;
	unsigned long cmd = ( (unsigned long)buf[5]         << 20) |
			    ( (unsigned long)buf[4]         << 12) |
			    ( (unsigned long)buf[3]         <<  4) |
			    (((unsigned long)buf[2] & 0xf0) >>  4);

	UNUSED(azer);
	if ((((buf[0] >> 4) & 0xf) ^
	      (buf[0] & 0xf) ^
	     ((buf[1] >> 4) & 0xf) ^
	      (buf[1] & 0xf)) != parity) {
		app_debug(REMOCON_FORMAT, 1,
			  "%s pattern detected, but parity is inconsistent.\n"
			  "%04x %01x %07lx",
			  azer->cfg->fmt_tag, custom, parity, cmd);
	}
	sprintf(dst_str, "custom=%04x cmd=%07lx", custom, cmd);
	return 0;
}

static struct analyzer_config aeha_azer_cfg = {
	.fmt_tag = "AEHA",
	.data_bit_len_min = 48,		/* SHARP dvd, Panasonic STB */
	.data_bit_len_max = 144,	/* Daikin aircon: 80bit,
					   Mitsubishi aircon: 144 bit */
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

static struct analyzer_ops aeha_azer_ops = {
	.on_flip_up = aeha_on_flip_up,
	.on_flip_dn = aeha_on_flip_dn,
	.on_each_sample = NULL,
	.on_end_cycle = analyzer_on_end_cycle,
	.on_exit = aeha_on_exit,
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

/*
 * DAIKIN aircon format
 *
 * | leader | data | stop bit | trailer |
 * leader:  ---------------------............  5ms / 2.2ms
 * data0:   -----.....                                     0.4ms / 0.8ms
 * data1:   -----.................                         0.4ms / 1.8ms
 * trailer: ..............................                 20.0ms (> 8ms)
 *
 * data: 48 bit
 */
#define DKIN_LEADER_H_LEN_MIN	4500
#define DKIN_LEADER_H_LEN_TYP	5000
#define DKIN_LEADER_H_LEN_MAX	5500
#define DKIN_LEADER_L_LEN_MIN	1900
#define DKIN_LEADER_L_LEN_TYP	2200
#define DKIN_LEADER_L_LEN_MAX	2500
#define DKIN_DATA_H_LEN_MIN	 300
#define DKIN_DATA_H_LEN_TYP	 400
#define DKIN_DATA_H_LEN_MAX	 500
#define DKIN_DATA0_L_LEN_MIN	 600
#define DKIN_DATA0_L_LEN_TYP	 800
#define DKIN_DATA0_L_LEN_MAX	1000
#define DKIN_DATA1_L_LEN_MIN	1500
#define DKIN_DATA1_L_LEN_TYP	1800
#define DKIN_DATA1_L_LEN_MAX	2100
#define DKIN_TRAILER_L_LEN_MIN	8000
#define DKIN_TRAILER_L_LEN_TYP	30000	/* uknown */
#define DKIN_TRAILER_L_LEN_MAX	1000000	/* no condition */
#define DKIN_CYCLE_LEN_MIN	0	/* no condition */
/* #define DKIN_CYCLE_LEN_TYP */
#define DKIN_CYCLE_LEN_MAX	1000000	/* no condition */

static int dkin_on_flip_up(const analyzer_t *azer)
{
	if (azer->state == ANALYZER_STATE_LEADER) {
		if ((azer->dur >= azer->cfg->leader_l_len_min) &&
		    (azer->dur <= azer->cfg->leader_l_len_max)) {
			app_debug(REMOCON_FORMAT, 2,
				  "[%s] leader detected at %d\n",
				  azer->cfg->fmt_tag, azer->src_idx);
			return DETECTED_PATTERN_LEADER;
		}
	} else if (azer->state == ANALYZER_STATE_DATA) {
		if ((azer->dur >= DKIN_DATA0_L_LEN_MIN) &&
		    (azer->dur <= DKIN_DATA0_L_LEN_MAX)) {
			app_debug(REMOCON_FORMAT, 2,
				  "[%s] data0 (bit%d) at %d\n",
				  azer->cfg->fmt_tag,
				  azer->dst_idx, azer->src_idx);
			return DETECTED_PATTERN_DATA0;
		} else if ((azer->dur >= DKIN_DATA1_L_LEN_MIN) &&
			   (azer->dur <= DKIN_DATA1_L_LEN_MAX)) {
			app_debug(REMOCON_FORMAT, 2,
				  "[%s] data1 (bit%d) at %d\n",
				  azer->cfg->fmt_tag,
				  azer->dst_idx, azer->src_idx);
			return DETECTED_PATTERN_DATA1;
		}
	} else if (azer->state == ANALYZER_STATE_TRAILER) {
		return DETECTED_PATTERN_TRAILER;
	}

	app_debug(REMOCON_FORMAT, 1,
		  "[%s] unmatched LOW duration (%4.1fms) at %d (state = %d)\n",
		  azer->cfg->fmt_tag, azer->dur / 1000.0,
		  azer->src_idx, azer->state);
	return -1;
}

static int dkin_on_flip_dn(const analyzer_t *azer)
{
	if (azer->state == ANALYZER_STATE_LEADER) {
		if ((azer->dur >= azer->cfg->leader_h_len_min) &&
		    (azer->dur <= azer->cfg->leader_h_len_max))
			return 0;
	} else if (azer->state == ANALYZER_STATE_DATA) {
		if ((azer->dur >= DKIN_DATA_H_LEN_MIN) &&
		    (azer->dur <= DKIN_DATA_H_LEN_MAX))
			return 0;
	}

	app_debug(REMOCON_FORMAT, 1,
		  "[%s] unmatched HIGH duration (%4.1fms) at %d (state = %d)\n",
		   azer->cfg->fmt_tag, azer->dur / 1000.0,
		   azer->src_idx, azer->state);
	return -1;
}

static int dkin_on_exit(const analyzer_t *azer, unsigned char *buf,
			char *dst_str)
{
	unsigned short custom = ((unsigned short)buf[1] << 8) | buf[0];
	unsigned char parity = buf[2] & 0xf;
	unsigned long cmd = ( (unsigned long)buf[5]         << 20) |
			    ( (unsigned long)buf[4]         << 12) |
			    ( (unsigned long)buf[3]         <<  4) |
			    (((unsigned long)buf[2] & 0xf0) >>  4);

	UNUSED(azer);
	if ((((buf[0] >> 4) & 0xf) ^
	      (buf[0] & 0xf) ^
	     ((buf[1] >> 4) & 0xf) ^
	      (buf[1] & 0xf)) != parity) {
		app_debug(REMOCON_FORMAT, 1,
			  "%s pattern detected, but parity is inconsistent.\n"
			  "%04x %01x %07lx",
			  azer->cfg->fmt_tag, custom, parity, cmd);
	}
	sprintf(dst_str, "custom=%04x cmd=%07lx", custom, cmd);
	return 0;
}

static struct analyzer_config dkin_azer_cfg = {
	.fmt_tag = "DKIN",
	.data_bit_len_min = 40,
	.data_bit_len_max = 80,
	.data_len = 10,
	.leader_h_len_min  = DKIN_LEADER_H_LEN_MIN,
	.leader_h_len_max  = DKIN_LEADER_H_LEN_MAX,
	.leader_l_len_min  = DKIN_LEADER_L_LEN_MIN,
	.leader_l_len_max  = DKIN_LEADER_L_LEN_MAX,
	.trailer_l_len_min = DKIN_TRAILER_L_LEN_MIN,
	.trailer_l_len_max = DKIN_TRAILER_L_LEN_MAX,
	.cycle_len_min     = DKIN_CYCLE_LEN_MIN,
	.cycle_len_max     = DKIN_CYCLE_LEN_MAX,
};

static struct analyzer_ops dkin_azer_ops = {
	.on_flip_up = dkin_on_flip_up,
	.on_flip_dn = dkin_on_flip_dn,
	.on_each_sample = NULL,
	.on_end_cycle = analyzer_on_end_cycle,
	.on_exit = dkin_on_exit,
};

#define dkin_forge_leader(fger) \
	forge_pulse(fger, DKIN_LEADER_H_LEN_TYP, AEHA_LEADER_L_LEN_TYP)
#define dkin_forge_data0(fger) \
	forge_pulse(fger, DKIN_DATA_H_LEN_TYP, AEHA_DATA0_L_LEN_TYP)
#define dkin_forge_data1(fger) \
	forge_pulse(fger, DKIN_DATA_H_LEN_TYP, AEHA_DATA1_L_LEN_TYP)

int remocon_format_forge_dkin(unsigned char *ptn, size_t sz,
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
		dkin_forge_leader(&fger);
		/* custom */
		for (idx = 0; idx < 16; idx++) {
			if (get_bit_in_ary(custom_char, idx))
				dkin_forge_data1(&fger);
			else
				dkin_forge_data0(&fger);
		}
		/* parity */
		for (idx = 0; idx < 4; idx++) {
			if (get_bit_in_ary(&custom_parity, idx))
				dkin_forge_data1(&fger);
			else
				dkin_forge_data0(&fger);
		}
		/* cmd */
		for (idx = 0; idx < 28; idx++) {
			if (get_bit_in_ary(cmd_char, idx))
				dkin_forge_data1(&fger);
			else
				dkin_forge_data0(&fger);
		}
		/* stop bit */
		forge_dur(&fger, 1, DKIN_DATA_H_LEN_TYP);
		/* trailer */
		forge_dur(&fger, 0, DKIN_TRAILER_L_LEN_TYP);
	}

	return 0;
}

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

	app_debug(REMOCON_FORMAT, 1,
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

	app_debug(REMOCON_FORMAT, 1,
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
		app_debug(REMOCON_FORMAT, 2, "[%s] leader detected at %d\n",
			  azer->cfg->fmt_tag, azer->src_idx);
		return DETECTED_PATTERN_LEADER;
	} else if ((azer->state == ANALYZER_STATE_DATA) &&
		   (azer->level == 0) &&
		   (azer->dur == SONY_DATA_L_LEN_MIN)) {
		if ((azer->dur_prev >= SONY_DATA0_H_LEN_MIN) &&
		    (azer->dur_prev <= SONY_DATA0_H_LEN_MAX)) {
			app_debug(REMOCON_FORMAT, 2,
				  "[%s] data0 (bit%d) at %d\n",
				  azer->cfg->fmt_tag,
				  azer->dst_idx, azer->src_idx);
			return DETECTED_PATTERN_DATA0;
		} else if ((azer->dur_prev >= SONY_DATA1_H_LEN_MIN) &&
			   (azer->dur_prev <= SONY_DATA1_H_LEN_MAX)) {
			app_debug(REMOCON_FORMAT, 2,
				  "[%s] data1 (bit%d) at %d\n",
				  azer->cfg->fmt_tag,
				  azer->dst_idx, azer->src_idx);
			return DETECTED_PATTERN_DATA1;
		}
	} else
		return 0;

	app_debug(REMOCON_FORMAT, 1,
		  "[%s] unmatched HIGH duration (%4.1fms) at %d (state = %d)\n",
		  azer->cfg->fmt_tag, azer->dur_prev / 1000.0,
		  azer->src_idx - azer->dur / 100, azer->state);
	return -1;
}

static int sony_on_exit(const analyzer_t *azer, unsigned char *buf,
			char *dst_str)
{
	unsigned char cmd;
	unsigned short prod;

	UNUSED(azer);
	cmd = buf[0] & 0x7f;
	prod = ((unsigned short)buf[2] << 9) |
	       ((unsigned short)buf[1] << 1) |
	       (buf[0] >> 7);
	sprintf(dst_str, "prod=%04x cmd=%02x", prod, cmd);
	return 0;
}

static struct analyzer_config sony_azer_cfg = {
	.fmt_tag = "SONY",
	.data_bit_len_min = 12,	/* 12, 15, 20 bits */
	.data_bit_len_max = 20,
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

static struct analyzer_ops sony_azer_ops = {
	.on_flip_up = sony_on_flip_up,
	.on_flip_dn = sony_on_flip_dn,
	.on_each_sample = sony_on_each_sample,
	.on_end_cycle = analyzer_on_end_cycle,
	.on_exit = sony_on_exit,
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
			app_debug(REMOCON_FORMAT, 2,
				  "[%s] data0 (bit%d) at %d\n",
				  azer->cfg->fmt_tag,
				  azer->dst_idx, azer->src_idx);
			return DETECTED_PATTERN_DATA0;
		} else if ((azer->dur_prev >= KOIZ_DATA1_L_LEN_MIN) &&
			   (azer->dur_prev <= KOIZ_DATA1_L_LEN_MAX) &&
			   (azer->dur >= KOIZ_DATA1_H_LEN_MIN) &&
			   (azer->dur <= KOIZ_DATA1_H_LEN_MAX)) {
			app_debug(REMOCON_FORMAT, 2,
				  "[%s] data1 (bit%d) at %d\n",
				  azer->cfg->fmt_tag,
				  azer->dst_idx, azer->src_idx);
			return DETECTED_PATTERN_DATA1;
		} else if ((azer->dur_prev >= KOIZ_MARKER_L_LEN_MIN) &&
			   (azer->dur_prev <= KOIZ_MARKER_L_LEN_MAX) &&
			   (azer->dur >= azer->cfg->leader_h_len_min) &&
			   (azer->dur <= azer->cfg->leader_h_len_max)) {
			if ((azer->dst_idx != KOIZ_MARKER_BIT_POS1) &&
			    (azer->dst_idx != KOIZ_MARKER_BIT_POS2)) {
				app_debug(REMOCON_FORMAT, 2,
					  "[%s] unexpected marker position (%d)"
					  " at %d\n",
					  azer->cfg->fmt_tag, azer->dst_idx,
					  azer->src_idx);
				return -1;
			}
			app_debug(REMOCON_FORMAT, 2, "[%s] marker at %d\n",
				  azer->cfg->fmt_tag, azer->src_idx);
			return DETECTED_PATTERN_MARKER;
		}
	} else
		return 0;

	app_debug(REMOCON_FORMAT, 1,
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
		app_debug(REMOCON_FORMAT, 2, "[%s] leader detected at %d\n",
			  azer->cfg->fmt_tag, azer->src_idx);
		return DETECTED_PATTERN_LEADER;
	} else
		return 0;

	app_debug(REMOCON_FORMAT, 1,
		  "[%s] unmatched HIGH duration (%4.1fms) at %d (state = %d)\n",
		  azer->cfg->fmt_tag, azer->dur_prev / 1000.0,
		  azer->src_idx - azer->dur / 100, azer->state);
	return -1;
}

static int koiz_on_end_cycle(const analyzer_t *azer,
			     unsigned char *buf, const unsigned char *tmp)
{
	char dst_str[ANALYZER_DATA_LEN_MAX * 2] = "";
	char tmp_str[ANALYZER_DATA_LEN_MAX * 2] = "";
	int bytes_got = (azer->dst_idx + 7) / 8;
	int i;

	for (i = bytes_got - 1; i >= 0; i--) {
		strcatf(dst_str, "%02x", buf[i]);
		strcatf(tmp_str, "%02x", tmp[i]);
	}

	app_debug(REMOCON_FORMAT, 1, "[%s] cycle %d data got: %s\n",
		  azer->cfg->fmt_tag, azer->cycle, tmp_str);

	/*
	 * cycle1:           command only
	 * cycle2 and after: command + id + command
	 */
	if (azer->cycle == 0)
		memcpy(buf, tmp, azer->cfg->data_len);
	else if (azer->cycle == 1) {
		unsigned short dst_cmd, tmp_cmd1, tmp_cmd2;
		dst_cmd = (buf[1] << 8) | buf[0];
		tmp_cmd1 = (((unsigned short)tmp[1] << 8) | tmp[0]) & 0x1ff;
		tmp_cmd2 = (((unsigned short)tmp[2] << 4) |
			    ((unsigned short)tmp[1] >> 4)) & 0x1ff;
		if ((dst_cmd != tmp_cmd1) ||
		    (dst_cmd != tmp_cmd2)) {
			app_debug(REMOCON_FORMAT, 1,
				  "[%s] command unmatched in second stage:\n"
				  " first cmd: %04x\n"
				  " second cmd1: %04x, cmd2: %04x\n",
				  azer->cfg->fmt_tag,
				  dst_cmd, tmp_cmd1, tmp_cmd2);
			return -1;
		}
		memcpy(buf, tmp, azer->cfg->data_len);
	} else {
		if (memcmp(buf, tmp, azer->cfg->data_len)) {
			app_debug(REMOCON_FORMAT, 1,
				  "[%s] data unmatched in cycles:\n"
				  " data 1: %s\n"
				  " data %d: %s\n",
				  azer->cfg->fmt_tag, dst_str,
				  azer->cycle + 1, tmp_str);
			return -1;
		}
	}

	return 0;
}

static int koiz_on_exit(const analyzer_t *azer, unsigned char *buf,
			char *dst_str)
{
	UNUSED(azer);
	unsigned char id;
	unsigned short cmd;

	id = (buf[1] >> 1) & 0x7;
	cmd = (((unsigned short)buf[1] << 8) | buf[0]) & 0x1ff;
	sprintf(dst_str, "id=%02x cmd=%04x", id, cmd);
	return 0;
}

static struct analyzer_config koiz_azer_cfg = {
	.fmt_tag = "KOIZ",
	.data_bit_len_min = 9,		/* 9 or 9 + 3 + 9 */
	.data_bit_len_max = 21,
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

static struct analyzer_ops koiz_azer_ops = {
	.on_flip_up = koiz_on_flip_up,
	.on_flip_dn = koiz_on_flip_dn,
	.on_each_sample = koiz_on_each_sample,
	.on_end_cycle = koiz_on_end_cycle,
	.on_exit = koiz_on_exit,
};

/*
 * generic analyzer func
 */
static int
analyze(struct analyzer_config *azer_cfg, struct analyzer_ops *azer_ops,
	char *fmt_tag, char *dst_str, const unsigned char *ptn, size_t sz)
{
	analyzer_t azer;
	unsigned char buf[ANALYZER_DATA_LEN_MAX];
	unsigned char buf_tmp[ANALYZER_DATA_LEN_MAX] = { 0 };
	size_t sz_bit = sz * 8;
	int r;

	azer.cfg = azer_cfg;
	azer.ops = azer_ops;

	/*
	 * configuration sanity check
	 */
	assert(azer.cfg->data_bit_len_max < ANALYZER_DATA_LEN_MAX * 8);

	analyzer_init(&azer);
	for (azer.src_idx = 0; azer.src_idx < (int)sz_bit; azer.src_idx++) {
		char this_bit = get_bit_in_ary(ptn, azer.src_idx);

		if ((azer.state == ANALYZER_STATE_DATA) ||
		    (azer.state == ANALYZER_STATE_TRAILER))
			azer.dur_cycle += 100;

		if (this_bit == azer.level) {
			azer.dur += 100;
		} else {
			r = analyzer_on_flipped(&azer);
			if (r < 0)
				return -1;
			else if (r == DETECTED_PATTERN_LEADER) {
				azer.state = ANALYZER_STATE_DATA;
				azer.dst_idx = 0;
				azer.dur_cycle = azer.dur_prev + azer.dur;
			} else if (r == DETECTED_PATTERN_TRAILER) {
				azer.state = ANALYZER_STATE_LEADER;
				azer.dur_cycle = 100;
			} else if (r == DETECTED_PATTERN_MARKER) {
				/* nothing to do */
			} else if (r == DETECTED_PATTERN_REPEATER_L) {
				azer.state = ANALYZER_STATE_REPEATER;
			} else if (r == DETECTED_PATTERN_REPEATER_H) {
				azer.state = ANALYZER_STATE_TRAILER;
			} else if (r > 0) {	/* data */
				int dat = (r == DETECTED_PATTERN_DATA1) ? 1 : 0;
				if (analyzer_on_bit_detected(&azer, buf_tmp,
							     dat) < 0)
					return -1;
				azer.dst_idx++;
			}

			azer.level = this_bit;
			azer.dur_prev = azer.dur;
			azer.dur = 100;
		}

		r = analyzer_on_each_sample(&azer);
		if (r < 0)
			return -1;
		else if (r == DETECTED_PATTERN_LEADER) {
			azer.state = ANALYZER_STATE_DATA;
			azer.dst_idx = 0;
			azer.dur_cycle = azer.dur_prev + azer.dur;
		} else if (r == DETECTED_PATTERN_TRAILER) {
			if (azer.ops->on_end_cycle(&azer, buf, buf_tmp) < 0)
				return -1;
			azer.cycle++;
			azer.state = ANALYZER_STATE_TRAILER;
		} else if (r == DETECTED_PATTERN_MARKER) {
			/* nothing to do */
		} else if (r > 0) {	/* data */
			int dat = (r == DETECTED_PATTERN_DATA1) ? 1 : 0;
			if (analyzer_on_bit_detected(&azer, buf_tmp, dat) < 0)
				return -1;
			azer.dst_idx++;
		}
	}

	if (azer.cycle == 0) {
		app_debug(REMOCON_FORMAT, 1, "[%s] no data cycle detected\n",
			  azer.cfg->fmt_tag);
		return -1;
	}

	/* successfully analyzed */
	if (azer.ops->on_exit(&azer, buf, dst_str) < 0)
		return -1;
	strcpy(fmt_tag, azer.cfg->fmt_tag);

	return azer.cfg->data_len;
}

int remocon_format_analyze(char *fmt_tag, char *dst_str,
			   const unsigned char *ptn, size_t sz)
{
	struct {
		struct analyzer_config *cfg;
		struct analyzer_ops *ops;
	} analyzer_set[] = {
		{ &aeha_azer_cfg, &aeha_azer_ops },
		{ &dkin_azer_cfg, &dkin_azer_ops },
		{ &nec_azer_cfg,  &nec_azer_ops },
		{ &sony_azer_cfg, &sony_azer_ops },
		{ &koiz_azer_cfg, &koiz_azer_ops },
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(analyzer_set); i++) {
		if (analyze(analyzer_set[i].cfg, analyzer_set[i].ops,
			    fmt_tag, dst_str, ptn, sz) >= 0)
			return 0;
	}

	return -1;
}
