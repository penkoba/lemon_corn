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
#include "../string_util.h"

#include "format_util.h"
#include "analyzer_common.h"
#include "analyzer_config.h"

#define ARRAY_SIZE(a)	(sizeof(a) / sizeof(a[0]))

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
	if (azer->dst_idx == ANALYZER_DATA_LEN_MAX * 8) {
		app_debug(ANALYZER, 1, "[%s] too long data\n",
			  azer->cfg->fmt_tag);
		return -1;
	}
	if (bit)
		set_bit_in_ary(buf, azer->dst_idx);
	return 0;
}

static inline int analyzer_on_flipped(analyzer_t *azer)
{
	app_debug(ANALYZER, 3,
		  "%-4s at %3d, dur = %4.1fms, dur_cycle = %4.1fms\n",
		  (azer->level == 1) ? "HIGH" : "LOW", azer->src_idx,
		  azer->dur / 1000.0, azer->dur_cycle / 1000.0);

	if (azer->level == 0)
		return azer->ops->on_flip_up(azer);
	else	/* azer->level = 1 */
		return azer->ops->on_flip_dn(azer);
}

static inline int analyzer_try_detect_trailer(const analyzer_t *azer)
{
	if ((azer->level == 0) &&
	    (azer->state == ANALYZER_STATE_DATA) &&
	    (azer->dur >= azer->cfg->trailer_l_len_min) &&
	    (azer->dur_cycle >= azer->cfg->cycle_len_min)) {
		app_debug(ANALYZER, 2, "[%s] trailer detected at %d\n",
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
			if (azer.ops->on_end_cycle(&azer, buf, buf_tmp,
						   dst_str) < 0)
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
		app_debug(ANALYZER, 1, "[%s] no data cycle detected\n",
			  azer.cfg->fmt_tag);
		return -1;
	}

	/* successfully analyzed */
	if (azer.ops->on_exit &&
	    (azer.ops->on_exit(&azer, buf, dst_str) < 0))
		return -1;
	strcpy(fmt_tag, azer.cfg->fmt_tag);

	return azer.cfg->data_len;
}

int remocon_format_analyze(char *fmt_tag, char *dst_str,
			   const unsigned char *ptn, size_t sz)
{
	struct analyzer_table analyzer_table[] = ANALYZER_TABLE;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(analyzer_table); i++) {
		if (analyze(analyzer_table[i].cfg, analyzer_table[i].ops,
			    fmt_tag, dst_str, ptn, sz) >= 0)
			return 0;
	}

	return -1;
}
