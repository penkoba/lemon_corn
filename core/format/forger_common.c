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
#include <memory.h>
#include "format_util.h"
#include "forger_common.h"

void forger_init(forger_t *fger, unsigned char *ptn, size_t ptn_len)
{
	fger->t = 0;
	fger->t_flip = 0;
	fger->ptn = ptn;
	fger->ptn_len = ptn_len;
	memset(ptn, 0, ptn_len);
}

void forge_dur(forger_t *fger, int val, int dur)
{
	for (fger->t_flip += dur;
	     fger->t < fger->t_flip;
	     fger->t += 100) {
		if (val)
			set_bit_in_ary(fger->ptn, fger->t / 100);
	}
}

void forge_until(forger_t *fger, int val, int until)
{
	for (fger->t_flip = until;
	     fger->t < fger->t_flip;
	     fger->t += 100) {
		if (val)
			set_bit_in_ary(fger->ptn, fger->t / 100);
	}
}

void forge_pulse(forger_t *fger, int h_len, int l_len)
{
	forge_dur(fger, 1, h_len);
	forge_dur(fger, 0, l_len);
}
