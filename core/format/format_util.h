#ifndef _FORMAT_UTIL_H
#define _FORMAT_UTIL_H

static inline char get_bit_in_ary(const unsigned char *ary, int idx)
{
	return (ary[idx / 8] >> (idx & 0x7)) & 0x01;
}

static inline void set_bit_in_ary(unsigned char *ary, int idx)
{
	ary[idx / 8] |= (1 << (idx & 0x7));
}

#endif	/* _FORMAT_UTIL_H */
