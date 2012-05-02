#ifndef _FORGER_COMMON_H
#define _FORGER_COMMON_H

typedef struct {
	unsigned long t;	/* time in us */
	unsigned long t_flip;
	unsigned char *ptn;
	size_t ptn_len;
} forger_t;

extern void forger_init(forger_t *fger, unsigned char *ptn, size_t ptn_len);
extern void forge_dur(forger_t *fger, int val, int dur);
extern void forge_until(forger_t *fger, int val, int until);
extern void forge_pulse(forger_t *fger, int h_len, int l_len);

#endif	/* _FORGER_COMMON_H */
