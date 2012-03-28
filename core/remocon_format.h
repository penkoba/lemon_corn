#ifndef _REMOCON_FORMAT_H
#define _REMOCON_FORMAT_H

extern int remocon_format_forge_nec(unsigned char *ptn, size_t sz,
				    unsigned short custom, unsigned char cmd);
extern int remocon_format_forge_aeha(unsigned char *ptn, size_t sz,
				     unsigned long custom, unsigned long cmd);
extern int remocon_format_forge_sony(unsigned char *ptn, size_t sz,
				     unsigned long prod, unsigned long cmd);
extern int remocon_format_analyze(char *fmt_tag, char *dst,
				  const unsigned char *ptn, size_t sz);

#endif	/* _REMOCON_FORMAT_H */
