#ifndef _DEBUG_H
#define _DEBUG_H

#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 95)

#ifdef APP_DEBUG
#  define app_debug(key, lev, ...) \
	do { \
		if (DEBUG_LEVEL_##key >= lev) \
			printf(DEBUG_HEAD_##key __VA_ARGS__); \
	} while (0)
#else	/* APP_DEBUG */
#  define app_debug(...)	do {} while (0)
#endif	/* APP_DEBUG */

#define app_error(...)		do { fprintf(stderr, __VA_ARGS__); } while (0)

#else	/* GNUC <= 2.0 or 2.95 etc. */

#ifdef APP_DEBUG
#  define app_debug(key, lev, args...) \
	do { \
		if (DEBUG_LEVEL_##key >= lev) \
			printf(DEBUG_HEAD_##key ##args); \
	} while (0)
#else	/* APP_DEBUG */
#  define app_debug(args...)	do {} while (0)
#endif	/* APP_DEBUG */

#define app_error(args...)	do { fprintf(stderr, ##args); } while (0)

#endif	/* about GNUC version */

#endif	/* _DEBUG_H */
