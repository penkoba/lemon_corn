#ifndef _ANALYZER_CONFIG_H
#define _ANALYZER_CONFIG_H

extern struct analyzer_config aeha_azer_cfg;
extern struct analyzer_ops aeha_azer_ops;

extern struct analyzer_config nec_azer_cfg;
extern struct analyzer_ops nec_azer_ops;

extern struct analyzer_config sony_azer_cfg;
extern struct analyzer_ops sony_azer_ops;

extern struct analyzer_config dkin_azer_cfg;
extern struct analyzer_ops dkin_azer_ops;

extern struct analyzer_config koiz_azer_cfg;
extern struct analyzer_ops koiz_azer_ops;

struct analyzer_table {
	struct analyzer_config *cfg;
	struct analyzer_ops *ops;
};

#define ANALYZER_TABLE	{ \
	{ &aeha_azer_cfg, &aeha_azer_ops }, \
	{ &dkin_azer_cfg, &dkin_azer_ops }, \
	{ &nec_azer_cfg,  &nec_azer_ops }, \
	{ &sony_azer_cfg, &sony_azer_ops }, \
	{ &koiz_azer_cfg, &koiz_azer_ops }, \
}

#endif /* _ANALYZER_CONFIG_H */
