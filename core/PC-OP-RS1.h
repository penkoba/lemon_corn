#ifndef _PC_OP_RS1_H
#define _PC_OP_RS1_H

#define PCOPRS1_CMD_DATA_COMPLETION	'E'
#define PCOPRS1_CMD_LED_OK		'O'
#define PCOPRS1_CMD_RECEIVE_DATA	'S'
#define PCOPRS1_CMD_OK			'Y'
#define PCOPRS1_CMD_RECEIVE_CANCEL	'c'
#define PCOPRS1_CMD_LED			'i'
#define PCOPRS1_CMD_RECEIVE		'r'
#define PCOPRS1_CMD_TRANSMIT		't'
#define PCOPRS1_CMD_CHANNEL(ch)		('0' + (ch))

#define PCOPRS1_DATA_LEN		240

#endif /* _PC_OP_RS1_H */
