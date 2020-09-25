#ifndef __DEFINES_H_
#define __DEFINES_H_

/* The number of bins MUST be a power of 2!!!
 * This is necessary to have equally-sized bins
 * and optimal performance.
 * Only change BINBASE by considering that the totanl
 * number of bins NBINS = 2^BINBASE.
 * The maximum number of bins if limited by the code 
 * complexity. In current _DEBUG_ mode, no more than
 * 2^12 bins can be used; without _DEBUG_ mode, no errors
 * were reported for 2^18.
 */
#define BINBASE 10 
#define NBINS 0x1<<BINBASE


/* Exit return codes */
#define EXIT_OK 		 0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL		 1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION	 2
#define EXIT_FAIL_XDP		30
#define EXIT_FAIL_BPF		40

#endif /* __DEFINES_H_ */
