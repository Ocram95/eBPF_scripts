#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "defines.h"

static const char *default_filename = "/sys/fs/bpf/tc/globals/tc_stats";
int verbose = 1;

struct stats_record {
	__u64 timestamp;
	__u32 counter[NBINS];
};

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static __u64 gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(EXIT_FAIL);
	}
	return (__u64) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

static double calc_period(struct stats_record *r, struct stats_record *p)
{
	double period_ = 0;
	__u64 period = 0;

	period = r->timestamp - p->timestamp;
	if (period > 0)
		period_ = ((double) period / NANOSEC_PER_SEC);

	return period_;
}

static void stats_print(struct stats_record *rec,
			struct stats_record *prev)
{
	double period;
	int packets;

	printf("Flow label\tNo packets\tTotal\tInterval\n");
	char *fmt = "%05x\t\t%d\t\t%d\t[%f s]\n";

	period = calc_period(rec, prev);
	if (period == 0)
	       return;

	for(int key=0;key<NBINS;key++) {
		packets = rec->counter[key] - prev->counter[key];
		printf(fmt, key, packets, rec->counter[key], period);
	}
	printf("\n");
}

static int stats_collect(int fd, struct stats_record *rec)
{
	int value = 0;

   /* Get time as close as possible to reading map contents */
   rec->timestamp = gettime();

	for(int key=0; key<NBINS;key++)
	{
		if ((bpf_map_lookup_elem(fd, &key, &value)) != 0) {
			fprintf(stderr,
				"ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
			return -1; /* Maybe we could just go on with other keys... TODO */
		}
		rec->counter[key] = value;
	}

   return 0;
}

static void print_csv(struct stats_record *rec)
{
	FILE *ftpr;
	ftpr = fopen("experiment_to_rename", "a");
	char timestamp[20];
	sprintf(timestamp, "%lld", rec->timestamp);
	fprintf(ftpr, timestamp);
	fprintf(ftpr, ",");
	for(int key=0;key<NBINS;key++){
		char str[10];
		sprintf(str, "%d", rec->counter[key]);
		fprintf(ftpr, str);
		if (key != ((NBINS) - 1)) {
			fprintf(ftpr, ",");
		}
	} 
	fprintf(ftpr, "\n");	
	fclose(ftpr);
}

static void stats_poll(int map_fd, int interval)
{
	struct stats_record prev, record = { 0 };

	/* Trick to pretty printf with thousands separators use %' */
	setlocale(LC_NUMERIC, "en_US");

	/* Print stats "header" */
	if (verbose) {
		printf("\n");
	}

	/* Get initial reading quickly */
	stats_collect(map_fd, &record);
	usleep(1000000/4);

	while (1) {
		prev = record; /* struct copy */
		stats_collect(map_fd, &record);
		stats_print(&record, &prev);
		print_csv(&record);
		//if( !interval )
		//	break;
		//sleep(interval);
		usleep(100000);
	}
}

static int __check_map_fd_info(int map_fd, struct bpf_map_info *info,
			       struct bpf_map_info *exp)
{
	__u32 info_len = sizeof(*info);
	int err;

	if (map_fd < 0)
		return EXIT_FAIL;

        /* BPF-info via bpf-syscall */
	err = bpf_obj_get_info_by_fd(map_fd, info, &info_len);
	if (err) {
		fprintf(stderr, "ERR: %s() can't get info - %s\n",
			__func__,  strerror(errno));
		return EXIT_FAIL_BPF;
	}

	if (exp->key_size && exp->key_size != info->key_size) {
		fprintf(stderr, "ERR: %s() "
			"Map key size(%d) mismatch expected size(%d)\n",
			__func__, info->key_size, exp->key_size);
		return EXIT_FAIL;
	}
	if (exp->value_size && exp->value_size != info->value_size) {
		fprintf(stderr, "ERR: %s() "
			"Map value size(%d) mismatch expected size(%d)\n",
			__func__, info->value_size, exp->value_size);
		return EXIT_FAIL;
	}
	if (exp->max_entries && exp->max_entries != info->max_entries) {
		fprintf(stderr, "ERR: %s() "
			"Map max_entries(%d) mismatch expected size(%d)\n",
			__func__, info->max_entries, exp->max_entries);
		return EXIT_FAIL;
	}
	if (exp->type && exp->type  != info->type) {
		fprintf(stderr, "ERR: %s() "
			"Map type(%d) mismatch expected type(%d)\n",
			__func__, info->type, exp->type);
		return EXIT_FAIL;
	}

	return 0;
}

int check_map_fd(int map_fd)
{
   struct bpf_map_info map_expect = { 0 };
   struct bpf_map_info info = { 0 };

	map_expect.key_size = sizeof(__u32);
	map_expect.value_size = sizeof(__u32);
	map_expect.max_entries = NBINS;
	
	return __check_map_fd_info(map_fd, &info, &map_expect);
};

void usage(const char *prog_name)
{
	printf("Usage: %s [options]\n", prog_name);

	printf("\nwhere options can be:\n");
	printf("-f <filename>: pinned filename for the map\n");
	printf("-i <interval>: reporting period in sec [default=1s; 0=print once and exit]\n");
	printf("q|v: quiet/verbose mode [default to: verbose]\n");
}

int main(int argc, char **argv)
{
	const char *pinned_file = NULL;
	int interval = 1;
	int map_fd = -1;
	int ret, opt;

	while ((opt = getopt(argc, argv, "f:i:qv") ) != -1 )
	{
		switch (opt) {
			case 'f':
				pinned_file = optarg;
				break;
			case 'i':
				interval = atoi(optarg);
				break;
			case 'v': 
				verbose = true;
				break;
			case 'q':
				verbose = false;
				break;
			default:
				usage(argv[0]);
				goto out;
		}
	}

	if( !pinned_file )
		pinned_file = default_filename;

	if( !pinned_file || interval < 0 )
	{
		usage(argv[0]);
		goto out;
	}

	map_fd = bpf_obj_get(pinned_file);
	if( map_fd < 0 ) {
		fprintf(stderr, "bpf_obj_get(%s): %s[%d]\n",
				pinned_file, strerror(errno), errno);
		goto out;
	}

	if( (ret = check_map_fd(map_fd)) < 0 ) {
		fprintf(stderr, "Map descriptor not compliant with what expected!\n");
		goto out;
	}

	stats_poll(map_fd, interval);
	ret = 0;

out:
	if( map_fd != -1 )
		close(map_fd);

	return ret;
}
