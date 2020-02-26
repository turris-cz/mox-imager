#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include "instr.h"

static void usage(FILE *fp, int ec)
{
	fprintf(fp, "Usage: gppc -o <output> <input>\n\n");
	exit(ec);
}

static FILE *xfopen(const char *path, const char *mode)
{
	FILE *fp = fopen(path, mode);

	if (!fp)
		die("Cannot open file %s: %m", path);

	return fp;
}

int main(int argc, char **argv)
{
	const char *outf = NULL;
	int res, i, opt;
	FILE *fp;
	u32 *out;

	while ((opt = getopt(argc, argv, "ho:")) != -1) {
		switch (opt) {
		case 'h':
			usage(stdout, EXIT_SUCCESS);
		case 'o':
			if (outf)
				usage(stderr, EXIT_FAILURE);
			outf = optarg;
			break;
		default:
			usage(stderr, EXIT_FAILURE);
		}
	}

	fp = optind < argc ? xfopen(argv[optind], "r") : stdin;
	res = assemble(&out, fp);
	fclose(fp);

	for (i = 0; i < res; ++i)
		out[i] = htole32(out[i]);

	fp = outf ? xfopen(outf, "w") : stdout;
	if (fwrite(out, res * sizeof(u32), 1, fp) < 1)
		die("Cannot write");
	fclose(fp);

	free(out);

	return 0;
}