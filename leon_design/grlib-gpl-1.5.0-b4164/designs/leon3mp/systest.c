#define TURN_TRUSTED setpsr(xgetpsr() | (0x7 << 16))
#define TURN_UNTRUSTED setpsr(xgetpsr() & ~(0x7 << 16))


int report_string(const char *array, unsigned int len) {
	int i;
	for (i = 0; i < len; ++i) {
		report_subtest(array[i]);
	}

	return 0;
}

inline int report_int(int val) {
	return report_string((const char*)&val, sizeof(val));
}

main()
{
	report_start();

	report_int(xgetpsr());
	TURN_TRUSTED;
	report_int(xgetpsr());
	TURN_UNTRUSTED;
	report_int(xgetpsr());
	//report_subtest(xgetpsr());
	//printf("psr: %d!\n", 1);
	//base_test();

	report_end();
	return 0;
}
