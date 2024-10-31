#include "definitions.hpp"

char8 g_curr_path_buf[32768];

byte g_read_buf[READ_BUFFER_BYTES];

u32 g_curr_path_chars;

void pack_with_args(Range<Range<char8>> args) noexcept;

void unpack_with_args(Range<Range<char8>> args) noexcept;

static __declspec(noreturn) void print_usage(const char8* program_name) noexcept
{
	panic("Usage: %s (" PACK_HELP ") | (" UNPACK_HELP ")", program_name);
}

s32 main()
{
	Range<Range<char8>> argv = minos::command_line_get();

	const u64 start_time = minos::timestamp_utc();

	if (argv.count() < 2)
		print_usage(argv[0].begin());

	if (strcmp(argv[1].begin(), "pack") == 0)
	{
		pack_with_args(argv);
	}
	else if (strcmp(argv[1].begin(), "unpack") == 0)
	{
		unpack_with_args(argv);
	}
	else
		print_usage(argv[0].begin());

	const u64 end_time = minos::timestamp_utc();

	const u64 seconds = (end_time - start_time) / minos::timestamp_ticks_per_second();

	fprintf(stdout, "Completed in %llu minutes %llu seconds\n", seconds / 60, seconds % 60);
}
