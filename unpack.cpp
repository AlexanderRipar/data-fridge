#include "definitions.hpp"

static minos::FileHandle g_data_file;

static minos::FileHandle g_names_file;

static u16 g_output_name_chars[2048];

static byte g_chunk_buf[MAX_CHUNK_SIZE];

static u32 hash_chunk_fnv1a(Range<byte> chunk) noexcept
{
	u32 fnv1a = 0x811C'9DC5;

	for (byte b : chunk)
		fnv1a = (fnv1a ^ b) * 0x010'00193;

	return fnv1a;
}

static void create_root_destination_directory() noexcept
{
	for (u32 i = 0; i != g_curr_path_chars; ++i)
	{
		if (g_curr_path_buf[i] == '\\')
		{
			const Range<char8> directory_name{ g_curr_path_buf, i };

			if (!minos::path_is_directory(directory_name))
			{
				if (!minos::directory_create(directory_name))
					panic("Could not create directory '%.*s' (0x%X)\n", static_cast<u32>(directory_name.count()), directory_name.begin(), minos::last_error());

				fprintf(stdout, "Created directory '%.*s'\n", static_cast<u32>(directory_name.count()), directory_name.begin());
			}
		}
	}

	const Range<char8> directory_name{ g_curr_path_buf, g_curr_path_chars };

	if (!minos::path_is_directory(directory_name))
	{
		if (!minos::directory_create(directory_name))
			panic("Could not create directory '%.*s' (0x%X)\n", static_cast<u32>(directory_name.count()), directory_name.begin(), minos::last_error());

		fprintf(stdout, "Created directory '%.*s'\n", static_cast<u32>(directory_name.count()), directory_name.begin());
	}
}

static void unpack(Range<char8> destination_path, Range<char8> names_path, Range<char8> data_path, minos::CreateMode output_create_mode) noexcept
{
	if (!minos::file_create(data_path, minos::Access::Read, minos::CreateMode::Open, minos::AccessPattern::RandomAccess, minos::SyncMode::Synchronous, false, &g_data_file))
		panic("Could not open data-file '%.*s' (0x%X)\n", static_cast<u32>(data_path.count()), data_path.begin(), minos::last_error());

	if (!minos::file_create(names_path, minos::Access::Read, minos::CreateMode::Open, minos::AccessPattern::Sequential, minos::SyncMode::Synchronous, false, &g_names_file))
		panic("Could not open names-file '%.*s' (0x%X)\n", static_cast<u32>(names_path.count()), names_path.begin(), minos::last_error());

	if (!minos::path_to_absolute(destination_path, MutRange{ g_curr_path_buf }, &g_curr_path_chars))
		panic("Could not convert destination path '%.*s' to absolute path (0x%X)\n", static_cast<u32>(destination_path.count()), destination_path.begin(), minos::last_error());

	minos::FileInfo info;

	if (!minos::file_get_info(g_names_file, &info))
		panic("Could not get info on names-file '%.*s' (0x%X)\n", static_cast<u32>(names_path.count()), names_path.begin(), minos::last_error());

	create_root_destination_directory();

	u64 offset = 0;

	u32 read_buf_reuse = 0;

	bool allow_chunk = false;

	u32 names_depth = 0;

	u32 filename_length = 0;

	minos::FileHandle output_file{};

	u64 output_file_offset = 0;

	while (offset != info.bytes)
	{
		const u32 bytes_to_read = static_cast<u32>(info.bytes - offset < sizeof(g_read_buf) - read_buf_reuse ? info.bytes - offset : sizeof(g_read_buf) - read_buf_reuse);

		minos::Overlapped overlapped{};
		overlapped.offset = offset;

		if (!minos::file_read(g_names_file, g_read_buf + read_buf_reuse, bytes_to_read, &overlapped))
			panic("Could not read %u bytes from file '%.*s' at offset %llu (0x%X)\n", bytes_to_read, static_cast<u32>(names_path.count()), names_path.begin(), offset, minos::last_error());

		u32 i = 0;

		while (i < bytes_to_read)
		{
			const NameTag tag = static_cast<NameTag>(g_read_buf[i]);

			if (tag == NameTag::Directory)
			{
				if (bytes_to_read - i < sizeof(DirectoryName))
					break;

				const DirectoryName* const name = reinterpret_cast<const DirectoryName*>(g_read_buf + i);

				if (bytes_to_read -  i < sizeof(DirectoryName) + align(name->name_length))
					break;

				if (names_depth == array_count(g_output_name_chars))
					panic("Directory nesting exceeds the supported %u names\n", array_count(g_output_name_chars));

				if (g_curr_path_chars + name->name_length + 1 > sizeof(g_curr_path_buf))
					panic("Directory name length exceeds the supported %u characters\n", sizeof(g_curr_path_buf));

				g_curr_path_buf[g_curr_path_chars] = '\\';

				memcpy(g_curr_path_buf + g_curr_path_chars + 1, name->name, name->name_length);

				g_curr_path_chars += name->name_length + 1;

				g_output_name_chars[names_depth] = name->name_length;

				names_depth += 1;

				allow_chunk = false;

				if (!minos::path_is_directory(Range<char8>{ g_curr_path_buf, g_curr_path_chars }))
				{
					if (!minos::directory_create(Range<char8>{ g_curr_path_buf, g_curr_path_chars }))
						panic("Could not create directory '%.*s' (0x%X)\n", g_curr_path_chars, g_curr_path_buf, minos::last_error());
				}
				else if (output_create_mode == minos::CreateMode::Create)
				{
					panic("Output directory '%.*s' already exists. Specify option '-overwrite' to suppress this error\n", g_curr_path_chars, g_curr_path_buf);
				}

				i += sizeof(DirectoryName) + align(name->name_length);
			}
			else if (tag == NameTag::DirectoryEnd)
			{
				if (bytes_to_read - i < align(sizeof(DirectoryEndName)))
					break;

				if (names_depth == 0)
					panic("Read DirectoryEndName from %.*s at offset %llu when there was no directory to end\n", static_cast<u32>(names_path.count()), names_path.begin(), offset + i);

				names_depth -= 1;

				g_curr_path_chars -= g_output_name_chars[names_depth] + 1;

				allow_chunk = false;

				i += align(sizeof(DirectoryEndName));
			}
			else if (tag == NameTag::File)
			{
				if (bytes_to_read - i < sizeof(FileName))
					break;

				const FileName* const name = reinterpret_cast<const FileName*>(g_read_buf + i);

				if (bytes_to_read -  i < sizeof(FileName) + align(name->name_length))
					break;

				if (g_curr_path_chars + name->name_length + 1 > sizeof(g_curr_path_buf))
					panic("File name length exceeds the supported %u characters\n", sizeof(g_curr_path_buf));

				g_curr_path_buf[g_curr_path_chars] = '\\';

				memcpy(g_curr_path_buf + g_curr_path_chars + 1, name->name, name->name_length);

				filename_length = name->name_length;

				if (output_file.m_rep != nullptr)
					minos::file_close(output_file);

				if (!minos::file_create(Range<char8>{ g_curr_path_buf, g_curr_path_chars + name->name_length + 1 }, minos::Access::Write, output_create_mode, minos::AccessPattern::Sequential, minos::SyncMode::Synchronous, false, &output_file))
					panic("Could not open output file '%.*s' (0x%X)\n", g_curr_path_chars + name->name_length + 1, g_curr_path_buf, minos::last_error());

				output_file_offset = 0;

				allow_chunk = true;

				i += sizeof(FileName) + align(name->name_length);
			}
			else if (tag == NameTag::Chunk)
			{
				if (!allow_chunk)
					panic("Unexpected chunk tag (0x%2X) in names-file '%.*s' at offset %llu\n", NameTag::Chunk, static_cast<u32>(names_path.count()), names_path.begin(), offset + i);

				if (bytes_to_read - i < align(sizeof(ChunkName)))
					break;

				const ChunkName* name = reinterpret_cast<const ChunkName*>(g_read_buf + i);

				const u64 source_offset = name->offset_lo + (static_cast<u64>(name->offset_hi) << 32);

				minos::Overlapped chunk_read_overlapped{};
				chunk_read_overlapped.offset = source_offset;

				if (!minos::file_read(g_data_file, g_chunk_buf, name->length, &chunk_read_overlapped))
					panic("Could not read %u bytes from file '%.*s' at offset %llu (0x%X)\n", name->length, static_cast<u32>(data_path.count()), data_path.begin(), source_offset, minos::last_error());

				const u32 actual_fnv1a = hash_chunk_fnv1a(Range<byte>{ g_chunk_buf, name->length });

				if (actual_fnv1a != name->fnv1a)
					panic("Mismatch between expected chunk hash %08X and actual %08X. Chunk of length %u is part of file '%.*s' at offset %llu, and is stored in '%.*s' at offset %llu\n", name->fnv1a, actual_fnv1a, name->length, g_curr_path_chars + filename_length + 1, g_curr_path_buf, output_file_offset, static_cast<u32>(data_path.count()), data_path.begin(), source_offset);

				minos::Overlapped chunk_write_overlapped{};
				chunk_write_overlapped.offset = output_file_offset;

				if (!minos::file_write(output_file, g_chunk_buf, name->length, &chunk_write_overlapped))
					panic("Could not write %u bytes to file '%.*s' at offset %llu (0x%X)\n", name->length, g_curr_path_chars + filename_length + 1, g_curr_path_buf, output_file_offset, minos::last_error());

				output_file_offset += name->length;

				i += align(sizeof(ChunkName));
			}
			else
			{
				panic("Unrecognized tag name '%2X' encountered in file '%.*s' at offset %llu\n", tag, static_cast<u32>(names_path.count()), data_path.begin(), offset + i);
			}
		}

		memmove(g_read_buf, g_read_buf + i, bytes_to_read - i);

		read_buf_reuse = bytes_to_read - i;

		offset += i;
	}

	if (output_file.m_rep != nullptr)
		minos::file_close(output_file);
}

static __declspec(noreturn) void print_unpack_usage(const char8* program_name) noexcept
{
	panic("Usage: %s " UNPACK_HELP "\n", program_name);
}

void unpack_with_args(Range<Range<char8>> args) noexcept
{
	Range<char8> destination_path{};

	Range<char8> data_path{};

	Range<char8> names_path{};

	bool overwrite = false;

	for (uint i = 2; i != args.count(); ++i)
	{
		if (strcmp(args[i].begin(), "-dst") == 0)
		{				
			if (i + 1 == args.count())
			{
				fprintf(stderr, "unpack: Parameter '-dst' supplied to pack is missing an argument\n");

				print_unpack_usage(args[0].begin());
			}

			if (destination_path.begin() != 0)
			{
				fprintf(stderr, "unpack: Parameter '-dst' supplied more than once\n");

				print_unpack_usage(args[0].begin());
			}

			destination_path = args[i + 1];

			i += 1;
		}
		else if (strcmp(args[i].begin(), "-data") == 0)
		{
			if (i + 1 == args.count())
			{
				fprintf(stderr, "unpack: Parameter '-data' supplied to pack is missing an argument\n");

				print_unpack_usage(args[0].begin());
			}

			if (data_path.begin() != 0)
			{
				fprintf(stderr, "unpack: Parameter '-data' supplied more than once\n");

				print_unpack_usage(args[0].begin());
			}

			data_path = args[i + 1];

			i += 1;
		}
		else if (strcmp(args[i].begin(), "-names") == 0)
		{
			if (i + 1 == args.count())
			{
				fprintf(stderr, "unpack: Parameter '-names' supplied to pack is missing an argument\n");

				print_unpack_usage(args[0].begin());
			}

			if (names_path.begin() != 0)
			{
				fprintf(stderr, "unpack: Parameter '-names' supplied more than once\n");

				print_unpack_usage(args[0].begin());
			}

			names_path = args[i + 1];

			i += 1;
		}
		else if (strcmp(args[i].begin(), "-overwrite") == 0)
		{
			if (overwrite)
			{
				fprintf(stderr, "unpack: Parameter '-overwrite' supplied more than once\n");

				print_unpack_usage(args[0].begin());
			}

			overwrite = true;
		}
		else
		{
			fprintf(stderr, "unpack: Unexpected parameter '%s'\n", args[i].begin());

			print_unpack_usage(args[0].begin());
		}
	}

	if (destination_path.begin() == nullptr)
		destination_path = range::from_literal_string(".");

	if (names_path.begin() == nullptr)
	{
		fprintf(stderr, "unpack: Missing parameter '-names'\n");

		print_unpack_usage(args[0].begin());
	}

	if (data_path.begin() == nullptr)
	{
		fprintf(stderr, "unpack: Missing parameter '-data'\n");

		print_unpack_usage(args[0].begin());
	}

	unpack(destination_path, names_path, data_path, overwrite ? minos::CreateMode::Recreate : minos::CreateMode::Create);
}
