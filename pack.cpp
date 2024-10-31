#include "definitions.hpp"

static constexpr u64 GEAR_HASH_LUT[256] = {
	12176548568703913075, 8860044641925307073,  9714323548148034708,  14183569105327458450,
	6917318239575149652,  5479279381411854890,  6131870341878151958,  3332785651370130976,
	16607001043816051575, 705052811190856398,   12799708993466112119, 13144063519300392464,
	6252189126752387280,  15534419676094504926, 1182532398565844620,  2889458844622955024,
	11210872980189466518, 10734232471800531119, 186583589036789320,   17090439885543029960,
	2968034757119363121,  10499249146905275956, 11322840402154292578, 5208633459074549778,
	1812993389107714657,  10230477349294210755, 8831093654530351777,  8146443749290497790,
	1953878055724402091,  13277756229091225287, 5646172370133123998,  5710425489089034901,
	15079473729529516762, 99400692503265686,    13645005063636041056, 6145069447356154196,
	4505862955199035503,  5408058304061281883,  4379680321680972113,  10811550478994129089,
	9901811535568902632,  9609107020325909137,  15818253996773738931, 13331221299971943492,
	12892069534707809039, 2229653886367932988,  14302273861035083415, 13233565003751606871,
	4130630451200556225,  18278136221540125906, 7219870259765162970,  2690088002695769738,
	636091573648111748,   8719834826525423332,  12819294657936554894, 3169855800683859879,
	7384842153268897411,  6245300283716243371,  17092557075049114614, 11596234451019003036,
	11880154034110903862, 9196888544133078263,  15135959573206054813, 4985976961530221890,
	10411274551984263261, 9484051937844970438,  11526620094094373380, 3643262510070375907,
	3908029217954396663,  16365614360867198540, 3355967475848315496,  12493558805879739962,
	14773536505404797429, 4420201277514130166,  17415754914297980046, 10502696905809540171,
	16439817934707989199, 8247732432317845275,  9686774411281573121,  14931709273491591389,
	14103168037808542172, 16544277527823578261, 12070210094876434773, 12298734589469056740,
	1911046133903225907,  16818435116595537926, 16980473276584194061, 15152895096511011292,
	9732328084389043758,  7486913047614212378,  16621062889982626545, 11842308940927269634,
	5714879069959018499,  12228890889154964215, 561052896422760383,   6159292560433162334,
	6516048425608968814,  12650066086631291891, 1218528690687077177,  5510843289924825525,
	1886078689086656997,  6064877788235219707,  14467775282571909902, 10052723527606872281,
	2533579171479083571,  7392075254740029228,  15992309876857830723, 5134282559786230161,
	7378549183369836680,  13261197327845167227, 18063528170754288445, 5055621810414119599,
	13184200618203012855, 12870668745267047349, 593761430425656181,   12197787123965983715,
	2687280076053376135,  13027276689633816385, 7598827318020356017,  8448127222929102221,
	15327344770901469655, 17294565156126755738, 7305901863671251226,  11416470854333715084,
	10550394047133782533, 16399333369807373879, 4844870457154301380,  2515222276175828411,
	14209088380384843304, 5660705643183798824,  17960059951134687931, 10011336031056684815,
	15810135761024998125, 12505983644094355854, 9100642380640208415,  17038989167223956982,
	11435629855218111582, 1018459713353833009,  18128595620713100082, 1663236497467796799,
	9174713712781629260,  14118687257146367734, 17972705482042434230, 13695300546863929828,
	1444237490018004928,  7603065021894239658,  9708201859453948830,  13969744543312565095,
	292250057992509161,   5864497572136578851,  5174414430749013421,  13194205235872290622,
	1212481257571826448,  5689829545962252119,  4935381633437450756,  9803536125473198798,
	3118364875584683868,  5158490493707341373,  15236642369968695550, 3693478565354060249,
	13753186792343734813, 16058248420571536912, 14033866203642524777, 10293556585259297604,
	16898947832675240507, 5327455751310573764,  8202957859952673379,  18394148686475874808,
	17627520348572014997, 414519400483960399,   10769903209765346120, 12222872451010722469,
	12818379224486084618, 7573040240940498853,  5243993472102175364,  15180508486366064983,
	10242018403894357980, 2153372195019276565,  12763481861845331548, 12708993932863755369,
	10764735630821077556, 904612932427805567,   9801647049909843517,  7957474081208426825,
	5765604485332676942,  14729083418846494920, 830452770978320356,   11354800595218639836,
	899260586259714603,   15429675403301577292, 10496860887328598333, 4203228982916823807,
	9791757134092161687,  3029131389392024605,  11546370688303851340, 13781788460936042964,
	281882791968007932,   15593583275207022986, 2280958894929997246,  1977999620051069359,
	2002705052216669083,  14737925579423702270, 5135423129188010317,  14919222425590295368,
	3120027545815988347,  806207072747526349,   17107490448498212535, 11488475939410677755,
	13990081182835961536, 288031854186869270,   11318244406266944863, 7922523588561059719,
	6725964415166504184,  2787058774091856195,  18059489032727326824, 2415806423219208279,
	1503465442064152742,  5960093828400113817,  14098604327099972249, 1062298971380311813,
	16803029094552945537, 13941150341585716235, 2923287545418460623,  9686295867900050156,
	1335767853826073877,  11029821270889289955, 11873469125576994325, 8396051246504565766,
	17655531459137967299, 18367900294440167045, 17413906763396884320, 17634280528286958383,
	7022963565307479587,  1000212534356543161,  16554989381358804984, 12984233191040675634,
	1755810645654909056,  3649099671889684651,  7990569194913431334,  813595222033450987,
	7607633444539233554,  18142286008736915760, 9344242349837795190,  7922971576656846261,
	9235729328393979746,  4327559433624705713,  17640268632867562731, 3038707588293148455,
	4197538793810517099,  12862393732710998693, 4431990953677964443,  6948029576332736378,
	10909782343348292244, 517490876774861318,   5554634407439135476,  12726136891022135881,
};

static char8 g_data_name_buf[32768];

static u32 g_data_name_chars;

static minos::FileHandle g_data_file;

static u64 g_data_curr_offset;

static u64 g_bytes_start_offset;

static ChunkMultiMap g_chunks;

static ReservedVec g_index;

static ReservedVec g_names;



// Statistics
static u64 g_uncompressed_chunk_count = 0;

static u64 g_uncompressed_bytes = 0;

static u64 g_compressed_bytes = 0;

static u64 g_input_files_count = 0;



static Chunk next_chunk_boundary(u32 offset, u32 end, bool is_last) noexcept
{
	if (end < offset + MIN_CHUNK_SIZE && !is_last)
		return { 0, 0 };

	const u32 gear_hash_prestart = offset + MIN_CHUNK_SIZE - 64 < end ? offset + MIN_CHUNK_SIZE - 64 : end;

	const u32 gear_hash_start  = offset + MIN_CHUNK_SIZE < end ? offset + MIN_CHUNK_SIZE : end;

	const u32 gear_hash_end = offset + MAX_CHUNK_SIZE < end ? offset + MAX_CHUNK_SIZE : end;

	u32 fnv1a = 0x811C'9DC5;

	for (u32 i = offset; i != gear_hash_prestart; ++i)
		fnv1a = (fnv1a ^ g_read_buf[i]) * 0x010'00193;

	u64 gear_hash = 0;

	for (u32 i = gear_hash_prestart; i != gear_hash_start; ++i)
	{
		fnv1a = (fnv1a ^ g_read_buf[i]) * 0x010'00193;

		gear_hash = (gear_hash << 1) + GEAR_HASH_LUT[g_read_buf[i]];
	}

	for (u32 i = gear_hash_start; i != gear_hash_end; ++i)
	{
		fnv1a = (fnv1a ^ g_read_buf[i]) * 0x010'00193;

		gear_hash = (gear_hash << 1) + GEAR_HASH_LUT[g_read_buf[i]];

		if ((gear_hash & ZERO_MASK) == 0)
			return { i + 1, fnv1a };
	}

	return { is_last || gear_hash_end == offset + MAX_CHUNK_SIZE ? gear_hash_end : 0, fnv1a };
}

static bool chunks_match(Range<byte> new_chunk, u64 existing_chunk_offset) noexcept
{
	byte readback_buf[MAX_CHUNK_SIZE];

	ASSERT_OR_IGNORE(new_chunk.count() <= array_count(readback_buf));

	minos::Overlapped overlapped{};
	overlapped.offset = existing_chunk_offset;

	if (!minos::file_read(g_data_file, readback_buf, static_cast<u32>(new_chunk.count()), &overlapped))
		panic("Failed to read back %llu bytes from output file '%.*s' at offset %llu (0x%X)\n", new_chunk.count(), g_data_name_chars, g_data_name_buf, existing_chunk_offset, minos::last_error());

	return memcmp(readback_buf, new_chunk.begin(), new_chunk.count()) == 0;
}

static u32 chunk_data(u32 end, bool is_last) noexcept
{
	u32 chunk_begin = 0;

	while (true)
	{
		Chunk chunk = next_chunk_boundary(chunk_begin, end, is_last);

		ASSERT_OR_IGNORE(!(chunk.end == 0 && is_last));

		if (chunk.end == 0)
			return chunk_begin;

		g_uncompressed_chunk_count += 1;

		KnownChunk* cc = g_chunks.insert(chunk.fnv1a, static_cast<u16>(chunk.end - chunk_begin));

		while (cc->next != ~0u)
		{
			ASSERT_OR_IGNORE(cc->offset != 0);

			if (chunks_match(Range{ g_read_buf + chunk_begin, chunk.end - chunk_begin }, cc->offset))
				goto CHUNK_EXISTS;

			cc = g_chunks.next(cc);
		}

		if (cc->offset != INVALID_CHUNK_LENGTH)
		{
			if (chunks_match(Range{ g_read_buf + chunk_begin, chunk.end - chunk_begin }, cc->offset))
				goto CHUNK_EXISTS;

			cc = g_chunks.append_new_chunk(cc);
		}

		ASSERT_OR_IGNORE(g_data_curr_offset < (1ui64 << 48));

		ASSERT_OR_IGNORE(chunk.end > chunk_begin);

		{
			minos::Overlapped overlapped{};
			overlapped.offset = g_data_curr_offset;
			cc->offset = g_data_curr_offset;

			if (!minos::file_write(g_data_file, g_read_buf + chunk_begin, chunk.end - chunk_begin, &overlapped))
				panic("Failed to write %u bytes to output file '%.*s' at offset %llu\n", chunk.end - chunk_begin, g_data_name_chars, g_data_name_buf, g_data_curr_offset);
		}

		IndexChunk* const index_chunk = static_cast<IndexChunk*>(g_index.reserve(sizeof(IndexChunk)));
		index_chunk->fnv1a = chunk.fnv1a;
		index_chunk->offset_lo = static_cast<u32>(g_data_curr_offset);
		index_chunk->offset_hi = static_cast<u16>(g_data_curr_offset >> 32);
		index_chunk->length = static_cast<u16>(chunk.end - chunk_begin);

		g_data_curr_offset += chunk.end - chunk_begin;

		g_compressed_bytes += chunk.end - chunk_begin;

	CHUNK_EXISTS:

		ChunkName* const persisted_name = static_cast<ChunkName*>(g_names.reserve(sizeof(ChunkName)));
		persisted_name->tag = NameTag::Chunk;
		persisted_name->length = static_cast<u16>(chunk.end - chunk_begin);
		persisted_name->fnv1a = chunk.fnv1a;
		persisted_name->offset_lo = static_cast<u32>(cc->offset);
		persisted_name->offset_hi = static_cast<u32>(cc->offset >> 32);

		if (chunk.end == end)
			return end;

		chunk_begin = chunk.end;
	}
}

static bool is_ignored_filename() noexcept
{
	return g_curr_path_chars == g_data_name_chars && memcmp(g_curr_path_buf, g_data_name_buf, g_curr_path_chars) == 0;
}

static void pack_file(Range<char8> name) noexcept
{
	if (is_ignored_filename())
		return;

	ASSERT_OR_IGNORE(name.count() <= UINT16_MAX);

	minos::FileHandle file;

	if (!minos::file_create(Range{ g_curr_path_buf, g_curr_path_chars }, minos::Access::Read, minos::CreateMode::Open, minos::AccessPattern::Sequential, minos::SyncMode::Synchronous, false, &file))
		panic("Could not open file '%.*s' (0x%X)\n", g_curr_path_chars, g_curr_path_buf, minos::last_error());

	minos::FileInfo info;

	if (!minos::file_get_info(file, &info))
		panic("Could not get info on file '%.*s' (0x%X)\n", g_curr_path_chars, g_curr_path_buf, minos::last_error());

	FileName* const persisted_name = static_cast<FileName*>(g_names.reserve(static_cast<u32>((sizeof(FileName) + name.count() + 3) & ~3)));
	persisted_name->tag = NameTag::File;
	persisted_name->name_length = static_cast<u16>(name.count());
	persisted_name->creation_time = info.creation_time;
	persisted_name->modified_time = info.modified_time;
	persisted_name->last_access_time = info.last_access_time;
	memcpy(persisted_name->name, name.begin(), name.count());

	g_input_files_count += 1;

	g_uncompressed_bytes += info.bytes;

	if ((g_input_files_count & 0x3FF) == 0)
		fprintf(stdout, "Processed %llu files (%llu bytes in %llu chunks)\n", g_input_files_count, g_uncompressed_bytes, g_uncompressed_chunk_count);

	u64 remaining_bytes = info.bytes;

	bool is_last = false;

	u32 buffer_offset = 0;

	u64 file_offset = 0;

	while (!is_last)
	{
		is_last = remaining_bytes <= READ_BUFFER_BYTES - buffer_offset;

		const u32 bytes_to_read = static_cast<u32>(is_last ? remaining_bytes : READ_BUFFER_BYTES - buffer_offset);

		if (bytes_to_read != 0)
		{
			minos::Overlapped overlapped{};
			overlapped.offset = file_offset;

			if (!minos::file_read(file, g_read_buf + buffer_offset, bytes_to_read, &overlapped))
				panic("Could not read from file '%.*s' at offset %llu (0x%X)\n", g_curr_path_chars, g_curr_path_buf, overlapped.offset, minos::last_error());
		}
		else if (buffer_offset == 0)
		{
			break;
		}

		const u32 last_chunk_end = chunk_data(bytes_to_read + buffer_offset, is_last);

		file_offset += bytes_to_read;

		remaining_bytes -= bytes_to_read;

		buffer_offset = buffer_offset + bytes_to_read - last_chunk_end;

		ASSERT_OR_IGNORE(!(is_last && buffer_offset != 0));

		memmove(g_read_buf, g_read_buf + last_chunk_end, buffer_offset);
	}

	minos::file_close(file);
}

static void pack_directory(Range<char8> name) noexcept
{
	ASSERT_OR_IGNORE(name.count() <= UINT16_MAX);

	DirectoryName* const persisted_name = static_cast<DirectoryName*>(g_names.reserve(static_cast<u32>((sizeof(DirectoryName) + name.count() + 3) & ~3)));
	persisted_name->tag = NameTag::Directory;
	persisted_name->name_length = static_cast<u16>(name.count());
	memcpy(persisted_name->name, name.begin(), name.count());

	minos::DirectoryEnumerationHandle enumeration;

	minos::DirectoryEnumerationResult result;

	minos::DirectoryEnumerationStatus s = minos::directory_enumeration_create(Range{ g_curr_path_buf, g_curr_path_chars }, &enumeration, &result);

	while (s == minos::DirectoryEnumerationStatus::Ok)
	{
		const Range<char8> child_name = range::from_cstring(result.filename);

		if (g_curr_path_chars + 1 + child_name.count() > array_count(g_curr_path_buf))
			panic("Maximum name length %u exceeded\n", array_count(g_curr_path_buf));

		g_curr_path_buf[g_curr_path_chars] = '\\';

		memcpy(g_curr_path_buf + g_curr_path_chars + 1, child_name.begin(), child_name.count());

		g_curr_path_chars += 1 + static_cast<u32>(child_name.count());

		if (result.is_directory)
			pack_directory(child_name);
		else
			pack_file(child_name);

		g_curr_path_chars -= 1 + static_cast<u32>(child_name.count());

		s = minos::directory_enumeration_next(enumeration, &result);
	}

	minos::directory_enumeration_close(enumeration);

	if (s == minos::DirectoryEnumerationStatus::Error)
		panic("Could not enumerate contents of '%.*s' (0x%X)\n", g_curr_path_chars, g_curr_path_buf, minos::last_error());

	DirectoryEndName* const end = static_cast<DirectoryEndName*>(g_names.reserve((sizeof(DirectoryEndName) + 3) & ~3));

	end->tag = NameTag::DirectoryEnd;
}

static void write_names_file(Range<char8> path) noexcept
{
	minos::FileHandle names_file;

	if (!minos::file_create(path, minos::Access::Write, minos::CreateMode::Recreate, minos::AccessPattern::Sequential, minos::SyncMode::Synchronous, false, &names_file))
		panic("Could not open names-file '%.*s' (0x%X)\n", static_cast<u32>(path.count()), path.begin(), minos::last_error());

	minos::Overlapped overlapped{};

	if (!minos::file_write(names_file, g_names.begin(), g_names.used(), &overlapped))
		panic("Could not write %u bytes to names-file '%.*s' (0x%X)\n", g_names.used(), static_cast<u32>(path.count()), path.begin(), minos::last_error());

	minos::file_close(names_file);
}

static void prime_data_file(Range<char8> path) noexcept
{
	if (!minos::path_to_absolute(path, MutRange{ g_data_name_buf }, &g_data_name_chars))
		panic("Could not convert destination prefix '%.*s' to absolute path (0x%X)\n", static_cast<u32>(path.count()), path.begin(), minos::last_error());

	if (!minos::file_create(path, minos::Access::ReadWrite, minos::CreateMode::OpenOrCreate, minos::AccessPattern::RandomAccess, minos::SyncMode::Synchronous, false, &g_data_file))
		panic("Could not open output bytes-file '%.*s' (0x%X)\n", static_cast<u32>(path.count()), path.begin(), minos::last_error());

	minos::FileInfo info;

	if (!minos::file_get_info(g_data_file, &info))
		panic("Could not get info on bytes-file '%.*s' (0x%X)\n", static_cast<u32>(path.count()), path.begin(), minos::last_error());

	u64 file_bytes = info.bytes;

	if (file_bytes != 0)
	{
		if (file_bytes < sizeof(u64))
			panic("Output file '%.*s' has unexpected length %llu. Expected either 0 or at least 8 bytes\n", static_cast<u32>(path.count()), path.begin(), file_bytes);

		u64 valid_bytes;

		minos::Overlapped overlapped{};

		if (!minos::file_read(g_data_file, &valid_bytes, sizeof(valid_bytes), &overlapped))
			panic("Could not read %u bytes from '%.*s' at offset 0 (0x%X)\n", sizeof(valid_bytes), static_cast<u32>(path.count()), path.begin(), minos::last_error());

		if (valid_bytes > file_bytes)
		{
			panic("Valid length %llu declared in file '%.*s' is greater than the file's actual length %llu\n", valid_bytes, static_cast<u32>(path.count()), path.begin(), file_bytes);
		}
		else if (valid_bytes < file_bytes)
		{
			fprintf(stderr, "Valid length %llu declared in file '%.*s' is less than the file's actual length %llu. Truncating file down to declared valid length\n", valid_bytes, static_cast<u32>(path.count()), path.begin(), file_bytes);

			if (!minos::file_resize(g_data_file, valid_bytes))
				panic("Could not truncate file '%.*s' to %llu bytes (0x%X)\n", static_cast<u32>(path.count()), path.begin(), valid_bytes, minos::last_error());
		}

		file_bytes = valid_bytes;
	}
	
	if (file_bytes == 0)
	{
		u64 valid_bytes = 0;

		minos::Overlapped overlapped{};

		if (!minos::file_write(g_data_file, &valid_bytes, sizeof(valid_bytes), &overlapped))
			panic("Could not write %u bytes to file '%.*s' at offset 0 (0x%X)\n", sizeof(valid_bytes), static_cast<u32>(path.count()), path.begin(), minos::last_error());

		file_bytes = 8;
	}
	

	g_data_curr_offset = file_bytes;

	g_bytes_start_offset = file_bytes;
}

static void prime_chunks_map() noexcept
{
	u64 offset = sizeof(u64);

	while (offset < g_bytes_start_offset)
	{
		SectionHeader header;

		minos::Overlapped header_overlapped{};
		header_overlapped.offset = offset;

		if (!minos::file_read(g_data_file, &header, sizeof(header), &header_overlapped))
			panic("Failed to read back %llu bytes of section header from output file '%.*s' at offset %llu (0x%X)\n", sizeof(SectionHeader), g_data_name_chars, g_data_name_buf, offset, minos::last_error());

		if (memcmp(header.magic, SECTION_HEADER_INDEX_MAGIC, sizeof(header.magic)) == 0)
		{
			if (header.length % sizeof(IndexChunk) != 0)
				panic("Length field of index section header in output file '%.*s' at offset %llu has invalid value %llu (Expected to be a multiple of %u)\n", g_data_name_chars, g_data_name_buf, offset, sizeof(IndexChunk));

			if (header.length == 0)
				panic("Length field of index section header in output file '%.*s' at offset %llu has an invalid value of 0\n", g_data_name_chars, g_data_name_buf, offset, header.length, sizeof(IndexChunk));

			static constexpr u32 MAX_READ_COUNT = sizeof(g_read_buf) / sizeof(IndexChunk);

			ASSERT_OR_IGNORE(header.length <= UINT32_MAX);

			u32 remaining_count = static_cast<u32>(header.length) / sizeof(IndexChunk);

			u64 read_offset = offset + sizeof(SectionHeader);

			while (remaining_count != 0)
			{
				const u32 read_count = remaining_count < MAX_READ_COUNT ? remaining_count : MAX_READ_COUNT;

				minos::Overlapped index_overlapped{};
				index_overlapped.offset = read_offset;

				if (!minos::file_read(g_data_file, g_read_buf, read_count * sizeof(IndexChunk), &index_overlapped))
					panic("Failed to read back %llu bytes of index data from output file '%.*s' at offset %llu (0x%X)\n", sizeof(SectionHeader), g_data_name_chars, g_data_name_buf, offset, minos::last_error());

				for (u32 i = 0; i != read_count; ++i)
				{
					const IndexChunk* const chunk = reinterpret_cast<IndexChunk*>(g_read_buf + i * sizeof(IndexChunk));

					KnownChunk* cc = g_chunks.insert(chunk->fnv1a, chunk->length);

					if (cc->next != ~0u)
						cc = g_chunks.append_new_chunk(cc);

					cc->offset = chunk->offset_lo | (static_cast<u64>(chunk->offset_hi) << 32);
				}

				read_offset += read_count * sizeof(IndexChunk);

				remaining_count -= read_count;
			}
		}
		else if (memcmp(header.magic, SECTION_HEADER_BYTES_MAGIC, sizeof(header.magic)) != 0)
		{
			panic("Magic field of section header in output file '%.*s' at offset %llu has an unrecognized value (%llX)\n", g_data_name_chars, g_data_name_buf, offset, *reinterpret_cast<u64*>(header.magic));
		}
		
		offset += static_cast<u32>(sizeof(SectionHeader) + header.length);
	}

	if (offset != g_bytes_start_offset)
		panic("Last section header length in output file '%.*s' overshot remaining file length by %llu bytes\n", g_data_name_chars, g_data_name_buf, offset - g_bytes_start_offset);
}

static void create_data_file_header() noexcept
{
	SectionHeader header{};

	minos::Overlapped overlapped{};
	overlapped.offset = g_data_curr_offset;

	if (!minos::file_write(g_data_file, &header, sizeof(header), &overlapped))
		panic("Could not write %u bytes to bytes-file '%.*s' at offset %llu (0x%X)\n", sizeof(header), g_data_name_chars, g_data_name_buf, g_data_curr_offset, minos::last_error());

	g_data_curr_offset += sizeof(header);
}

static void complete_data_file() noexcept
{
	if (g_bytes_start_offset + sizeof(SectionHeader) == g_data_curr_offset)
	{
		ASSERT_OR_IGNORE(g_index.used() == sizeof(SectionHeader));

		g_data_curr_offset = g_bytes_start_offset;

		if (!minos::file_resize(g_data_file, g_data_curr_offset))
			panic("Could not truncate bytes-file '%.*s' to %llu bytes (0x%X)\n", g_data_name_chars, g_data_name_buf, g_data_curr_offset, minos::last_error());

		return;
	}

	ASSERT_OR_IGNORE(g_index.used() != sizeof(SectionHeader));

	SectionHeader bytes_header;
	memcpy(bytes_header.magic, SECTION_HEADER_BYTES_MAGIC, sizeof(bytes_header.magic));
	bytes_header.length = g_data_curr_offset - g_bytes_start_offset - sizeof(SectionHeader);

	minos::Overlapped bytes_overlapped{};
	bytes_overlapped.offset = g_bytes_start_offset;

	if (!minos::file_write(g_data_file, &bytes_header, sizeof(bytes_header), &bytes_overlapped))
		panic("Could not write %u bytes to bytes-file '%.*s' at offset %llu (0x%X)\n", sizeof(bytes_header), g_data_name_chars, g_data_name_buf, g_bytes_start_offset, minos::last_error());
		
	SectionHeader* const index_header = reinterpret_cast<SectionHeader*>(g_index.begin());
	memcpy(index_header->magic, SECTION_HEADER_INDEX_MAGIC, sizeof(index_header->magic));
	index_header->length = g_index.used() - sizeof(SectionHeader);

	minos::Overlapped index_overlapped{};
	index_overlapped.offset = g_data_curr_offset;

	if (!minos::file_write(g_data_file, g_index.begin(), g_index.used(), &index_overlapped))
		panic("Could not write %u bytes to bytes-file '%.*s' at offset %llu (0x%X)\n", g_index.used(), g_data_name_chars, g_data_name_buf, g_data_curr_offset, minos::last_error());

	g_data_curr_offset += g_index.used();

	minos::Overlapped valid_bytes_overlapped{};

	if (!minos::file_write(g_data_file, &g_data_curr_offset, sizeof(g_data_curr_offset), &valid_bytes_overlapped))
		panic("Could not write %u bytes to '%.*s' at offset 0 (0x%X)\n", sizeof(g_data_curr_offset), g_data_name_chars, g_data_name_buf, minos::last_error());
}

static Range<char8> path_get_leaf() noexcept
{
	u32 last_path_elem_offset = g_curr_path_chars - 1;

	while (last_path_elem_offset != 0 && g_curr_path_buf[last_path_elem_offset] != '\\' && g_curr_path_buf[last_path_elem_offset] != '/')
		last_path_elem_offset -= 1;

	if (g_curr_path_buf[last_path_elem_offset] == '\\' || g_curr_path_buf[last_path_elem_offset] == '/')
		last_path_elem_offset += 1;

	return { g_curr_path_buf + last_path_elem_offset, g_curr_path_chars - last_path_elem_offset };
}

static void pack(Range<char8> source_path, Range<char8> names_path, Range<char8> data_path) noexcept
{
	g_chunks.init(1 << 28, 1 << 18, 1 << 27, 1 << 20, 1 << 20);

	g_names.init(1 << 28, 1 << 18);

	g_index.init(1 << 28, 1 << 18);

	g_index.reserve(sizeof(SectionHeader));

	if (!minos::path_to_absolute(source_path, MutRange{ g_curr_path_buf }, &g_curr_path_chars))
		panic("Could not convert source path '%.*s' to absolute path (0x%X)\n", static_cast<u32>(source_path.count()), source_path.begin(), minos::last_error());

	prime_data_file(data_path);

	prime_chunks_map();

	create_data_file_header();

	const Range<char8> name{ g_curr_path_buf, g_curr_path_chars };

	if (minos::path_is_directory(name))
		pack_directory(path_get_leaf());
	else
		pack_file(path_get_leaf());

	complete_data_file();

	minos::file_close(g_data_file);

	write_names_file(names_path);

	fprintf(stdout, "Compressed %llu files containing %llu bytes down to %llu, reducing %llu chunks down to %llu\n", g_input_files_count, g_uncompressed_bytes, g_compressed_bytes, g_uncompressed_chunk_count, (g_index.used() - sizeof(SectionHeader)) / sizeof(IndexChunk));
}

static __declspec(noreturn) void print_pack_usage(const char8* program_name) noexcept
{
	panic("Usage: %s " PACK_HELP "\n", program_name);
}

void pack_with_args(Range<Range<char8>> args) noexcept
{
	Range<char8> source_path{};

	Range<char8> data_path{};

	Range<char8> names_path{};

	for (uint i = 2; i != args.count(); ++i)
	{
		if (strcmp(args[i].begin(), "-src") == 0)
		{				
			if (i + 1 == args.count())
			{
				fprintf(stderr, "pack: Parameter '-src' supplied to pack is missing an argument\n");

				print_pack_usage(args[0].begin());
			}

			if (source_path.begin() != 0)
			{
				fprintf(stderr, "pack: Parameter '-src' supplied more than once\n");

				print_pack_usage(args[0].begin());
			}

			source_path = args[i + 1];

			i += 1;
		}
		else if (strcmp(args[i].begin(), "-data") == 0)
		{
			if (i + 1 == args.count())
			{
				fprintf(stderr, "pack: Parameter '-data' supplied to pack is missing an argument\n");

				print_pack_usage(args[0].begin());
			}

			if (data_path.begin() != 0)
			{
				fprintf(stderr, "pack: Parameter '-data' supplied more than once\n");

				print_pack_usage(args[0].begin());
			}

			data_path = args[i + 1];

			i += 1;
		}
		else if (strcmp(args[i].begin(), "-names") == 0)
		{
			if (i + 1 == args.count())
			{
				fprintf(stderr, "pack: Parameter '-names' supplied to pack is missing an argument\n");

				print_pack_usage(args[0].begin());
			}

			if (names_path.begin() != 0)
			{
				fprintf(stderr, "pack: Parameter '-names' supplied more than once\n");

				print_pack_usage(args[0].begin());
			}

			names_path = args[i + 1];

			i += 1;
		}
		else
		{
			fprintf(stderr, "pack: Unexpected parameter '%s'\n", args[i].begin());

			print_pack_usage(args[0].begin());
		}
	}

	if (source_path.begin() == nullptr)
		source_path = range::from_literal_string(".");

	if (names_path.begin() == nullptr)
	{
		fprintf(stderr, "pack: Missing parameter '-names'\n");

		print_pack_usage(args[0].begin());
	}

	if (data_path.begin() == nullptr)
	{
		fprintf(stderr, "pack: Missing parameter '-data'\n");

		print_pack_usage(args[0].begin());
	}

	pack(source_path, names_path, data_path);
}
