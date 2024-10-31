#ifndef DEFINITIONS_INCLUDE_GUARD
#define HELPTEDEFINITIONS_INCLUDE_GUARDXT_INCLUDE_GUARD

#include "common/common.hpp"
#include "common/minos.hpp"

#include <cstdio>
#include <cstring>

#define PACK_HELP "pack -src <source-path> -data <output-data-path> -names <output-names-path>"

#define UNPACK_HELP "unpack -dst <output-path> -data <source-data-path> -names <source-names-path> [-overwrite]"

static constexpr u64 MIN_CHUNK_SIZE = 4096;

static constexpr u64 MAX_CHUNK_SIZE = UINT16_MAX;

static constexpr u64 READ_BUFFER_BYTES = 4194304;

static constexpr u64 ZERO_MASK = 0x0000'D903'0353'0000ui64;

static constexpr u64 INVALID_CHUNK_LENGTH = 0;

static constexpr char8 SECTION_HEADER_BYTES_MAGIC[] = "ch0nk:B;";

static constexpr char8 SECTION_HEADER_INDEX_MAGIC[] = "ch0nk:I;";

struct Chunk
{
	u32 end;

	u32 fnv1a;
};

struct IndexChunk
{
	u32 offset_lo;
	
	u16 offset_hi;

	u16 length;

	u32 fnv1a;
};

struct alignas(16) KnownChunk
{
	u32 hash;

	u32 next;

	u64 offset : 48;

	u64 length : 16;
};

static_assert(sizeof(KnownChunk) == 16);

struct ChunkMultiMap
{
private:

	static constexpr u16 LOOKUP_DISTANCE_BITS = 6;

	static constexpr u16 LOOKUP_DISTANCE_ONE = 1 << (16 - LOOKUP_DISTANCE_BITS);

	static constexpr u16 LOOKUP_DISTANCE_MASK = ((1 << LOOKUP_DISTANCE_BITS) - 1) << (16 - LOOKUP_DISTANCE_BITS);

	static constexpr u16 LOOKUP_HASH_SHIFT = 16 + LOOKUP_DISTANCE_BITS;

	static constexpr u16 LOOKUP_HASH_MASK = static_cast<u16>(~LOOKUP_DISTANCE_MASK);

	u16* m_lookups;

	u32* m_offsets;

	KnownChunk* m_values;

	u32 m_lookup_used;

	u32 m_value_used;

	u32 m_lookup_commit;

	u32 m_value_commit;

	u32 m_lookup_capacity;

	u32 m_value_capacity;

	u32 m_value_commit_increment;

	static bool is_empty_lookup(u16 lookup) noexcept
	{
		return lookup == 0;
	}

	static u16 create_lookup(u32 hash) noexcept
	{
		const u16 lookup = static_cast<u16>(hash >> LOOKUP_HASH_SHIFT);

		return lookup == 0 ? 1 : lookup;
	}

	void ensure_value_capacity() noexcept
	{
		if (m_value_used == m_value_commit)
		{
			if (m_value_used == m_value_capacity)
				panic("Could not insert value into ChunkMultiMap as value storage capacity of %u is exceeded\n", m_value_capacity);

			u32 new_commit = m_value_commit + m_value_commit_increment;

			if (!minos::commit(m_values + m_value_commit, (new_commit - m_value_commit) * sizeof(KnownChunk)))
				panic("Could not commit additional memory for ChunkMultiMap values (0x%X)\n", minos::last_error());

			m_value_commit = new_commit;
		}
	}

	u32 create_value(u32 hash, u16 length) noexcept
	{
		ensure_value_capacity();

		const u32 value_offset = m_value_used;

		KnownChunk* const value = m_values + value_offset;
		value->hash = hash;
		value->length = length;
		value->next = ~0u;
		value->offset = INVALID_CHUNK_LENGTH;

		m_value_used += 1;

		return value_offset;
	}

	void rehash() noexcept
	{
		fprintf(stderr, "Rehashing\n");

		if (m_lookup_commit == m_lookup_capacity)
			panic("Could not rehash ChunkMultiMap lookup as no additional capacity was available\n");

		const u32 lookup_and_offset_bytes = m_lookup_commit * (sizeof(*m_lookups) + sizeof(*m_offsets));

		if (!minos::commit(reinterpret_cast<byte*>(m_lookups) + lookup_and_offset_bytes, lookup_and_offset_bytes))
			panic("Could not commit additional memory for ChunkMultiMap lookups and offsets (0x%X)\n", minos::last_error());

		memset(m_lookups, 0, m_lookup_commit * (sizeof(*m_lookups) + sizeof(*m_offsets)));

		m_lookup_commit *= 2;

		m_offsets = reinterpret_cast<u32*>(m_lookups + m_lookup_commit);

		for (const KnownChunk* curr = m_values; curr != m_values + m_value_used; ++curr)
		{
			if (curr->length != 0)
				reinsert_value_into_lookup(static_cast<u32>(curr - m_values), curr->hash);
		}
	}

	void reinsert_value_into_lookup(u32 offset_to_insert, u32 hash) noexcept
	{
		u32 index = hash & (m_lookup_commit - 1);

		u16 wanted_lookup = create_lookup(hash);

		while (true)
		{
			const u16 curr_lookup = m_lookups[index];

			if (is_empty_lookup(curr_lookup))
			{
				m_lookups[index] = wanted_lookup;

				m_offsets[index] = offset_to_insert;

				return;
			}
			else if ((curr_lookup & LOOKUP_DISTANCE_MASK) < (wanted_lookup & LOOKUP_DISTANCE_MASK))
			{
				const u32 curr_offset = m_offsets[index];

				m_lookups[index] = wanted_lookup;

				m_offsets[index] = offset_to_insert;

				wanted_lookup = curr_lookup;

				offset_to_insert = curr_offset;
			}

			if (index == m_lookup_commit - 1)
				index = 0;
			else
				index += 1;

			if ((wanted_lookup & LOOKUP_DISTANCE_MASK) == LOOKUP_DISTANCE_MASK)
			{
				rehash();

				return;
			}

			wanted_lookup += LOOKUP_DISTANCE_ONE;
		}
	}

public:

	void init(u32 lookup_capacity, u32 lookup_commit, u32 value_capacity, u32 value_commit, u32 value_commit_increment) noexcept
	{
		if (!is_pow2(lookup_capacity))
			panic("Could not create ChunkMultiMap with non-power-of-two lookup capacity %u\n", lookup_capacity);

		if (!is_pow2(lookup_commit))
			panic("Could not create ChunkMultiMap with non-power-of-two initial lookup commit %u\n", lookup_commit);

		if (lookup_commit > lookup_capacity)
			panic("Could not create ChunkMultiMap with initial lookup commit %u greater than lookup capacity %u\n", lookup_commit, lookup_capacity);

		if (value_commit > value_capacity)
			panic("Could not create ChunkMultiMap with initial value commit %u greater than value capacity %u\n", value_commit, value_capacity);

		m_lookups = static_cast<u16*>(minos::reserve(lookup_capacity * (sizeof(*m_lookups) + sizeof(*m_offsets)) + value_capacity * sizeof(KnownChunk)));

		if (m_lookups == nullptr)
			panic("Could not reserve memory for ChunkMultiMap (0x%X)\n", minos::last_error());

		m_offsets = reinterpret_cast<u32*>(m_lookups + lookup_commit);
		
		m_values = reinterpret_cast<KnownChunk*>(reinterpret_cast<byte*>(m_lookups) + lookup_capacity * (sizeof(*m_lookups) + sizeof(*m_offsets)));

		m_lookup_used = 0;

		m_value_used = 0;

		m_lookup_commit = lookup_commit;

		m_value_commit = value_commit;

		m_lookup_capacity = lookup_capacity;

		m_value_capacity = value_capacity;

		m_value_commit_increment = value_commit_increment;

		if (!minos::commit(m_lookups, lookup_commit * (sizeof(*m_lookups) + sizeof(*m_offsets))))
			panic("Could not commit initial memory for ChunkMultiMap lookups and offsets (0x%X)\n", minos::last_error());

		if (!minos::commit(m_values, value_commit * sizeof(KnownChunk)))
			panic("Could not commit initial memory for ChunkMultiMap offsets (0x%X)\n", minos::last_error());
	}

	KnownChunk* insert(u32 hash, u16 length) noexcept
	{
		ASSERT_OR_IGNORE(length != 0);

		if (m_lookup_used * 4 > m_lookup_commit * 3)
			rehash();

		u32 index = hash & (m_lookup_commit - 1);

		u16 wanted_lookup = create_lookup(hash);

		u32 offset_to_insert = 0; // Does not matter; gets overwritten anyways

		u32 new_value_offset = ~0u;

		while (true)
		{
			const u16 curr_lookup = m_lookups[index];

			if (is_empty_lookup(curr_lookup))
			{
				m_lookups[index] = wanted_lookup;

				if (new_value_offset == ~0u)
				{
					new_value_offset = create_value(hash, length);

					offset_to_insert = new_value_offset;
				}

				m_offsets[index] = offset_to_insert;

				m_lookup_used += 1;

				return m_values + new_value_offset;
			}
			else if (curr_lookup == wanted_lookup)
			{
				const u32 existing_value_offset = m_offsets[index];

				KnownChunk* const existing_value = m_values + existing_value_offset;

				if (existing_value->hash == hash && existing_value->length == length)
					return existing_value;
			}
			else if ((curr_lookup & LOOKUP_DISTANCE_MASK) < (wanted_lookup & LOOKUP_DISTANCE_MASK))
			{
				const u32 curr_offset = m_offsets[index];

				m_lookups[index] = wanted_lookup;

				if (new_value_offset == ~0u)
				{
					new_value_offset = create_value(hash, length);

					offset_to_insert = new_value_offset;
				}

				m_offsets[index] = offset_to_insert;

				wanted_lookup = curr_lookup;

				offset_to_insert = curr_offset;
			}

			if (index == m_lookup_commit - 1)
				index = 0;
			else
				index += 1;

			if ((wanted_lookup & LOOKUP_DISTANCE_MASK) == LOOKUP_DISTANCE_MASK)
			{
				rehash();

				return new_value_offset == ~0u ? insert(hash, length) : m_values + new_value_offset;
			}

			wanted_lookup += LOOKUP_DISTANCE_ONE;
		}
	}

	KnownChunk* append_new_chunk(KnownChunk* prev) noexcept
	{
		ensure_value_capacity();

		const u32 old_next = prev->next;

		prev->next = m_value_used;

		KnownChunk* const next = m_values + m_value_used;

		next->next = old_next;

		m_value_used += 1;

		return next;
	}

	KnownChunk* next(KnownChunk* prev) noexcept
	{
		ASSERT_OR_IGNORE(prev->next != ~0u);

		return m_values + prev->next;
	}

	u64 count() const noexcept
	{
		return m_value_used;
	}

	Range<KnownChunk> entries() const noexcept
	{
		return { m_values, m_value_used };
	}
};

struct ReservedVec
{
private:

	byte* m_memory;

	u32 m_used;

	u32 m_committed;

	u32 m_commit_increment;

	u32 m_reserved;

	void ensure_capacity(u32 extra_used) noexcept
	{
		const u64 required_commit = m_used + extra_used;

		if (required_commit <= m_committed)
			return;

		if (required_commit > m_reserved)
			panic("Could not allocate additional memory, as the required memory (%llu bytes) exceeds the reserve of %llu bytes\n", required_commit, m_reserved);

		const u32 new_commit = next_multiple(static_cast<u32>(required_commit), m_commit_increment);

		if (!minos::commit(m_memory + m_committed, (new_commit - m_committed)))
			panic("Could not allocate additional memory (%llu bytes - error 0x%X)\n", (new_commit - m_committed), minos::last_error());

		m_committed = new_commit;
	}

public:

	void init(u32 reserve, u32 commit_increment) noexcept
	{
		m_memory = static_cast<byte*>(minos::reserve(reserve));

		m_used = 0;

		m_committed = commit_increment;

		m_commit_increment = commit_increment;

		m_reserved = reserve;

		ASSERT_OR_IGNORE(reserve >= commit_increment);

		if (m_memory == nullptr)
			panic("Could not reserve memory (%llu bytes - error 0x%X)\n", reserve, minos::last_error());

		if (!minos::commit(m_memory, m_committed))
			panic("Could not commit initial memory (%llu bytes - error 0x%X)\n", m_committed, minos::last_error());
	}

	void* reserve(u32 bytes) noexcept
	{
		ensure_capacity(bytes);

		byte* const result = m_memory + m_used;

		m_used += bytes;

		return result;
	}

	byte* begin() noexcept
	{
		return m_memory;
	}

	const byte* begin() const noexcept
	{
		return m_memory;
	}

	byte* end() noexcept
	{
		return m_memory + m_used;
	}

	const byte* end() const noexcept
	{
		return m_memory + m_used;
	}

	u32 used() const noexcept
	{
		return m_used;
	}

	u32 committed() const noexcept
	{
		return m_committed;
	}

	u32 reserved() const noexcept
	{
		return m_reserved;
	}
};

enum class NameTag : u8
{
	Directory = 1,
	DirectoryEnd = 2,
	File = 3,
	Chunk = 4,
};

struct DirectoryName
{
	NameTag tag;

	u16 name_length;

	#pragma warning(push)
	#pragma warning(disable : 4200) //  warning C4200: nonstandard extension used: zero-sized array in struct/union
	char8 name[];
	#pragma warning(pop)
};

struct DirectoryEndName
{
	NameTag tag;
};

struct FileName
{
	NameTag tag;

	u16 name_length;

	u64 creation_time;

	u64 modified_time;

	u64 last_access_time;

	#pragma warning(push)
	#pragma warning(disable : 4200) //  warning C4200: nonstandard extension used: zero-sized array in struct/union
	char8 name[];
	#pragma warning(pop)
};

struct ChunkName
{
	NameTag tag;

	u16 length;

	u32 fnv1a;

	u32 offset_lo;

	u32 offset_hi;
};

struct SectionHeader
{
	char8 magic[8];

	u64 length;
};

extern char8 g_curr_path_buf[32768];

extern byte g_read_buf[READ_BUFFER_BYTES];

extern u32 g_curr_path_chars;

inline u32 align(u32 n) noexcept
{
	return (n + 3) & ~3;
}

#endif // DEFINITIONS_INCLUDE_GUARD
