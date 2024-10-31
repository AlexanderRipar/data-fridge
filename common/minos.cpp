#include "minos.hpp"

#define NOGDICAPMASKS
#define NOVIRTUALKEYCODES
#define NOWINMESSAGES
#define NOWINSTYLES
#define NOSYSMETRICS
#define NOMENUS
#define NOICONS
#define NOKEYSTATES
#define NOSYSCOMMANDS
#define NORASTEROPS
#define NOSHOWWINDOW
#define OEMRESOURCE
#define NOATOM
#define NOCLIPBOARD
#define NOCOLOR
#define NOCTLMGR
#define NODRAWTEXT
#define NOGDI
#define NOKERNEL
#define NOUSER
// #define NONLS
#define NOMB
#define NOMEMMGR
#define NOMETAFILE
#define NOMINMAX
#define NOMSG
#define NOOPENFILE
#define NOSCROLL
#define NOSERVICE
#define NOSOUND
#define NOTEXTMETRIC
#define NOWH
#define NOWINOFFSETS
#define NOCOMM
#define NOKANJI
#define NOHELP
#define NOPROFILER
#define NODEFERWINDOWPOS
#define NOMCX
#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <shellapi.h>
#include <atomic>

std::atomic<HANDLE> g_job;

u32 minos::last_error() noexcept
{
	return GetLastError();
}

void* minos::reserve(u64 bytes) noexcept
{
	return VirtualAlloc(nullptr, bytes, MEM_RESERVE, PAGE_READWRITE);
}

bool minos::commit(void* ptr, u64 bytes) noexcept
{
	return VirtualAlloc(ptr, bytes, MEM_COMMIT, PAGE_READWRITE) != nullptr;
}

void minos::unreserve(void* ptr) noexcept
{
	if (VirtualFree(ptr, 0, MEM_RELEASE) == 0)
		panic("VirtualFree(MEM_RELEASE) failed (0x%X)\n", last_error());
}

void minos::decommit(void* ptr, u64 bytes) noexcept
{
	if (VirtualFree(ptr, bytes, MEM_DECOMMIT) == 0)
		panic("VirtualFree(MEM_DECOMMIT) failed (0x%X)\n", last_error());
}

u32 minos::page_bytes() noexcept
{
	SYSTEM_INFO sysinfo;

	GetSystemInfo(&sysinfo);

	return sysinfo.dwPageSize;
}

void minos::address_wait(void* address, void* undesired, u32 bytes) noexcept
{
	if (!WaitOnAddress(address, undesired, bytes, INFINITE))
		panic("WaitOnAddress failed (0x%X)\n", last_error());
}

bool minos::address_wait_timeout(void* address, void* undesired, u32 bytes, u32 milliseconds) noexcept
{
	if (WaitOnAddress(address, undesired, bytes, milliseconds))
		return true;

	if (GetLastError() != ERROR_TIMEOUT)
		panic("WaitOnAddress failed (0x%X)\n", last_error());

	return false;
}

void minos::address_wake_single(void* address) noexcept
{
	WakeByAddressSingle(address);
}

void minos::address_wake_all(void* address) noexcept
{
	WakeByAddressAll(address);
}

void minos::yield() noexcept
{
	YieldProcessor();
}

__declspec(noreturn) void minos::exit_process(u32 exit_code) noexcept
{
	ExitProcess(exit_code);
}

u32 minos::logical_processor_count() noexcept
{
	SYSTEM_INFO si;

	GetSystemInfo(&si);

	return si.dwNumberOfProcessors;
}

bool minos::thread_create(thread_proc proc, void* param, Range<char8> thread_name, ThreadHandle* opt_out) noexcept
{
	static constexpr u32 MAX_THREAD_NAME_CHARS = 255;

	if (opt_out != nullptr)
		opt_out->m_rep = nullptr;

	if (thread_name.count() > MAX_THREAD_NAME_CHARS)
		panic("Thread name with length %llu bytes exceeds maximum supported length of %u bytes: %.*s\n", thread_name.count(), MAX_THREAD_NAME_CHARS, static_cast<u32>(thread_name.count()), thread_name.begin());

	ThreadHandle handle = { CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(proc), param, 0, nullptr) };

	if (handle.m_rep == nullptr)
		return false;

	if (thread_name.count() != 0)
	{
		char16 buf[MAX_THREAD_NAME_CHARS * 2 + 1];

		s32 chars = MultiByteToWideChar(CP_UTF8, 0, thread_name.begin(), static_cast<s32>(thread_name.count()), buf, static_cast<s32>(array_count(buf) - 1));

		if (chars == 0)
		{
			thread_close(handle);

			return false;
		}

		buf[chars] = '\0';

		if (FAILED(SetThreadDescription(handle.m_rep, buf)))
		{
			thread_close(handle);

			return false;
		}
	}

	if (opt_out != nullptr)
		*opt_out = handle;
	else
		thread_close(handle);

	return true;
}

void minos::thread_close(ThreadHandle handle) noexcept
{
	if (!CloseHandle(handle.m_rep))
		panic("CloseHandle(ThreadHandle) failed (0x%X)\n", last_error());
}

bool minos::file_create(Range<char8> filepath, Access access, CreateMode createmode, AccessPattern pattern, SyncMode syncmode, bool inheritable, FileHandle* out) noexcept
{
	char16 filepath_utf16[8192];

	const s32 filepath_utf16_chars = MultiByteToWideChar(CP_UTF8, 0, filepath.begin(), static_cast<s32>(filepath.count()), filepath_utf16, static_cast<s32>(array_count(filepath_utf16) - 1));

	if (filepath_utf16_chars == 0)
		return false;

	filepath_utf16[filepath_utf16_chars] = '\0';

	DWORD native_access;

	switch (access)
	{
	case Access::Read:
		native_access = GENERIC_READ;
		break;

	case Access::Write:
		native_access = GENERIC_WRITE;
		break;

	case Access::ReadWrite:
		native_access = GENERIC_READ | GENERIC_WRITE;
		break;

	case Access::Execute:
		native_access = GENERIC_EXECUTE;
		break;

	default:
		ASSERT_UNREACHABLE;
	}

	DWORD native_createmode;

	DWORD native_flags = FILE_ATTRIBUTE_NORMAL;

	switch (createmode)
	{
	case CreateMode::Open:
		native_createmode = OPEN_EXISTING;
		break;
	
	case CreateMode::Create:
		native_createmode = CREATE_NEW;
		break;

	case CreateMode::OpenOrCreate:
		native_createmode = OPEN_ALWAYS;
		break;

	case CreateMode::Recreate:
		native_createmode = CREATE_ALWAYS;
		break;

	case CreateMode::OpenDirectory:
		native_createmode = OPEN_EXISTING;
		native_flags |= FILE_FLAG_BACKUP_SEMANTICS;
		break;

	default:
		ASSERT_UNREACHABLE;
	}

	switch (pattern)
	{
	case AccessPattern::Sequential:
		native_flags |= FILE_FLAG_SEQUENTIAL_SCAN;
		break;

	case AccessPattern::RandomAccess:
		native_flags |= FILE_FLAG_RANDOM_ACCESS;
		break;

	case AccessPattern::Unbuffered:
		native_flags |= FILE_FLAG_NO_BUFFERING;
		break;
	
	default:
		ASSERT_UNREACHABLE;
	}

	switch (syncmode)
	{
	case SyncMode::Asynchronous:
		native_flags |= FILE_FLAG_OVERLAPPED;
		break;

	case SyncMode::Synchronous:
		break;

	default:
		ASSERT_UNREACHABLE;
	}

	SECURITY_ATTRIBUTES security_attributes{ sizeof(SECURITY_ATTRIBUTES), nullptr, inheritable };

	const HANDLE handle = CreateFileW(filepath_utf16, native_access, FILE_SHARE_READ, &security_attributes, native_createmode, native_flags, nullptr);

	if (handle == INVALID_HANDLE_VALUE)
		return false;

	out->m_rep = handle;

	return true;
}

void minos::file_close(FileHandle handle) noexcept
{
	if (!CloseHandle(handle.m_rep))
		panic("CloseHandle(FileHandle) failed (0x%X)\n", last_error());
}

bool minos::file_read(FileHandle handle, void* buffer, u32 bytes_to_read, Overlapped* overlapped) noexcept
{
	if (ReadFile(handle.m_rep, buffer, bytes_to_read, nullptr, reinterpret_cast<OVERLAPPED*>(overlapped)))
		return true;

	return GetLastError() == ERROR_IO_PENDING;
}

bool minos::file_write(FileHandle handle, const void* buffer, u32 bytes_to_write, Overlapped* overlapped) noexcept
{
	DWORD bytes_written = 0;

	if (WriteFile(handle.m_rep, buffer, bytes_to_write, &bytes_written, reinterpret_cast<OVERLAPPED*>(overlapped)))
		return true;

	return GetLastError() == ERROR_IO_PENDING;
}

bool minos::file_get_info(FileHandle handle, FileInfo* out) noexcept
{
	BY_HANDLE_FILE_INFORMATION info;

	if (!GetFileInformationByHandle(handle.m_rep, &info))
		return false;

	out->identity.volume_serial = info.dwVolumeSerialNumber;
	out->identity.index = info.nFileIndexLow | (static_cast<u64>(info.nFileIndexHigh) << 32);
	out->bytes = info.nFileSizeLow | (static_cast<u64>(info.nFileSizeHigh) << 32);
	out->creation_time = info.ftCreationTime.dwLowDateTime | (static_cast<u64>(info.ftCreationTime.dwHighDateTime) << 32);
	out->modified_time = info.ftLastWriteTime.dwLowDateTime | (static_cast<u64>(info.ftLastWriteTime.dwHighDateTime) << 32);
	out->last_access_time = info.ftLastAccessTime.dwLowDateTime | (static_cast<u64>(info.ftLastAccessTime.dwHighDateTime) << 32);
	out->raw_flags = info.dwFileAttributes;
	out->is_directory = (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

	return true;
}

[[nodiscard]] bool minos::file_resize(FileHandle handle, u64 new_bytes) noexcept
{
	LARGE_INTEGER destination;
	destination.QuadPart = new_bytes;

	if (!SetFilePointerEx(handle.m_rep, destination, nullptr, FILE_BEGIN))
		return false;

	return SetEndOfFile(handle.m_rep);
}

bool minos::overlapped_wait(FileHandle handle, Overlapped* overlapped) noexcept
{
	DWORD bytes;

	return GetOverlappedResult(handle.m_rep, reinterpret_cast<OVERLAPPED*>(overlapped), &bytes, true);
}

bool minos::event_create(bool inheritable, EventHandle* out) noexcept
{
	SECURITY_ATTRIBUTES security_attributes{ sizeof(SECURITY_ATTRIBUTES), nullptr, inheritable };

	const HANDLE event = CreateEventW(&security_attributes, TRUE, FALSE, nullptr);

	if (event == nullptr)
		return false;

	out->m_rep = event;

	return true;
}

void minos::event_close(EventHandle handle) noexcept
{
	if (!CloseHandle(handle.m_rep))
		panic("CloseHandle(EventHandle) failed (0x%X)\n", last_error());
}

void minos::event_wake(EventHandle handle) noexcept
{
	if (!SetEvent(handle.m_rep))
		panic("SetEvent failed (0x%X)\n", last_error());
}

void minos::event_wait(EventHandle handle) noexcept
{
	const u32 wait_result = WaitForSingleObject(handle.m_rep, INFINITE);

	if (wait_result != 0)
		panic("WaitForSingleObject(EventHandle) failed with 0x%X (0x%X)\n", wait_result, last_error());
}

bool minos::event_wait_timeout(EventHandle handle, u32 milliseconds) noexcept
{
	const u32 wait_result = WaitForSingleObject(handle.m_rep, milliseconds);

	if (wait_result == 0)
		return true;
	else if (wait_result == WAIT_TIMEOUT)
		return false;

	panic("WaitForSingleObject(EventHandle, timeout) failed with 0x%X (0x%X)\n", wait_result, last_error());
}

bool minos::completion_create(CompletionHandle* out) noexcept
{
	HANDLE handle = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1);

	if (handle == nullptr)
		return false;

	out->m_rep = handle;

	return true;
}

void minos::completion_close(CompletionHandle handle) noexcept
{
	if (!CloseHandle(handle.m_rep))
		panic("CloseHandle(CompletionHandle) failed (0x%X)\n", last_error());
}

void minos::completion_associate_file(CompletionHandle completion, FileHandle file, u64 key) noexcept
{
	if (CreateIoCompletionPort(file.m_rep, completion.m_rep, key, 0) == nullptr)
		panic("CreateIoCompletionPort failed to associate file (0x%X)\n", last_error());
}

bool minos::completion_wait(CompletionHandle completion, CompletionResult* out) noexcept
{
	if (GetQueuedCompletionStatus(
			completion.m_rep,
			reinterpret_cast<DWORD*>(&out->bytes),
			reinterpret_cast<ULONG_PTR*>(&out->key),
			reinterpret_cast<OVERLAPPED**>(&out->overlapped), INFINITE
	))
		return true;

	return GetLastError() == ERROR_HANDLE_EOF;
}

void minos::sleep(u32 milliseconds) noexcept
{
	Sleep(milliseconds);
}

static bool construct_command_line(MutRange<char16> buffer, Range<char8> exe_path, Range<Range<char8>> command_line) noexcept
{
	u32 index = 0;

	buffer[index++] = '"';

	if (exe_path.count() != 0)
	{
		const u32 exe_path_written = MultiByteToWideChar(CP_UTF8, 0, exe_path.begin(), static_cast<s32>(exe_path.count()), buffer.begin() + index, static_cast<s32>(buffer.count() - index));

		if (exe_path_written == 0)
			return false;

		for (u32 i = 0; i != exe_path_written; ++i)
		{
			if (buffer[index + i] == '/')
				buffer[index + i] = '\\';
		}

		index += exe_path_written;
	}
	else
	{
		SetLastError(ERROR_SUCCESS);

		const u32 exe_path_written = GetModuleFileNameW(nullptr, buffer.begin() + index, static_cast<u32>(buffer.count() - index));

		if (exe_path_written == 0 || GetLastError() == ERROR_INSUFFICIENT_BUFFER)
			return false;

		index += exe_path_written;
	}

		if (index == buffer.count())
			return false;

	buffer[index++] = '"';
	
	for (const Range<char8> argument : command_line)
	{
		if (index + 1 >= buffer.count())
			return false;

		buffer[index++] = ' ';
		buffer[index++] = '"';

		const u32 argument_written = MultiByteToWideChar(CP_UTF8, 0, argument.begin(), static_cast<s32>(argument.count()), buffer.begin() + index, static_cast<s32>(buffer.count() - index));

		if (argument_written == 0)
			return false;

		u32 escape_count = 0;

		for (u32 i = 0; i != argument_written; ++i)
		{
			if (buffer[index + i] == '"')
				escape_count += 1;
		}

		if (escape_count != 0)
		{
			u32 offset = escape_count;

			if (buffer.count() <= index + argument_written + escape_count)
				return false;

			for (u32 i = 0; i != argument_written; ++i)
			{
				const char16 c = buffer[index + argument_written - i - 1];

				buffer[index + argument_written + offset - i - 1] = c;

				if (c == '"')
				{
					offset -= 1;

					buffer[index + argument_written + offset - i - 1] = '\\';
				}
			}
		}

		index += argument_written + escape_count;

		if (index == buffer.count())
			return false;

		buffer[index++] = '"';
	}

	if (index == buffer.count())
		return false;

	buffer[index] = '\0';

	return true;
}

static HANDLE get_global_job_object() noexcept
{
	const HANDLE existing = g_job.load(std::memory_order_relaxed);

	if (existing != nullptr)
		return existing;

	HANDLE created = CreateJobObjectW(nullptr, nullptr);

	if (created == nullptr)
		panic("CreateJobObjectW failed during lazy global job object initialization (0x%X)\n", minos::last_error());

	JOBOBJECT_EXTENDED_LIMIT_INFORMATION limit_info{};
	limit_info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

	if (!SetInformationJobObject(created, JobObjectExtendedLimitInformation, &limit_info, sizeof(limit_info)))
		panic("SetInformationJobObject(JOBOBJECT_EXTENDED_LIMIT_INFORMATION) with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE failed during lazy global job object initialization (0x%X)\n", minos::last_error());

	HANDLE exchanged = nullptr;

	if (g_job.compare_exchange_strong(exchanged, created))
		return created;

	if (!CloseHandle(created))
		panic("CloseHandle(JobHandle) failed during race in lazy global job object initialization (0x%X)\n", minos::last_error());

	return exchanged;
}

bool minos::process_create(Range<char8> exe_path, Range<Range<char8>> command_line, Range<char8> working_directory, Range<GenericHandle> inherited_handles, bool inheritable, ProcessHandle* out) noexcept
{
	static constexpr u64 COMMAND_LINE_CHARS = 32768;

	STARTUPINFOEXW startup_info{};
	startup_info.StartupInfo.cb = sizeof(startup_info);

	u64 proc_thread_attribute_list_bytes = 0;

	if (inherited_handles.count() != 0)
	{
		if (!InitializeProcThreadAttributeList(nullptr, 1, 0, &proc_thread_attribute_list_bytes) && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			return false;
	}

	const u32 working_directory_chars = working_directory.count() == 0 ? 0 : GetCurrentDirectoryW(0, nullptr);

	if (working_directory.count() != 0 && working_directory_chars == 0)
		return false;

	const u64 total_bytes = proc_thread_attribute_list_bytes
	                      + COMMAND_LINE_CHARS * sizeof(char16)
						  + working_directory_chars * sizeof(char16);

	void* const buffer = reserve(total_bytes);

	if (buffer == nullptr)
		return false;

	if (!commit(buffer, total_bytes))
	{
		unreserve(buffer);

		return false;
	}

	char16* const command_line_16 = static_cast<char16*>(buffer);

	char16* const working_directory_16 = working_directory.count() == 0 ? nullptr : command_line_16 + COMMAND_LINE_CHARS;

	LPPROC_THREAD_ATTRIBUTE_LIST const attribute_list = inherited_handles.count() == 0 ? nullptr : reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(command_line_16 + COMMAND_LINE_CHARS + working_directory_chars); 

	if (inherited_handles.count() != 0)
	{
		if (!InitializeProcThreadAttributeList(attribute_list, 1, 0, &proc_thread_attribute_list_bytes))
		{
			unreserve(buffer);
			
			return false;
		}

		if (!UpdateProcThreadAttribute(attribute_list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, const_cast<GenericHandle*>(inherited_handles.begin()), inherited_handles.count() * sizeof(GenericHandle), nullptr, nullptr))
		{
			unreserve(buffer);

			return false;
		}
	}

	if (working_directory.count() != 0)
	{
		if (GetCurrentDirectoryW(working_directory_chars, working_directory_16) != working_directory_chars - 1)
		{
			unreserve(buffer);

			return false;
		}
	}

	if (!construct_command_line({ command_line_16, COMMAND_LINE_CHARS }, exe_path, command_line))
	{
		unreserve(buffer);

		return false;
	}

	SECURITY_ATTRIBUTES security_attributes{ sizeof(SECURITY_ATTRIBUTES), nullptr, inheritable };

	PROCESS_INFORMATION process_info;

	if (!CreateProcessW(nullptr, command_line_16, &security_attributes, nullptr, inherited_handles.count() != 0, CREATE_SUSPENDED, nullptr, working_directory_16, &startup_info.StartupInfo, &process_info))
	{
		unreserve(buffer);

		return false;
	}

	unreserve(buffer);

	if (!AssignProcessToJobObject(get_global_job_object(), process_info.hProcess))
	{
		if (!CloseHandle(process_info.hProcess))
			panic("CloseHandle(ProcessHandle) failed (0x%X)\n", last_error());

		if (!CloseHandle(process_info.hThread))
			panic("CloseHandle(ThreadHandle) failed (0x%X)\n", last_error());

		return false;
	}

	if (ResumeThread(process_info.hThread) == static_cast<DWORD>(-1))
	{
		if (!CloseHandle(process_info.hProcess))
			panic("CloseHandle(ProcessHandle) failed (0x%X)\n", last_error());

		if (!CloseHandle(process_info.hThread))
			panic("CloseHandle(ThreadHandle) failed (0x%X)\n", last_error());

		return false;
	}

	if (!CloseHandle(process_info.hThread))
		panic("CloseHandle(ThreadHandle) failed (0x%X)\n", last_error());

	out->m_rep = process_info.hProcess;

	return true;
}

void minos::process_wait(ProcessHandle handle) noexcept
{
	const u32 wait_result = WaitForSingleObject(handle.m_rep, INFINITE);

	if (wait_result != 0)
		panic("WaitForSingleObject(ProcessHandle) failed with 0x%X (0x%X)\n", wait_result, last_error());
}

bool minos::process_wait_timeout(ProcessHandle handle, u32 milliseconds) noexcept
{
	const u32 wait_result = WaitForSingleObject(handle.m_rep, milliseconds);

	if (wait_result == 0)
		return true;
	else if (wait_result == WAIT_TIMEOUT)
		return false;

	panic("WaitForSingleObject(ProcessHandle, timeout) failed with 0x%X (0x%X)\n", wait_result, last_error());
}

bool minos::process_get_exit_code(ProcessHandle handle, u32* out) noexcept
{
	DWORD exit_code;

	if (!GetExitCodeProcess(handle.m_rep, &exit_code))
		panic("GetExitCodeProcess failed (0x%X)\n", last_error());

	if (exit_code == STATUS_PENDING)
	{
		if (!process_wait_timeout(handle, 0))
			return false;

		if (!GetExitCodeProcess(handle.m_rep, &exit_code))
			panic("GetExitCodeProcess failed (0x%X)\n", last_error());
	}

	*out = exit_code;

	return true;
}

bool minos::shm_create(Access access, u64 bytes, ShmHandle* out) noexcept
{
	u32 native_access;

	switch (access)
	{
	case Access::Read:
		native_access = PAGE_READONLY;
		break;
	
	case Access::Write:
		native_access = PAGE_READWRITE;
		break;

	case Access::ReadWrite:
		native_access = PAGE_READWRITE;
		break;

	case Access::Execute:
		native_access = PAGE_EXECUTE_READ;
		break;

	default:
		ASSERT_UNREACHABLE;
	}

	SECURITY_ATTRIBUTES security_attributes{ sizeof(SECURITY_ATTRIBUTES), nullptr, true };

	const HANDLE handle = CreateFileMappingW(INVALID_HANDLE_VALUE, &security_attributes, native_access | SEC_RESERVE, static_cast<u32>(bytes >> 32), static_cast<u32>(bytes), nullptr);

	if (handle == nullptr)
		return false;

	out->m_rep = handle;

	return true;
}

void minos::shm_close(ShmHandle handle) noexcept
{
	if (!CloseHandle(handle.m_rep))
		panic("CloseHandle(ShmHandle) failed (0x%X)\n", last_error());
}

void* minos::shm_reserve(ShmHandle handle, Access access, u64 offset, u64 bytes) noexcept
{
	u32 native_access;

	switch (access)
	{
	case Access::Read:
	case Access::Execute:
		native_access = FILE_MAP_READ;
		break;

	case Access::Write:
	case Access::ReadWrite:
		native_access = FILE_MAP_WRITE;
		break;

	default:
		ASSERT_UNREACHABLE;
	}

	return MapViewOfFile(handle.m_rep, native_access, static_cast<u32>(offset >> 32), static_cast<u32>(offset), bytes);
}

bool minos::sempahore_create(u32 initial_count, u32 maximum_count, bool inheritable, SemaphoreHandle* out) noexcept
{
	SECURITY_ATTRIBUTES security_attribute{ sizeof(SECURITY_ATTRIBUTES), nullptr, inheritable };

	const HANDLE handle = CreateSemaphoreW(&security_attribute, initial_count, maximum_count, nullptr);

	if (handle == nullptr)
		return false;

	out->m_rep = handle;

	return true;
}

void minos::semaphore_close(SemaphoreHandle handle) noexcept
{
	if (!CloseHandle(handle.m_rep))
		panic("CloseHandle(SemaphoreHandle) failed (0x%X)\n", last_error());
}

void minos::semaphore_post(SemaphoreHandle handle, u32 count) noexcept
{
	if (!ReleaseSemaphore(handle.m_rep, count, nullptr))
		panic("ReleaseSemaphore failed (0x%X)\n", last_error());
}

void minos::semaphore_wait(SemaphoreHandle handle) noexcept
{
	const u32 wait_result = WaitForSingleObject(handle.m_rep, INFINITE);

	if (wait_result != 0)
		panic("WaitForSingleObject(SemaphoreHandle) failed with 0x%X (0x%X)\n", wait_result, last_error());
}

bool minos::semaphore_wait_timeout(SemaphoreHandle handle, u32 milliseconds) noexcept
{
	const u32 wait_result = WaitForSingleObject(handle.m_rep, milliseconds);

	if (wait_result == 0)
		return true;
	else if (wait_result == WAIT_TIMEOUT)
		return false;

	panic("WaitForSingleObject(SemaphoreHandle, timeout) failed with 0x%X (0x%X)\n", wait_result, last_error());
}

static void make_directory_enumeration_result(const WIN32_FIND_DATAW* data, minos::DirectoryEnumerationResult* out) noexcept
{
	out->is_directory = (data->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

	out->creation_time = data->ftCreationTime.dwLowDateTime | (static_cast<u64>(data->ftCreationTime.dwHighDateTime) << 32);

	out->last_access_time = data->ftLastAccessTime.dwLowDateTime | (static_cast<u64>(data->ftLastAccessTime.dwHighDateTime) << 32);

	out->last_write_time = data->ftLastWriteTime.dwLowDateTime | (static_cast<u64>(data->ftLastWriteTime.dwHighDateTime) << 32);

	out->bytes = data->nFileSizeLow | (static_cast<u64>(data->nFileSizeHigh) << 32);

	if (WideCharToMultiByte(CP_UTF8, 0, data->cFileName, -1, out->filename, static_cast<s32>(array_count(out->filename)), nullptr, nullptr) == 0)
		panic("Failed utf-16 to utf-8 conversion with guaranteed-to-be sufficient output buffer size (0x%X)\n", minos::last_error());
}

minos::DirectoryEnumerationStatus minos::directory_enumeration_create(Range<char8> directory_path, DirectoryEnumerationHandle* out, DirectoryEnumerationResult* out_first) noexcept
{
	out->m_rep = nullptr;

	char16 directory_path_utf16[8192];

	const s32 directory_path_utf16_chars = MultiByteToWideChar(CP_UTF8, 0, directory_path.begin(), static_cast<s32>(directory_path.count()), directory_path_utf16, static_cast<s32>(array_count(directory_path_utf16) - 3));

	if (directory_path_utf16_chars == 0)
		return DirectoryEnumerationStatus::Error;

	directory_path_utf16[directory_path_utf16_chars] = '\\';
	directory_path_utf16[directory_path_utf16_chars + 1] = '*';
	directory_path_utf16[directory_path_utf16_chars + 2] = '\0';

	WIN32_FIND_DATAW first;

	const HANDLE handle = FindFirstFileW(directory_path_utf16, &first);

	if (handle == INVALID_HANDLE_VALUE)
		return last_error() == ERROR_FILE_NOT_FOUND ? DirectoryEnumerationStatus::NoMoreFiles : DirectoryEnumerationStatus::Error;

	out->m_rep = handle;

	while (first.cFileName[0] == '.' && (first.cFileName[1] == '\0' || (first.cFileName[1] == '.' && first.cFileName[2] == '\0')))
	{
		if (!FindNextFileW(handle, &first))
			return last_error() == ERROR_NO_MORE_FILES ? DirectoryEnumerationStatus::NoMoreFiles : DirectoryEnumerationStatus::Error;
	}

	make_directory_enumeration_result(&first, out_first);

	return DirectoryEnumerationStatus::Ok;
}

minos::DirectoryEnumerationStatus minos::directory_enumeration_next(DirectoryEnumerationHandle handle, DirectoryEnumerationResult* out) noexcept
{
	WIN32_FIND_DATAW data;

	if (!FindNextFileW(handle.m_rep, &data))
		return last_error() == ERROR_NO_MORE_FILES ? DirectoryEnumerationStatus::NoMoreFiles : DirectoryEnumerationStatus::Error;

	make_directory_enumeration_result(&data, out);

	return DirectoryEnumerationStatus::Ok;
}

void minos::directory_enumeration_close(DirectoryEnumerationHandle handle) noexcept
{
	if (handle.m_rep == nullptr)
		return;

	if (!FindClose(handle.m_rep))
		panic("FindClose failed (0x%X)\n", last_error());
}

bool minos::directory_create(Range<char8> path) noexcept
{
	char16 path_utf16[8192];

	const s32 path_utf16_chars = MultiByteToWideChar(CP_UTF8, 0, path.begin(), static_cast<s32>(path.count()), path_utf16, static_cast<s32>(array_count(path_utf16) - 1));

	if (path_utf16_chars == 0)
		return false;

	path_utf16[path_utf16_chars] = '\0';

	return CreateDirectoryW(path_utf16, nullptr);
}

bool minos::path_is_directory(Range<char8> path) noexcept
{
	char16 path_utf16[8192];

	const s32 path_utf16_chars = MultiByteToWideChar(CP_UTF8, 0, path.begin(), static_cast<s32>(path.count()), path_utf16, static_cast<s32>(array_count(path_utf16) - 1));

	if (path_utf16_chars == 0)
		return false;

	path_utf16[path_utf16_chars] = '\0';

	const u32 attributes = GetFileAttributesW(path_utf16);

	return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

bool minos::path_to_absolute(Range<char8> path, MutRange<char8> out_buf, u32* out_chars) noexcept
{
	char16 rel_path_utf16[8192];

	s32 path_chars = static_cast<s32>(path.count());

	if (path_chars != 0 && path[path_chars - 1] == '\\' || path[path_chars - 1] == '/')
		path_chars -= 1;

	const s32 rel_path_utf16_chars = MultiByteToWideChar(CP_UTF8, 0, path.begin(), path_chars, rel_path_utf16, static_cast<s32>(array_count(rel_path_utf16) - 1));

	if (rel_path_utf16_chars == 0)
		return false;

	rel_path_utf16[rel_path_utf16_chars] = '\0';

	char16 abs_path_utf16[8192];

	const u32 abs_path_utf16_chars = GetFullPathNameW(rel_path_utf16, static_cast<u32>(array_count(abs_path_utf16)), abs_path_utf16, nullptr);

	if (abs_path_utf16_chars == 0 || abs_path_utf16_chars > array_count(abs_path_utf16))
		return false;

	const s32 result_chars = WideCharToMultiByte(CP_UTF8, 0, abs_path_utf16, abs_path_utf16_chars, out_buf.begin(), static_cast<s32>(out_buf.count()), nullptr, nullptr);

	if (result_chars == 0)
		return false;

	*out_chars = result_chars;

	return true;
}

bool minos::path_get_info(Range<char8> path, FileInfo* out) noexcept
{
	char16 path_utf16[8192];

	const s32 path_utf16_chars = MultiByteToWideChar(CP_UTF8, 0, path.begin(), static_cast<s32>(path.count()), path_utf16, static_cast<s32>(array_count(path_utf16) - 1));

	if (path_utf16_chars == 0)
		return false;

	path_utf16[path_utf16_chars] = '\0';

	WIN32_FILE_ATTRIBUTE_DATA info;

	if (!GetFileAttributesExW(path_utf16, GetFileExInfoStandard, &info))
		return false;

	out->identity = {};
	out->bytes = info.nFileSizeLow | (static_cast<u64>(info.nFileSizeHigh) << 32);
	out->creation_time = info.ftCreationTime.dwLowDateTime | (static_cast<u64>(info.ftCreationTime.dwHighDateTime) << 32);
	out->modified_time = info.ftLastWriteTime.dwLowDateTime | (static_cast<u64>(info.ftLastWriteTime.dwHighDateTime) << 32);
	out->last_access_time = info.ftLastAccessTime.dwLowDateTime | (static_cast<u64>(info.ftLastAccessTime.dwHighDateTime) << 32);
	out->raw_flags = info.dwFileAttributes;
	out->is_directory = (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

	return true;
}

u64 minos::timestamp_utc() noexcept
{
	FILETIME filetime;

	GetSystemTimeAsFileTime(&filetime);

	return filetime.dwLowDateTime | (static_cast<u64>(filetime.dwHighDateTime) << 32);
}

u64 minos::timestamp_local() noexcept
{
	FILETIME utc_filetime;

	GetSystemTimeAsFileTime(&utc_filetime);

	FILETIME local_filetime;

	if (!FileTimeToLocalFileTime(&utc_filetime, &local_filetime))
		panic("FileTimeToLocalFileTime failed (0x%X)\n", last_error());

	return local_filetime.dwLowDateTime | (static_cast<u64>(local_filetime.dwHighDateTime) << 32);
}

s64 minos::timestamp_local_offset() noexcept
{
	TIME_ZONE_INFORMATION timezone;

	const u32 mode = GetTimeZoneInformation(&timezone);

	u64 offset_minutes;

	if (mode == TIME_ZONE_ID_UNKNOWN || mode == TIME_ZONE_ID_STANDARD)
		offset_minutes = timezone.Bias + timezone.StandardBias;
	else if (mode == TIME_ZONE_ID_DAYLIGHT)
		offset_minutes = timezone.Bias + timezone.DaylightBias;
	else if (mode == TIME_ZONE_ID_INVALID)
		panic("Could not determine timezone information (0x%X)\n", last_error());
	else
		ASSERT_UNREACHABLE;

	return offset_minutes * 60 * timestamp_ticks_per_second();
}

u64 minos::timestamp_ticks_per_second() noexcept
{
	return 10'000'000ui64;
}

Range<Range<char8>> minos::command_line_get() noexcept
{
	s32 argc;

	char16** argv = CommandLineToArgvW(GetCommandLineW(), &argc);

	if (argv == nullptr)
		panic("CommandLineToArgvW failed (0x%X)\n", last_error());

	u32 required_bytes = sizeof(Range<char8>) * argc;

	for (s32 i = 0; i != argc; ++i)
	{
		const u32 arg_bytes = WideCharToMultiByte(CP_UTF8, 0, argv[i], -1, nullptr, 0, nullptr, nullptr);

		if (arg_bytes == 0)
			panic("WideCharToMultiByte failed (0x%X)\n", last_error());

		required_bytes += arg_bytes;
	}

	Range<char8>* const dst = static_cast<Range<char8>*>(reserve(required_bytes));

	if (dst == nullptr)
		panic("reserve failed (0x%X)\n", last_error());

	if (!commit(dst, required_bytes))
		panic("commit failed (0x%X)\n", last_error());

	u32 dst_arg_offset = sizeof(Range<char8>) * argc;

	char8* const dst_argv = reinterpret_cast<char8*>(dst);

	for (s32 i = 0; i != argc; ++i)
	{
		const u32 arg_bytes = WideCharToMultiByte(CP_UTF8, 0, argv[i], -1, dst_argv + dst_arg_offset, required_bytes - dst_arg_offset, nullptr, nullptr);

		if (arg_bytes == 0)
			panic("WideCharToMultiByte failed (0x%X)\n", last_error());

		dst[i] = Range<char8>{ dst_argv + dst_arg_offset, arg_bytes - 1 };

		dst_arg_offset += arg_bytes;
	}

	LocalFree(argv);

	return Range{ dst, static_cast<uint>(argc) };
}
