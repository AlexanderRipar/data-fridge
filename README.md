# Usage

data-fridge takes a directory, and recursively stores the names and contents of
all its children into two files: One for the contents (data), and one for their
names:

```
fridge pack -src <source-directory> -data <data-file> -names <names-file>
```

The data is divided into chunks using an approach known as Content-Defined
Chunking, with chunks that occur more than once only being stored once.

The generated data-file and names-file can then be unpacked together at a later
stage, recreating the original directory:

```
fridge unpack -dst <destination-directory> -data <data-file> -names <names-file> [-overwrite]
```

Additionally, the data-file can be reused as the base for further compaction
operations, resulting in already present chunks being reused.

This means that taking snapshots of multiple mostly identical directories (or
one directory at multiple points in time) will result in very little overhead
if a shared data-file is used.



# Platforms

data-fridge is currently only (sporadically) tested on Windows 10.
**Do not rely on this as a backup software**
