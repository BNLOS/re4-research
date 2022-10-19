# re4-research
Various modding tools & research for Resident Evil 4.

* **[IDA 7.7 database](https://github.com/emoose/re4-research/issues/3)** - IDA database for RE4 UHD (Steam) version 1.1.0, with over 80% of in-use functions named, and a lot of structures/classes added.

* **[re4_tweaks/SDK/](https://github.com/nipkownix/re4_tweaks/tree/master/dllmain/SDK)** - C++ headers defining a lot of structs/classes used by the UHD Steam release, check [re4_tweaks/Game.cpp](https://github.com/nipkownix/re4_tweaks/blob/master/dllmain/Game.cpp) for info about finding offsets/addrs (note that IDA database has more structs included, although those are less tested)

* **re4lfs.cpp** - (un)packer for RE4 LFS files, allowing you to compress your modded RE4 data to as little as 5% the size in best case!

* **re4mdt.cs** - allows converting MDT text files used by the game to readable INI files, and can apply updated INIs back on top of the MDT.

* **re4resample.cpp** - tool for extracting & resampling XWB files used by RE4 (resampling low-sample-rate audio to a higher rate should improve any HRTF effects mixed into the audio)

* **re4sym.cpp** - parser for SYM files included with the RE4 GC debug build, allows exporting the SYM as both IDA & Ghidra scripts

* **prodg-rel.py** - IDAPython loader for PS2 "SN ProDG relocatable DLL" files, as used by the RE4 PS2 versions, will automatically name functions with whatever symbols are available in the REL.

* **ProDG-SNR2.bt** - 010 Editor template for PS2 ProDG SNR2/REL files

More tools may be added later on, who knows.

If anything here helped you in some way, maybe consider buying me a coffee at [https://ko-fi.com/emoose](https://ko-fi.com/emoose)
