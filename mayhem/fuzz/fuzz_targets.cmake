# The libFuzzer harness and its standalone reproducer, linked against the application's own object
# library (qelectrotech_objects, every source except main.cpp), as upstream's tests/qttest do.
set(QET_FUZZ_DIR "${CMAKE_CURRENT_LIST_DIR}")
separate_arguments(QET_FUZZ_ENGINE UNIX_COMMAND "$ENV{LIB_FUZZING_ENGINE}")

add_executable(qet_cli_fuzzer "${QET_FUZZ_DIR}/qet_cli_fuzzer.cpp" "${QET_LSAN_OFF_SRC}")
target_link_libraries(qet_cli_fuzzer PRIVATE qelectrotech_objects)
target_link_options(qet_cli_fuzzer PRIVATE ${QET_FUZZ_ENGINE})

add_executable(qet_cli_fuzzer-standalone "${QET_FUZZ_DIR}/qet_cli_fuzzer.cpp" "${QET_LSAN_OFF_SRC}"
               "${QET_STANDALONE_MAIN_OBJ}")
set_source_files_properties("${QET_STANDALONE_MAIN_OBJ}" PROPERTIES EXTERNAL_OBJECT TRUE GENERATED TRUE)
target_link_libraries(qet_cli_fuzzer-standalone PRIVATE qelectrotech_objects)
target_sources(qelectrotech PRIVATE "${QET_LSAN_OFF_SRC}")  # the CLI test.sh runs: no leak reports

# Bundled miniz: mz_zip_mem_read_func computes m_pMem + file_ofs before checking the offset (the copy
# is then 0 bytes), which UBSan's pointer-overflow check reports within seconds on any damaged .qetz
# and would mask every other finding. Only that one check, on that one file, is relaxed; ASan and the
# rest of UBSan stay on and halting.
set_source_files_properties("${CMAKE_SOURCE_DIR}/sources/container/miniz/miniz.c"
  DIRECTORY "${CMAKE_SOURCE_DIR}"
  PROPERTIES COMPILE_OPTIONS "-fno-sanitize=pointer-overflow")

# Bundled LZMA SDK (the .edz 7-Zip reader): on x86 it reads little-endian integers straight from byte
# buffers on purpose (CpuArch.h, MY_CPU_LE_UNALIGN -> GetUi16/32/64), so UBSan's alignment check
# fires on the start header of every valid archive (7zArcIn.c, nextHeaderOffset = GetUi64(header + 12))
# and the qet_edz target could not get past it. Only that one check, on those C files, is relaxed;
# ASan and the rest of UBSan stay on and halting.
file(GLOB QET_FUZZ_LZMA_SOURCES "${CMAKE_SOURCE_DIR}/sources/import/edz/lzma/*.c")
set_source_files_properties(${QET_FUZZ_LZMA_SOURCES}
  DIRECTORY "${CMAKE_SOURCE_DIR}"
  PROPERTIES COMPILE_OPTIONS "-fno-sanitize=alignment")
