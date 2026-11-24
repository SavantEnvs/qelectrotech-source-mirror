# Injected with -DCMAKE_PROJECT_qelectrotech_INCLUDE=<this file> (no upstream file is edited).
# Runs right after upstream's project() call and defers the fuzz-target definitions to the end of
# the top-level CMakeLists.txt, once the qelectrotech_objects library exists. EVAL bakes the path
# in now (a deferred call would otherwise expand CMAKE_CURRENT_LIST_DIR when it runs).
cmake_language(EVAL CODE
  "cmake_language(DEFER DIRECTORY \"${CMAKE_SOURCE_DIR}\" CALL include [[${CMAKE_CURRENT_LIST_DIR}/fuzz_targets.cmake]])")
