cmake_minimum_required(VERSION 3.24)
project(dfc-package-consumer C)

find_package(dfc-core 2 REQUIRED CONFIG)

add_executable(dfc-package-consumer main.c)
target_link_libraries(dfc-package-consumer PRIVATE dfc::dfc)

enable_testing()
add_test(NAME dfc-package-consumer COMMAND dfc-package-consumer)
