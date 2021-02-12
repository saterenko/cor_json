cmake_minimum_required(VERSION 3.17)
project(cor_json_tests C)

add_executable(test_cor_json
    test_cor_json.c
    cor_test.h)

target_link_libraries(test_cor_json
    cor_json)

