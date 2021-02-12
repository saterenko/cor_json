cmake_minimum_required(VERSION 3.17)
project(cor_json C)

set(CMAKE_C_STANDARD 99)

add_library(cor_json
    cor_json.c
    cor_json.h
    cor_core.h
    cor_pool.c
    cor_pool.h)