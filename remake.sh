#!/bin/bash
export CC=gcc
export CXX=g++
make clean
make -j$(nproc)
