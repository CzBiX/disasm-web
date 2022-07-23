#!/usr/bin/env bash

VERSION=latest

cd
git clone https://github.com/emscripten-core/emsdk.git --depth 1 
cd emsdk 
./emsdk install $VERSION 
./emsdk activate $VERSION
