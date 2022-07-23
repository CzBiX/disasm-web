#!/usr/bin/env python3

import re
import sys
from typing import Generator

BINDING_DIR = 'native/bindings/nodejs/consts'
ENTRYPOINT_FILE = f'{BINDING_DIR}/keystone.js'

def get_const() -> Generator[None, str, list]:
  re_const = re.compile(r'exports\.(\w+ = .+)$')

  result = []
  while True:
    line = yield

    if not line:
      break
    
    if line.startswith('//'):
      continue

    match = re_const.search(line)
    if not match:
      print("Warning: No const found for '{}'".format(line), file=sys.stderr)
      continue
    
    result.append('KS_' + match.group(1))

  return result

def process_file(file_path, visitor):
  with open(file_path) as f:
    next(visitor)

    try:
      for line in f:
        visitor.send(line.strip())
      visitor.send(None)
    except StopIteration as e:
      return e.value

def handle_get_const():
  def _c(line):
    if not line:
      return ''
    
    return f'export const {line}'
  
  result = process_file(ENTRYPOINT_FILE, get_const())
  result = [
    '// AUTO-GENERATED FILE, DO NOT EDIT',
    '/* eslint-disable */',
    '',
    *map(_c, result),
  ]

  return result

def main():
  if len(sys.argv) == 1:
    print('Missing action')
    exit(1)

  action = sys.argv[1]
  
  if action == "const":
    result = handle_get_const()
  else:
    print('Invalid action')
    exit(1)
    
  print(*result, sep='\n')

if __name__ == '__main__':
  main()
