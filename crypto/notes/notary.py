#!/usr/bin/env python3.7


'''
Notary: a script for formatting notes. Try ./notary.py --help.
'''


from __future__ import annotations
from typing import List, Any, Iterable, Tuple, NamedTuple, Optional, Iterator
import itertools
import functools
import argparse
import operator
import enum
import io
import re


MAX_COLUMNS_DEFAULT = 65


class NotASection(Exception):
    
    pass


class Section(NamedTuple):
    text: str
    kind: int

    def formatted(self, max_columns: int) -> str:
        if self.kind == Section.table_of_contents():
            return self.text

        def yield_lines() -> Iterable[str]:
            words = self.text.split()
            line = ''
            for word in words:
                new_line = f'{line} {word}' if line else word
                if len(new_line) >= max_columns:
                    yield line
                    line = f'{word}'
                else:
                    line = new_line
            if line.strip():
                yield line
        lines = (
            f'  {line}' if self.kind == Section.body() else f'{line}'
            for line in yield_lines()
        )

        def header() -> str:
            if self.kind == Section.title():
                return '\n\n\n'
            elif self.kind == Section.subtitle() or self.kind == Section.body():
                return '\n'
            else:
                return ''

        return header() + '\n'.join(lines)

    @staticmethod
    def title() -> int:
        return 0

    @staticmethod
    def subtitle() -> int:
        return 1

    @staticmethod
    def body() -> int:
        return 2 

    @staticmethod
    def table_of_contents() -> int:
        return 3

    @staticmethod
    def is_title(line: str) -> bool:
        w = first_word(line)
        return len(w) == 2 and w[1] == '.'

    @staticmethod
    def is_subtitle(line: str) -> bool:
        w = first_word(line)
        return len(w) == 4 and w[1] == w[3] == '.'

    @staticmethod
    def is_body_line(line: str) -> bool:
        return line.startswith('  ')

    @staticmethod
    def is_table_of_contents_line(line: str) -> bool:
        return line.startswith('+') or line.startswith('|')


class BadNotesFormat(Exception):

    pass


def parse_notes(notes: str) -> Iterable[Section]:
    def parse_lines(
        line_predicate: Any,
        kind: int,
        lines: Iterator[str]
    ) -> Section:
        text = '\n'.join(itertools.takewhile(line_predicate, lines))
        return Section(text, kind)

    parse_table_of_contents = functools.partial(
        parse_lines,
        Section.is_table_of_contents_line,
        Section.table_of_contents()
    )

    parse_body = functools.partial(
        parse_lines,
        Section.is_body_line,
        Section.body()
    )

    lines = iter(notes.splitlines(keepends=False))
    yield parse_table_of_contents(lines)
    for line in lines:
        if not line.strip():
            continue
        if Section.is_title(line):
            yield Section(line, kind=Section.title())
        elif Section.is_subtitle(line):
            yield Section(line, kind=Section.subtitle())
        elif Section.is_body_line(line):
            yield parse_body(itertools.chain([line], lines))


def format_sections(sections: Iterable[Section], max_columns: int) -> str:
    return '\n'.join(
        section.formatted(max_columns) for section in sections
    )


def format_notes(notes: str, max_columns: int) -> str:
    sections = parse_notes(notes)
    return format_sections(sections, max_columns)


def first_word(s: str) -> str:
    return s.split()[0]


def parse_args() -> Any:
    parser = argparse.ArgumentParser(description='Notary: formats notes.')
    parser.add_argument(
        'path', metavar='FILEPATH', type=str, help='path to the file to format'
    )
    parser.add_argument(
        '--max-columns', dest='max_columns', metavar='N',
        type=int, default=MAX_COLUMNS_DEFAULT,
        help=f'maximum number of columns, {MAX_COLUMNS_DEFAULT} by default'
    )
    return parser.parse_args()


def read_file(file_name: str) -> str:
    with open(file_name) as f:
        return f.read()


def write_to_file(file_name: str, content: str) -> None:
    with open(file_name, 'w') as f:
        f.write(content)


def main() -> None:
    args = parse_args()
    notes = format_notes(read_file(args.path), args.max_columns)
    write_to_file(args.path, notes)


if __name__ == '__main__':
    main()

