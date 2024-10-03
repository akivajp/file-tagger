#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import datetime
import json
import os
import sys

import hashlib

import magic

from pathlib import Path

from logzero import logger
from tqdm.auto import tqdm

import sqlalchemy
from sqlalchemy.orm import declarative_base
from sqlalchemy.schema import Column
from sqlalchemy.types import (
    Boolean,
    DateTime,
    Integer,
    String
)

import pandas as pd

Base = declarative_base()

class File(Base):
    __tablename__ = 'files'
    id = Column(Integer, primary_key=True)
    absolute_path = Column(String)
    relative_path = Column(String)
    size = Column(Integer)
    hash = Column(String)
    updated_at = Column(DateTime)
    mime_type = Column(String)
    detected_as_duplicated = Column(Boolean, default=False)

    def __repr__(self):
        return f'File(id={self.id}, absolute_path={self.absolute_path}, updated_at={self.updated_at})'
    
class Rule(Base):
    __tablename__ = 'ignore_rules'
    id = Column(Integer, primary_key=True)
    type = Column(String)
    pattern = Column(String)

    def __repr__(self):
        return f'Rule(id={self.id}, type={self.type}, pattern={self.pattern})'

def connect_sqlite(database):
    absolute_path = os.path.abspath(os.path.expanduser(database))
    #logger.debug('absolute_path: %s', absolute_path)
    basedir = os.path.dirname(absolute_path)
    if not os.path.exists(basedir):
        logger.debug('Creating directory: %s', basedir)
        os.makedirs(basedir)
    path = 'sqlite:///' + absolute_path
    #logger.debug('path: %s', path)
    engine = sqlalchemy.create_engine(path, echo=False)
    Base.metadata.create_all(bind=engine)
    session = sqlalchemy.orm.sessionmaker(bind=engine)()
    return session

def find_file(
    session: sqlalchemy.orm.Session,
    absolute_path: str,
    relative_path: str,
    size: int,
    updated_at: DateTime,
) -> File | None:
    # 絶対パス、相対パス、ファイルサイズ、更新日時が一致するものは、変更の無いファイルとみなす
    found = session.query(File).filter(
        File.absolute_path == absolute_path,
        File.relative_path == relative_path,
        File.size == size,
        File.updated_at == updated_at,
    ).first()
    if found:
        return found
    # 絶対パス、相対パスが一致したものはファイルが更新された可能性あり
    found = session.query(File).filter(
        File.absolute_path == absolute_path,
        File.relative_path == relative_path,
    ).first()
    if found:
        return found
    # 絶対パス、ファイルサイズ、更新日時が一致するものは、基準ディレクトリが変更された可能性あり
    found = session.query(File).filter(
        File.absolute_path == relative_path,
        File.size == size,
        File.updated_at == updated_at,
    ).first()
    if found:
        return found
    # 相対パス、ファイルサイズ、更新日時が一致するものは、移動したファイルとみなす
    found = session.query(File).filter(
        File.relative_path == relative_path,
        File.size == size,
        File.updated_at == updated_at,
    ).first()
    if found:
        return found
    return None

def find_duplicate(
    session: sqlalchemy.orm.Session,
    file: File,
) -> File | None:
    found = session.query(File).filter(
        File.id != file.id,
        #File.id < file.id,
        File.hash == file.hash,
        File.size == file.size,
        File.mime_type == file.mime_type,
    ).first()
    #logger.debug('file.id: %s', file.id)
    #logger.debug('found: %s', found)
    if found:
        return found
    return None

def update_file(
    session: sqlalchemy.orm.Session,
    absolute_path: str,
    relative_path: str,
):
    size = os.path.getsize(absolute_path)
    mtime = os.path.getmtime(absolute_path)
    updated_at = datetime.datetime.fromtimestamp(int(mtime))
    # 重複チェック
    found = find_file(
        session=session,
        absolute_path=absolute_path,
        relative_path=relative_path,
        size=size,
        updated_at=updated_at,
    )
    modified = False
    if found:
        file = found
    else:
        file = File()
        session.add(instance=file)
        modified = True
        #logger.debug('new file: %s', file)
    if any([
        file.size != size,
        file.updated_at != updated_at,
    ]):
        modified = True
    if not modified:
        if all([
            file.absolute_path == absolute_path,
            file.relative_path == relative_path,
        ]):
            logger.debug('no change: %s', file)
            return
    file.absolute_path = absolute_path
    file.relative_path = relative_path
    file.size = size
    file.updated_at = updated_at
    if modified:
        mime_type = magic.from_file(absolute_path, mime=True)
        hash = hashlib.sha256(open(absolute_path, 'rb').read()).hexdigest()
        file.mime_type = mime_type
        file.hash = hash
    if not found:
        logger.debug('new file: %s', file)
    session.commit()

    duplicated = None
    if size >= 100:
        duplicated = find_duplicate(
            session=session,
            file=file,
        )
        #logger.debug('duplicated: %s', duplicated)
    new_duplicated = duplicated is not None
    if file.detected_as_duplicated != new_duplicated:
        file.detected_as_duplicated = new_duplicated
        session.commit()

def get_ignore_rules(
    session: sqlalchemy.orm.Session,
) -> list[str]:
    rules = session.query(Rule).filter(
        Rule.type == 'ignore',
    ).all()
    return [rule.pattern for rule in rules]

def scan_directory(
    session: sqlalchemy.orm.Session,
    scan_path: str,
    path: str,
    max_depth: int = 10,
    ignore_rules: list[str] = [],
    depth: int = 0,
):
    if depth > max_depth:
        logger.warning('max depth reached: %s', path)
        return
    kwargs = dict(
        session=session,
        scan_path=scan_path,
        max_depth=max_depth,
        ignore_rules=ignore_rules,
    )
    for elem in os.listdir(path):
        if elem in ignore_rules:
            logger.warning('ignored: %s', elem)
            continue
        found_path = os.path.join(path, elem)
        if os.path.isfile(found_path):
            logger.debug('file: %s', found_path)
            absolute_path = os.path.abspath(found_path)
            relative_path = os.path.relpath(found_path, scan_path)
            update_file(
                session=session,
                absolute_path=absolute_path,
                relative_path=relative_path,
            )
        elif os.path.isdir(found_path):
            #logger.debug('directory: %s', found_path)
            scan_directory(
                path=found_path,
                depth=depth + 1,
                **kwargs,
            )
        else:
            logger.debug('unknown: %s', found_path)

def command_scan(args):
    logger.debug('Scanning files')
    logger.debug('args: %s', args)
    session = connect_sqlite(args.database)
    ignore_rules = get_ignore_rules(session)
    logger.debug('ignore_rules: %s', ignore_rules)
    scan_directory(
        session=session,
        scan_path=args.path,
        path=args.path,
        ignore_rules=ignore_rules,
    )

def command_find(args):
    session = connect_sqlite(args.database)
    queries = []
    if args.duplicated:
        queries.append(File.detected_as_duplicated == True)
    files = session.query(File).filter(
        *queries,
    )
    #logger.debug('files: %s', files)
    df = pd.read_sql(files.statement, files.session.bind)
    df = df[(key for key in df.keys() if key != 'id')]
    #logger.debug('keys: %s', df.keys())
    #logger.debug('files: \n%s', df)
    df_selected = df[[
        #'id',
        'absolute_path',
        #'relative_path',
        'size',
        #'updated_at',
        #'mime_type',
        #'detected_as_duplicated',
    ]]
    #logger.debug('files: \n%s', df_selected)
    #print(df_selected)
    str_json = df.to_json(orient='records', indent=2)
    #j = df_selected.to_json(orient='records', indent=2)
    print(str_json)

def add_rule(
    session: sqlalchemy.orm.Session,
    type: str,
    pattern: str,
):
    found = session.query(Rule).filter(
        Rule.type == type,
        Rule.pattern == pattern,
    ).first()
    if found:
        logger.warning('Already exists: %s', found)
        return
    rule = Rule()
    rule.type = type
    rule.pattern = pattern
    session.add(instance=rule)
    session.commit()
    logger.info('Added: %s', rule)

def command_ignore(args):
    session = connect_sqlite(args.database)
    for pattern in args.patterns:
        add_rule(
            session=session,
            type='ignore',
            pattern=pattern,
        )

def command_export_rules(args):
    session = connect_sqlite(args.database)
    rules = session.query(Rule).filter(
        #Rule.type == 'ignore',
    )
    df = pd.read_sql(rules.statement, rules.session.bind)
    df = df[(key for key in df.keys() if key != 'id')]
    str_json = df.to_json(orient='records', indent=2)
    print(str_json)

def load_json(path):
    if path.endswith('.json'):
        with open(path, 'r') as f:
            return json.load(f)
    elif path.endswith('.jsonl'):
        with open(path, 'r') as f:
            return [json.loads(line) for line in f]
    else:
        raise ValueError('Unsupported file extension: %s' % path)

def command_import_rules(args):
    session = connect_sqlite(args.database)
    data = load_json(args.path)
    for item in data:
        add_rule(session, **item)

def main():
    parser = argparse.ArgumentParser(description='File Tag Manager')
    subparsers = parser.add_subparsers(dest='command')
    parser.add_argument(
        '--database',
        default='~/tmp/file-tagger.db',
        help='Path to the database file'
    )

    parser_scan = subparsers.add_parser('scan', help='Scan files and update database')
    parser_scan.add_argument(
        'path',
        default='./',
        nargs='?',
        help='Path to scan'
    )
    parser_scan.set_defaults(handler=command_scan)

    parser_find = subparsers.add_parser('find', help='Find files')
    parser_find.add_argument(
        '--duplicated', '-d',
        action='store_true',
        help='Find duplicated files'
    )
    parser_find.set_defaults(handler=command_find)

    parser_ignore = subparsers.add_parser('ignore', help='Add ignore rules')
    parser_ignore.add_argument(
        'patterns',
        metavar='PATTERN',
        nargs='+',
        help='Pattern to ignore'
    )
    parser_ignore.set_defaults(handler=command_ignore)

    parser_export_rules = subparsers.add_parser('export-rules', help='Export rules')
    parser_export_rules.set_defaults(handler=command_export_rules)

    parser_import_rules = subparsers.add_parser('import-rules', help='Import rules')
    parser_import_rules.add_argument(
        'path',
        help='Path to the rules file (JSON/JSONL)',
    )
    parser_import_rules.set_defaults(handler=command_import_rules)

    args = parser.parse_args()
    if args.command:
        args.handler(args)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == '__main__':
    main()
