#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import datetime
import os
import sys

import hashlib
import json
import sqlite3

from pathlib import Path

from logzero import logger
from tqdm.auto import tqdm

import sqlalchemy
#from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import declarative_base
from sqlalchemy.schema import Column
from sqlalchemy.types import Integer, String
from sqlalchemy.types import DateTime

import pandas as pd

Base = declarative_base()

class File(Base):
    __tablename__ = 'files'
    id = Column(Integer, primary_key=True)
    #path = Column(String, unique=True)
    absolute_path = Column(String)
    relative_path = Column(String)
    size = Column(Integer)
    hash = Column(String)
    #tags = Column(String)
    updated_at = Column(DateTime)
    mime_type = Column(String)

    def __repr__(self):
        return f'File(absolute_path={self.absolute_path}, updated_at={self.updated_at})'

class Directory(Base):
    __tablename__ = 'directories'
    id = Column(Integer, primary_key=True)
    #path = Column(String, unique=True)
    absolute_path = Column(String)
    relative_path = Column(String)
    updated_at = Column(DateTime)

def connect_sqlite(database):
    absolute_path = os.path.abspath(os.path.expanduser(database))
    logger.debug('absolute_path: %s', absolute_path)
    #basedir = os.path.dirname(database)
    basedir = os.path.dirname(absolute_path)
    if not os.path.exists(basedir):
        logger.debug('Creating directory: %s', basedir)
        os.makedirs(basedir)
    #path = 'sqlite:///' + database
    #path = 'sqlite://' + absolute_path
    path = 'sqlite:///' + absolute_path
    logger.debug('path: %s', path)
    #engine = sqlalchemy.create_engine(path, echo=True)
    engine = sqlalchemy.create_engine(path, echo=False)
    Base.metadata.create_all(bind=engine)
    #return engine
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
    # 相対パス、ファイルサイズ、更新日時が一致するものは、移動したファイルとみなす
    found = session.query(File).filter(
        File.relative_path == relative_path,
        File.size == size,
        File.updated_at == updated_at,
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
    return None

def update_file(
    session: sqlalchemy.orm.Session,
    absolute_path: str,
    relative_path: str,
):
    size = os.path.getsize(absolute_path)
    mtime = os.path.getmtime(absolute_path)
    #updated_at = sqlalchemy.sql.func.datetime(mtime, 'unixepoch')
    #updated_at = DateTime(mtime)
    #updated_at = datetime.datetime.fromtimestamp(mtime)
    updated_at = datetime.datetime.fromtimestamp(int(mtime))
    #logger.debug('updated_at: %s', updated_at)
    # 重複チェック
    #found = session.query(File).filter(
    #    File.absolute_path == absolute_path,
    #    File.relative_path == relative_path,
    #).first()
    file = find_file(
        session=session,
        absolute_path=absolute_path,
        relative_path=relative_path,
        size=size,
        updated_at=updated_at,
    )
    #logger.debug('file: %s', file)
    modified = False
    if not file:
        file = File()
        session.add(instance=file)
        modified = True
        logger.debug('new file: %s', file)
    #logger.debug('file.size: %s', file.size)
    #logger.debug('size: %s', size)
    #logger.debug('file.updated_at: %s', file.updated_at)
    #logger.debug('updated_at: %s', updated_at)
    if any([
        file.size != size,
        file.updated_at != updated_at,
    ]):
        modified = True
    #logger.debug('modified: %s', modified)
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
        mime_type = 'application/octet-stream'
        hash = hashlib.sha256(open(absolute_path, 'rb').read()).hexdigest()
        #logger.debug('hash: %s', hash)
        file.mime_type = mime_type
        file.hash = hash
    #file = File(
    #    absolute_path=absolute_path,
    #    relative_path=relative_path,
    #    size=size,
    #    updated_at=updated_at,
    #    mime_type=mime_type,
    #    hash=hash,
    #)
    #session.add(instance=file)
    session.commit()

def command_scan(args):
    logger.debug('Scanning files')
    logger.debug('args: %s', args)
    #engine = sqlalchemy.create_engine('sqlite:///' + args.database)
    #engine = connect_sqlite(args.database)
    #logger.debug('engine: %s', engine)
    #session = sqlalchemy.orm.sessionmaker(bind=engine)()
    session = connect_sqlite(args.database)
    for elem in os.listdir(args.path):
        #logger.debug('elem: %s', elem)
        path = os.path.join(args.path, elem)
        if os.path.isfile(path):
            logger.debug('file: %s', path)
            absolute_path = os.path.abspath(path)
            relative_path = os.path.relpath(path, args.path)
            #size = os.path.getsize(path)
            #mtime = os.path.getmtime(path)
            ##logger.debug('updated_at: %s', updated_at)
            ##updated_at = sqlalchemy.sql.func.datetime(updated_at, 'unixepoch')
            #updated_at = sqlalchemy.sql.func.datetime(mtime, 'unixepoch')
            #logger.debug('updated_at: %s', updated_at)
            ## 重複チェック
            #found = session.query(File).filter(
            #    File.absolute_path == absolute_path,
            #    File.relative_path == relative_path,
            #).first()
            #mime_type = 'application/octet-stream'
            #hash = hashlib.sha256(open(path, 'rb').read()).hexdigest()
            #logger.debug('hash: %s', hash)
            #file = File(
            #    absolute_path=absolute_path,
            #    relative_path=relative_path,
            #    size=size,
            #    updated_at=updated_at,
            #    mime_type=mime_type,
            #    hash=hash,
            #)
            #session.add(instance=file)
            #session.commit()
            update_file(
                session=session,
                absolute_path=absolute_path,
                relative_path=relative_path,
            )
        elif os.path.isdir(path):
            logger.debug('directory: %s', path)
        else:
            logger.debug('unknown: %s', path)

def command_find(args):
    session = connect_sqlite(args.database)
    #files = session.query(File).all()
    #files = session.query(File).limit(10)
    files = session.query(File)
    logger.debug('files: %s', files)
    df = pd.read_sql(files.statement, files.session.bind)
    #logger.debug('df: \n%s', df)
    #j = df.to_json(orient='records')
    j = df.to_json(orient='records', indent=2)
    #j = json.dumps(df.to_dict(orient='records'), indent=2)
    logger.debug('j: \n%s', j)

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
    parser_find.set_defaults(handler=command_find)

    args = parser.parse_args()
    if args.command:
        args.handler(args)
    else:
        parser.print_help()
        sys.exit(1)
    #logger.debug('args: %s', args)

if __name__ == '__main__':
    main()
