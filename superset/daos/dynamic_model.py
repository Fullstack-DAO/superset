import sqlalchemy as sa
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.exc import SQLAlchemyError
from typing import Any
from superset import db
import re
from sqlalchemy import DECIMAL, Integer, Numeric, BigInteger, Text, Float, DateTime
from sqlalchemy.dialects.postgresql import VARCHAR, TIMESTAMP
from sqlalchemy import Table
import logging

logger = logging.getLogger(__name__)

trino_to_sqlalchemy_type_mapping = {
    'VARCHAR': VARCHAR,
    'DECIMAL': DECIMAL,
    'BIGINT': BigInteger,
    'TIMESTAMP': TIMESTAMP,
    # Trino 的 'integer' 映射为 SQLAlchemy 的 Integer
    'INTEGER': Integer,
    # Trino 的 'double' 映射为 SQLAlchemy 的 Float
    'DOUBLE': Float,
    # Trino 的 'real' 和 'numeric' 映射为 SQLAlchemy 的 Numeric
    'NUMERIC': DECIMAL,
    'REAL': Float,
    'DATE': DateTime,
    'TEXT': Text,
}
Base = declarative_base()

def map_trino_type_to_sqlalchemy(trino_type):
    match = re.match(r'(\w+)(\((.+)\))?', trino_type)
    if not match:
        raise ValueError(f"Cannot parse Trino type: {trino_type}")
    
    base_type, type_args_str = match.groups()[0], match.groups()[2]
    if base_type in trino_to_sqlalchemy_type_mapping:
        if("DECIMAL" == base_type):
            return trino_to_sqlalchemy_type_mapping[base_type](38, 15)
        else:
          type_args = tuple(int(arg) for arg in type_args_str.split(',')) if type_args_str else ()
          return trino_to_sqlalchemy_type_mapping[base_type](*type_args)
    else:
        raise ValueError(f"No SQLAlchemy mapping for Trino type: {base_type}")

def create_dynamic_table(table_name, fields, base=Base):
    # # 检查并清理旧的类定义
    # if table_name in base._decl_class_registry:
    #     # 清理映射
    #     clear_mappers()
    #     # 从注册表中移除类
    #     del base._decl_class_registry[table_name]
    #     # 如果该类存在于 metadata 中，则也移除它
    #     if table_name in base.metadata.tables:
    #         del base.metadata.tables[table_name]
    logger.info(
        "Create dataset dynamic table, table_name: %r.", table_name
    )
    if table_name in base.metadata.tables:
        table = Table(table_name, base.metadata, autoload_with=db.engine)
        table.drop(db.engine, checkfirst=True)
    # if table_name in base.metadata.tables:
    #     table = Table(table_name, base.metadata)
    #     table.drop(db.engine, checkfirst=True)

    attributes = {'__tablename__': table_name, '__table_args__': {'extend_existing': True}}
    
    attributes['id'] = sa.Column(sa.Integer, primary_key=True)

    for field_name, field_type in fields.items():
        attributes[field_name] = sa.Column(map_trino_type_to_sqlalchemy(field_type))
    
    DynamicTable = type(table_name, (Base,), attributes)

    # if table_name in Base.metadata.tables:
    #     del base.metadata.tables[table_name]
        # Base.metadata.tables[table_name].extend_existing = True
   
    Base.metadata.create_all(bind=db.engine)
    return DynamicTable

def add_data_to_dynamic_table(table_class, datas: dict[str, Any]):
    logger.info(
        "Insert datas to dataset dynamic table Start."
    )
    items = []
    try:
        for data in datas:
          item = table_class(**data)
          db.session.add(item)
          items.append(item)
        
        db.session.commit()
        logger.info(
            "Insert datas to dataset dynamic table Finish."
        )
        return items
    except SQLAlchemyError as ex:
        db.session.rollback()
        raise RuntimeError("Failed to create item in database") from ex

def drop_dynamic_table(table_name: str):
    db.session.execute('DROP TABLE IF EXISTS "'+ table_name +'";')  
    db.session.commit()

def reinit_dynamic_table(table_name: str, fields: dict[str, Any], datas: dict[str, Any]):
    logger.info(
        "Start init dataset dynamic table process, table_name: %r.", table_name
    )
    # drop_dynamic_table(table_name)
    table_class = create_dynamic_table(table_name, fields)
    add_data_to_dynamic_table(table_class, datas)
    return table_class