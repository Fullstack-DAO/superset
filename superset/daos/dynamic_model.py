import sqlalchemy as sa
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.exc import SQLAlchemyError
from typing import Any
from superset import db
import re
from sqlalchemy import DECIMAL, Integer, Numeric, BigInteger, Text, Float, DateTime
from sqlalchemy.dialects.postgresql import VARCHAR, TIMESTAMP
from sqlalchemy import Table, and_, or_
import logging
from superset.utils import core as utils

logger = logging.getLogger(__name__)

trino_to_sqlalchemy_type_mapping = {
    'varchar': VARCHAR,
    'decimal': DECIMAL,
    'bigint': BigInteger,
    'timestamp': TIMESTAMP,
    # Trino 的 'integer' 映射为 SQLAlchemy 的 Integer
    'integer': Integer,
    # Trino 的 'double' 映射为 SQLAlchemy 的 Float
    'double': Float,
    # Trino 的 'real' 和 'numeric' 映射为 SQLAlchemy 的 Numeric
    'numeric': DECIMAL,
    'real': Float,
    'date': DateTime,
    'text': Text,
    'string': VARCHAR,
    
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
    logger.info(
        "Create dataset dynamic table, table_name: %r.", table_name
    )
    if table_name in base.metadata.tables:
        table = Table(table_name, base.metadata, autoload_with=db.engine)
        table.drop(db.engine, checkfirst=True)
    else:
        drop_dynamic_table(table_name)

    attributes = {'__tablename__': table_name, '__table_args__': {'extend_existing': True}}
    
    attributes['id'] = sa.Column(sa.Integer, primary_key=True)

    for field_name, field_type in fields.items():
        attributes[field_name] = sa.Column(map_trino_type_to_sqlalchemy(field_type))
    
    DynamicTable = type(table_name, (Base,), attributes)
   
    Base.metadata.create_all(bind=db.engine)
    return DynamicTable

def append_data_to_dynamic_table(table_name, datas: list[dict[str, Any]], batch_size: int = 50000, base=Base):
    logger.info(f"Append datas to dataset dynamic table Start, params( table_name: {table_name})" )
    total = len(datas)
    batches = (total - 1) // batch_size + 1  
    table = Table(table_name, base.metadata, autoload_with=db.engine)
    for i in range(batches):
        try:
            with db.engine.connect() as conn:
                trans = conn.begin()
                batch_data = datas[i * batch_size:(i + 1) * batch_size]
                conn.execute(table.insert(), batch_data)
                logger.info(f"Append data nested Batch {i+1}/{batches} inserted successfully.")
                trans.commit()
        except SQLAlchemyError as ex:
            db.session.rollback()
            logger.error(f"Error occurred in nested batch {i+1}/{batches}.", exc_info=True)
            raise RuntimeError(f"Failed to create item in database in nested batch {i+1}") from ex
        finally:
            del batch_data

def add_data_to_dynamic_table(table_class, datas: list[dict[str, Any]], batch_size: int = 50000):
    logger.info("Insert datas to dataset dynamic table Start.")
    total = len(datas)
    batches = (total - 1) // batch_size + 1  
    items = []

    for i in range(batches):
        batch_data = datas[i * batch_size:(i + 1) * batch_size]
        try:
            for data in batch_data:
                item = table_class(**data)
                db.session.add(item)
                items.append(item)
            db.session.commit()
            logger.info(f"Nested Batch {i+1}/{batches} inserted successfully.")
        except SQLAlchemyError as ex:
            db.session.rollback()
            logger.error(f"Error occurred in nested batch {i+1}/{batches}.", exc_info=True)
            raise RuntimeError(f"Failed to create item in database in nested batch {i+1}") from ex
        finally:
            del batch_data
    
    return items
def delete_dynamic_table(table_name: str):
    db.session.execute('delete from "'+ table_name +'";')  
    db.session.commit()

def drop_dynamic_table(table_name: str):
    db.session.execute('DROP TABLE IF EXISTS "'+ table_name +'";')  
    db.session.commit()

def reinit_dynamic_table(table_name: str, res_gen):
    logger.info(
        "Start init dataset dynamic table process, table_name: %r.", table_name
    )
    # drop_dynamic_table(table_name)
    fields = next(res_gen)['columns']
    table_class = create_dynamic_table(table_name, fields)
    i = 0
    for batch in res_gen:
      records = batch['records']
      table_datas = [{key: record[i] for i, key in enumerate(fields.keys())} for record in records]
      add_data_to_dynamic_table(table_class, table_datas)
      i += 1
      logger.info(f"Finish {i} batch datas save to dynamic table {table_name}.")
    return table_class

def refresh_dynamic_table_datas_by_condition(table_name: str, conditions: list,  res_gen):
    conditions_str = [
        condition['col'] + condition['op'] + str((','.join(condition['val']) if isinstance(condition['val'], list) else condition['val']))
        for condition in conditions
        if condition['op'] != utils.FilterOperator.TEMPORAL_RANGE.value
    ]
    logger.info("Start refresh dataset dynamic table process, table_name: %r, conditions: %r.", table_name, conditions_str)
    fields = next(res_gen)['columns']
    i = 0
    for batch in res_gen:
      records = batch['records']
      table_datas = [{key: record[i] for i, key in enumerate(fields.keys())} for record in records]
      append_data_to_dynamic_table(table_name, table_datas)
      i += 1
      logger.info(f"Finish {i} batch datas append to dynamic table. params( table_name: {table_name}, conditions: {conditions_str} )")

def delete_dynamic_table_datas_by_condition(table_name: str, conditions: list):
    conditions_str = [
        condition['col'] + condition['op'] + str((','.join(condition['val']) if isinstance(condition['val'], list) else condition['val']))
        for condition in conditions
        if condition['op'] != utils.FilterOperator.TEMPORAL_RANGE.value
    ]
    logger.info("Start delete dataset dynamic table process, table_name: %r, conditions: %r.", table_name, conditions_str)
    table = Table(table_name, Base.metadata, autoload_with=db.engine)
    #将入参conditions，过滤掉op等于TEMPORAL_RANGE的数据
    condition_expressions = [build_condition(table, condition) for condition in conditions if condition['op'] != utils.FilterOperator.TEMPORAL_RANGE.value]

    where_clause = and_(*condition_expressions)
    db.session.execute(table.delete().where(where_clause))
    db.session.commit()

    logger.info(f"Finish delete dynamic table datas by condition. params( table_name: {table_name}, conditions: {conditions_str})")

    


def build_condition(table, condition):
    op = condition['op']
    col = condition['col']
    val = condition['val']
    column = getattr(table.c, col)
    
    if op == utils.FilterOperator.EQUALS.value:
        return column == val
    elif op == utils.FilterOperator.NOT_EQUALS.value:
        return column != val
    elif op == utils.FilterOperator.IN.value:
        return column.in_(val)
    elif op == utils.FilterOperator.NOT_IN.value:
        return column.notin_(val)
    elif op == utils.FilterOperator.GREATER_THAN.value:
        return column > val
    elif op == utils.FilterOperator.LESS_THAN.value:
        return column < val
    elif op == utils.FilterOperator.GREATER_THAN_OR_EQUALS.value:
        return column >= val
    elif op == utils.FilterOperator.LESS_THAN_OR_EQUALS.value:
        return column <= val
    elif op == utils.FilterOperator.LIKE.value:
        return column.like(val)
    else:
        raise ValueError(f"Unsupported operator: {op}")