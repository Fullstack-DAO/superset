# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""add_column_to_tables

Revision ID: 53e6925233ce
Revises: ccdf9fa7ebfb
Create Date: 2024-03-29 11:49:17.806006

"""

# revision identifiers, used by Alembic.
revision = '53e6925233ce'
down_revision = 'ccdf9fa7ebfb'

from sqlalchemy.dialects import postgresql
import sqlalchemy as sa
from alembic import op
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session

from superset import db
from superset.migrations.shared.utils import paginated_update, table_has_column

Base = declarative_base()


class SqlaTable(Base):
    __tablename__ = "tables"

    id = sa.Column(sa.Integer, primary_key=True)
    dynamic_ready = sa.Column(sa.Boolean())
    dynamic_refresh_type = sa.Column(sa.VARCHAR(10))
    dynamic_refresh_year_column = sa.Column(sa.VARCHAR(255))
    dynamic_refresh_month_column = sa.Column(sa.VARCHAR(255))

def upgrade():
    if not table_has_column("tables", "dynamic_ready"):
        op.add_column(
            "tables",
            sa.Column(
                "dynamic_ready",
                sa.Boolean(),
                nullable=True,
                default=False,
                server_default=sa.false(),
            ),
            sa.Column(
                'dynamic_refresh_type',
                sa.VARCHAR(10),
                nullable=True,
                autoincrement=False,
            ),
            sa.Column(
                'dynamic_refresh_year_column',
                sa.VARCHAR(255),
                nullable=True,
                autoincrement=False,
            ),
            sa.Column(
                'dynamic_refresh_month_column',
                sa.VARCHAR(255),
                nullable=True,
                autoincrement=False,
            ),
        )

        bind = op.get_bind()
        session = db.Session(bind=bind)

        for table in paginated_update(session.query(SqlaTable)):
            table.dynamic_ready = False



def downgrade():
    if table_has_column("tables", "dynamic_ready"):
        op.drop_column("tables", "dynamic_ready")
        op.drop_column("tables", "dynamic_refresh_type")
        op.drop_column("tables", "dynamic_refresh_year_column")
        op.drop_column("tables", "dynamic_refresh_month_column")
