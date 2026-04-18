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
"""add dashboard menu tables

Revision ID: 6f4c9b8a1e21
Revises: 17b1c765c9d3
Create Date: 2026-04-10 10:00:00.000000

"""

import sqlalchemy as sa
from alembic import op


revision = "6f4c9b8a1e21"
down_revision = "17b1c765c9d3"


def upgrade():
    op.create_table(
        "dashboard_menu_folders",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["ab_user.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "name"),
    )
    op.create_index(
        op.f("ix_dashboard_menu_folders_user_id"),
        "dashboard_menu_folders",
        ["user_id"],
        unique=False,
    )
    op.create_table(
        "dashboard_menu_items",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("folder_id", sa.Integer(), nullable=False),
        sa.Column("dashboard_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["dashboard_id"], ["dashboards.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["folder_id"], ["dashboard_menu_folders.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("folder_id", "dashboard_id"),
    )
    op.create_index(
        op.f("ix_dashboard_menu_items_dashboard_id"),
        "dashboard_menu_items",
        ["dashboard_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_dashboard_menu_items_folder_id"),
        "dashboard_menu_items",
        ["folder_id"],
        unique=False,
    )


def downgrade():
    op.drop_index(
        op.f("ix_dashboard_menu_items_folder_id"),
        table_name="dashboard_menu_items",
    )
    op.drop_index(
        op.f("ix_dashboard_menu_items_dashboard_id"),
        table_name="dashboard_menu_items",
    )
    op.drop_table("dashboard_menu_items")
    op.drop_index(
        op.f("ix_dashboard_menu_folders_user_id"),
        table_name="dashboard_menu_folders",
    )
    op.drop_table("dashboard_menu_folders")