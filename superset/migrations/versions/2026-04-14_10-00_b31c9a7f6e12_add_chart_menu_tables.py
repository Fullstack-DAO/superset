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
"""add chart menu tables

Revision ID: b31c9a7f6e12
Revises: 8d4f82d82a64
Create Date: 2026-04-14 10:00:00.000000

"""

import sqlalchemy as sa
from alembic import op


revision = "b31c9a7f6e12"
down_revision = "8d4f82d82a64"


def upgrade():
    op.create_table(
        "chart_menu_folders",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["ab_user.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name", name="uq_chart_menu_folders_name"),
    )
    op.create_index(
        op.f("ix_chart_menu_folders_user_id"),
        "chart_menu_folders",
        ["user_id"],
        unique=False,
    )
    op.create_table(
        "chart_menu_items",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("folder_id", sa.Integer(), nullable=False),
        sa.Column("chart_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["chart_id"], ["slices.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["folder_id"], ["chart_menu_folders.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("folder_id", "chart_id"),
    )
    op.create_index(
        op.f("ix_chart_menu_items_chart_id"),
        "chart_menu_items",
        ["chart_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_chart_menu_items_folder_id"),
        "chart_menu_items",
        ["folder_id"],
        unique=False,
    )


def downgrade():
    op.drop_index(
        op.f("ix_chart_menu_items_folder_id"),
        table_name="chart_menu_items",
    )
    op.drop_index(
        op.f("ix_chart_menu_items_chart_id"),
        table_name="chart_menu_items",
    )
    op.drop_table("chart_menu_items")
    op.drop_index(
        op.f("ix_chart_menu_folders_user_id"),
        table_name="chart_menu_folders",
    )
    op.drop_table("chart_menu_folders")
