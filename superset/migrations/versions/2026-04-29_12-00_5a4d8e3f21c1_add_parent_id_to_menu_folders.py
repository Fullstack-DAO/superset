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
"""add parent id to menu folders

This is a compatibility migration for existing flat menu-folder data.
All historical rows keep a NULL parent_id after upgrade, which means they
remain valid top-level folders until an administrator explicitly re-parents
them into a nested structure.

Revision ID: 5a4d8e3f21c1
Revises: b31c9a7f6e12
Create Date: 2026-04-29 12:00:00.000000

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "5a4d8e3f21c1"
down_revision = "b31c9a7f6e12"


def upgrade():
    # Existing folders are intentionally preserved as root-level nodes.
    # The new column is nullable so no backfill is required for old data.
    op.add_column(
        "dashboard_menu_folders",
        sa.Column("parent_id", sa.Integer(), nullable=True),
    )
    op.create_index(
        op.f("ix_dashboard_menu_folders_parent_id"),
        "dashboard_menu_folders",
        ["parent_id"],
        unique=False,
    )
    op.create_foreign_key(
        "fk_dashboard_menu_folders_parent_id",
        "dashboard_menu_folders",
        "dashboard_menu_folders",
        ["parent_id"],
        ["id"],
        ondelete="CASCADE",
    )

    op.add_column(
        "chart_menu_folders",
        sa.Column("parent_id", sa.Integer(), nullable=True),
    )
    op.create_index(
        op.f("ix_chart_menu_folders_parent_id"),
        "chart_menu_folders",
        ["parent_id"],
        unique=False,
    )
    op.create_foreign_key(
        "fk_chart_menu_folders_parent_id",
        "chart_menu_folders",
        "chart_menu_folders",
        ["parent_id"],
        ["id"],
        ondelete="CASCADE",
    )


def downgrade():
    op.drop_constraint(
        "fk_chart_menu_folders_parent_id",
        "chart_menu_folders",
        type_="foreignkey",
    )
    op.drop_index(op.f("ix_chart_menu_folders_parent_id"), table_name="chart_menu_folders")
    op.drop_column("chart_menu_folders", "parent_id")

    op.drop_constraint(
        "fk_dashboard_menu_folders_parent_id",
        "dashboard_menu_folders",
        type_="foreignkey",
    )
    op.drop_index(
        op.f("ix_dashboard_menu_folders_parent_id"),
        table_name="dashboard_menu_folders",
    )
    op.drop_column("dashboard_menu_folders", "parent_id")