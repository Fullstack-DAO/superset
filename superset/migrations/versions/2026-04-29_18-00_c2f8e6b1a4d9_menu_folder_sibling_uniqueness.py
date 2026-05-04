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
"""menu folder sibling uniqueness

Revision ID: c2f8e6b1a4d9
Revises: 5a4d8e3f21c1
Create Date: 2026-04-29 18:00:00.000000

"""

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision = "c2f8e6b1a4d9"
down_revision = "5a4d8e3f21c1"


def upgrade():
    with op.batch_alter_table("dashboard_menu_folders") as batch_op:
        batch_op.drop_constraint("uq_dashboard_menu_folders_name", type_="unique")
        batch_op.create_unique_constraint(
            "uq_dashboard_menu_folders_parent_id_name",
            ["parent_id", "name"],
        )

    with op.batch_alter_table("chart_menu_folders") as batch_op:
        batch_op.drop_constraint("uq_chart_menu_folders_name", type_="unique")
        batch_op.create_unique_constraint(
            "uq_chart_menu_folders_parent_id_name",
            ["parent_id", "name"],
        )


def downgrade():
    with op.batch_alter_table("chart_menu_folders") as batch_op:
        batch_op.drop_constraint(
            "uq_chart_menu_folders_parent_id_name",
            type_="unique",
        )
        batch_op.create_unique_constraint("uq_chart_menu_folders_name", ["name"])

    with op.batch_alter_table("dashboard_menu_folders") as batch_op:
        batch_op.drop_constraint(
            "uq_dashboard_menu_folders_parent_id_name",
            type_="unique",
        )
        batch_op.create_unique_constraint("uq_dashboard_menu_folders_name", ["name"])