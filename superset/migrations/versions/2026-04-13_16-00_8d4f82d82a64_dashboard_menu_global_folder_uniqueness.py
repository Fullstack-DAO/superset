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
"""dashboard menu global folder uniqueness

Revision ID: 8d4f82d82a64
Revises: 6f4c9b8a1e21
Create Date: 2026-04-13 16:00:00.000000

"""

# revision identifiers, used by Alembic.
revision = "8d4f82d82a64"
down_revision = "6f4c9b8a1e21"

import sqlalchemy as sa
from alembic import op
from sqlalchemy.engine.reflection import Inspector
from sqlalchemy.orm import Session

from superset.utils.core import generic_find_uq_constraint_name

conv = {"uq": "uq_%(table_name)s_%(column_0_name)s"}

dashboard_menu_folders = sa.table(
    "dashboard_menu_folders",
    sa.column("id", sa.Integer()),
    sa.column("user_id", sa.Integer()),
    sa.column("name", sa.String(length=255)),
)

dashboard_menu_items = sa.table(
    "dashboard_menu_items",
    sa.column("id", sa.Integer()),
    sa.column("folder_id", sa.Integer()),
    sa.column("dashboard_id", sa.Integer()),
)


def _merge_duplicate_folder_names(session: Session) -> None:
    duplicate_names = session.execute(
        sa.select(dashboard_menu_folders.c.name)
        .group_by(dashboard_menu_folders.c.name)
        .having(sa.func.count(dashboard_menu_folders.c.id) > 1)
    ).scalars()

    for folder_name in duplicate_names:
        folder_ids = list(
            session.execute(
                sa.select(dashboard_menu_folders.c.id)
                .where(dashboard_menu_folders.c.name == folder_name)
                .order_by(dashboard_menu_folders.c.id.asc())
            ).scalars()
        )
        keep_folder_id, *duplicate_folder_ids = folder_ids

        existing_dashboard_ids = set(
            session.execute(
                sa.select(dashboard_menu_items.c.dashboard_id).where(
                    dashboard_menu_items.c.folder_id == keep_folder_id,
                )
            ).scalars()
        )

        for duplicate_folder_id in duplicate_folder_ids:
            duplicate_dashboard_ids = list(
                session.execute(
                    sa.select(dashboard_menu_items.c.dashboard_id).where(
                        dashboard_menu_items.c.folder_id == duplicate_folder_id,
                    )
                ).scalars()
            )

            for dashboard_id in duplicate_dashboard_ids:
                if dashboard_id in existing_dashboard_ids:
                    session.execute(
                        sa.delete(dashboard_menu_items).where(
                            dashboard_menu_items.c.folder_id == duplicate_folder_id,
                            dashboard_menu_items.c.dashboard_id == dashboard_id,
                        )
                    )
                    continue

                session.execute(
                    sa.update(dashboard_menu_items)
                    .where(
                        dashboard_menu_items.c.folder_id == duplicate_folder_id,
                        dashboard_menu_items.c.dashboard_id == dashboard_id,
                    )
                    .values(folder_id=keep_folder_id)
                )
                existing_dashboard_ids.add(dashboard_id)

            session.execute(
                sa.delete(dashboard_menu_folders).where(
                    dashboard_menu_folders.c.id == duplicate_folder_id,
                )
            )

    session.commit()


def upgrade():
    bind = op.get_bind()
    session = Session(bind=bind)
    inspector = Inspector.from_engine(bind)

    _merge_duplicate_folder_names(session)

    old_constraint_name = generic_find_uq_constraint_name(
        "dashboard_menu_folders", {"user_id", "name"}, inspector
    ) or "uq_dashboard_menu_folders_user_id"

    with op.batch_alter_table(
        "dashboard_menu_folders", naming_convention=conv
    ) as batch_op:
        batch_op.drop_constraint(old_constraint_name, type_="unique")
        batch_op.create_unique_constraint("uq_dashboard_menu_folders_name", ["name"])


def downgrade():
    bind = op.get_bind()
    inspector = Inspector.from_engine(bind)

    new_constraint_name = generic_find_uq_constraint_name(
        "dashboard_menu_folders", {"name"}, inspector
    ) or "uq_dashboard_menu_folders_name"

    with op.batch_alter_table(
        "dashboard_menu_folders", naming_convention=conv
    ) as batch_op:
        batch_op.drop_constraint(new_constraint_name, type_="unique")
        batch_op.create_unique_constraint(
            "uq_dashboard_menu_folders_user_id_name", ["user_id", "name"]
        )