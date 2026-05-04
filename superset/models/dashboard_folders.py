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
from flask_appbuilder import Model
from sqlalchemy import Column, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import relationship

from superset import security_manager


class DashboardMenuFolder(Model):
    __tablename__ = "dashboard_menu_folders"
    __table_args__ = (
        UniqueConstraint(
            "parent_id",
            "name",
            name="uq_dashboard_menu_folders_parent_id_name",
        ),
    )

    id = Column(Integer, primary_key=True)
    parent_id = Column(
        Integer,
        ForeignKey("dashboard_menu_folders.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    user_id = Column(
        Integer,
        ForeignKey("ab_user.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name = Column(String(255), nullable=False)

    user = relationship(security_manager.user_model, foreign_keys=[user_id])
    parent = relationship(
        "DashboardMenuFolder",
        remote_side=[id],
        back_populates="children",
        foreign_keys=[parent_id],
    )
    children = relationship(
        "DashboardMenuFolder",
        back_populates="parent",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="DashboardMenuFolder.id",
    )
    items = relationship(
        "DashboardMenuItem",
        back_populates="folder",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="DashboardMenuItem.id",
    )


class DashboardMenuItem(Model):
    __tablename__ = "dashboard_menu_items"
    __table_args__ = (UniqueConstraint("folder_id", "dashboard_id"),)

    id = Column(Integer, primary_key=True)
    folder_id = Column(
        Integer,
        ForeignKey("dashboard_menu_folders.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    dashboard_id = Column(
        Integer,
        ForeignKey("dashboards.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    folder = relationship("DashboardMenuFolder", back_populates="items")
    dashboard = relationship("Dashboard", foreign_keys=[dashboard_id])