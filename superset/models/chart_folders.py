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


class ChartMenuFolder(Model):
    __tablename__ = "chart_menu_folders"
    __table_args__ = (
        UniqueConstraint(
            "parent_id",
            "name",
            name="uq_chart_menu_folders_parent_id_name",
        ),
    )

    id = Column(Integer, primary_key=True)
    parent_id = Column(
        Integer,
        ForeignKey("chart_menu_folders.id", ondelete="CASCADE"),
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
        "ChartMenuFolder",
        remote_side=[id],
        back_populates="children",
        foreign_keys=[parent_id],
    )
    children = relationship(
        "ChartMenuFolder",
        back_populates="parent",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="ChartMenuFolder.id",
    )
    items = relationship(
        "ChartMenuItem",
        back_populates="folder",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="ChartMenuItem.id",
    )


class ChartMenuItem(Model):
    __tablename__ = "chart_menu_items"
    __table_args__ = (UniqueConstraint("folder_id", "chart_id"),)

    id = Column(Integer, primary_key=True)
    folder_id = Column(
        Integer,
        ForeignKey("chart_menu_folders.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    chart_id = Column(
        Integer,
        ForeignKey("slices.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    folder = relationship("ChartMenuFolder", back_populates="items")
    chart = relationship("Slice", foreign_keys=[chart_id])
