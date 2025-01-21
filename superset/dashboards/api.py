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
# pylint: disable=too-many-lines
import functools
import json
import logging
from datetime import datetime
from io import BytesIO
from typing import Any, Callable, cast, Optional
from zipfile import is_zipfile, ZipFile

from flask import make_response, redirect, request, Response, send_file, url_for, \
    jsonify
from flask_appbuilder import permission_name
from flask_appbuilder.api import expose, protect, rison, safe
from flask_appbuilder.hooks import before_request
from flask_appbuilder.models.sqla.interface import SQLAInterface
from flask_babel import gettext, ngettext
from flask_appbuilder.api.schemas import get_item_schema, get_list_schema
from marshmallow import ValidationError
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.wrappers import Response as WerkzeugResponse
from werkzeug.wsgi import FileWrapper

from superset import is_feature_enabled, thumbnail_cache
from superset.charts.permissions import ChartPermissions
from superset.charts.schemas import ChartEntityResponseSchema
from superset.commands.dashboard.create import CreateDashboardCommand
from superset.commands.dashboard.delete import DeleteDashboardCommand
from superset.commands.dashboard.exceptions import (
    DashboardAccessDeniedError,
    DashboardCreateFailedError,
    DashboardDeleteFailedError,
    DashboardForbiddenError,
    DashboardInvalidError,
    DashboardNotFoundError,
    DashboardUpdateFailedError,
)
from superset.commands.dashboard.export import ExportDashboardsCommand
from superset.commands.dashboard.importers.dispatcher import ImportDashboardsCommand
from superset.commands.dashboard.update import UpdateDashboardCommand
from superset.commands.importers.exceptions import NoValidFilesFoundError
from superset.commands.importers.v1.utils import get_contents_from_bundle
from superset.constants import MODEL_API_RW_METHOD_PERMISSION_MAP, RouteMethod
from superset.daos.chart import ChartDAO
from superset.daos.dashboard import DashboardDAO, EmbeddedDashboardDAO
from superset.dashboards.filters import (
    DashboardAccessFilter,
    DashboardCertifiedFilter,
    DashboardCreatedByMeFilter,
    DashboardFavoriteFilter,
    DashboardHasCreatedByFilter,
    DashboardTagFilter,
    DashboardTitleOrSlugFilter,
    FilterRelatedRoles,
)
from superset.dashboards.permissions import DashboardPermissions
from superset.dashboards.schemas import (
    DashboardCopySchema,
    DashboardDatasetSchema,
    DashboardGetResponseSchema,
    DashboardPostSchema,
    DashboardPutSchema,
    EmbeddedDashboardConfigSchema,
    EmbeddedDashboardResponseSchema,
    get_delete_ids_schema,
    get_export_ids_schema,
    get_fav_star_ids_schema,
    GetFavStarIdsSchema,
    openapi_spec_methods_override,
    thumbnail_query_schema,
)
from superset.extensions import event_logger, security_manager
from superset.models.dashboard import Dashboard
from superset.models.embedded_dashboard import EmbeddedDashboard
from superset.tasks.thumbnails import cache_dashboard_thumbnail
from superset.tasks.utils import get_current_user, get_current_user_object
from superset.utils.screenshots import DashboardScreenshot
from superset.utils.urls import get_url_path
from superset.views.base import generate_download_headers
from superset.views.base_api import (
    BaseSupersetModelRestApi,
    RelatedFieldFilter,
    requires_form_data,
    requires_json,
    statsd_metrics,
)
from superset.views.filters import (
    BaseFilterRelatedRoles,
    BaseFilterRelatedUsers,
    FilterRelatedOwners,
)

logger = logging.getLogger(__name__)


def with_dashboard(
    f: Callable[[BaseSupersetModelRestApi, Dashboard], Response]
) -> Callable[[BaseSupersetModelRestApi, str], Response]:
    """
    A decorator that looks up the dashboard by id or slug and passes it to the api.
    Route must include an <id_or_slug> parameter.
    Responds with 403 or 404 without calling the route, if necessary.
    """

    def wraps(self: BaseSupersetModelRestApi, id_or_slug: str) -> Response:
        try:
            dash = DashboardDAO.get_by_id_or_slug(id_or_slug)
            return f(self, dash)
        except DashboardAccessDeniedError:
            return self.response_403()
        except DashboardNotFoundError:
            return self.response_404()

    return functools.update_wrapper(wraps, f)


class DashboardRestApi(BaseSupersetModelRestApi):
    datamodel = SQLAInterface(Dashboard)

    @before_request(only=["thumbnail"])
    def ensure_thumbnails_enabled(self) -> Optional[Response]:
        if not is_feature_enabled("THUMBNAILS"):
            return self.response_404()
        return None

    include_route_methods = RouteMethod.REST_MODEL_VIEW_CRUD_SET | {
        RouteMethod.EXPORT,
        RouteMethod.IMPORT,
        RouteMethod.RELATED,
        "bulk_delete",  # not using RouteMethod since locally defined
        "favorite_status",
        "add_favorite",
        "remove_favorite",
        "get_charts",
        "get_datasets",
        "get_embedded",
        "set_embedded",
        "delete_embedded",
        "thumbnail",
        "copy_dash",
        "get_access_info",
        "modify_permissions",
        "add_collaborator",
    }
    resource_name = "dashboard"
    allow_browser_login = True

    class_permission_name = "Dashboard"
    method_permission_name = MODEL_API_RW_METHOD_PERMISSION_MAP

    list_columns = [
        "id",
        "published",
        "status",
        "slug",
        "url",
        "css",
        "position_json",
        "json_metadata",
        "thumbnail_url",
        "certified_by",
        "certification_details",
        "changed_by.first_name",
        "changed_by.last_name",
        "changed_by.id",
        "changed_by_name",
        "changed_on_utc",
        "changed_on_delta_humanized",
        "created_on_delta_humanized",
        "created_by.first_name",
        "created_by.id",
        "created_by.last_name",
        "dashboard_title",
        "owners.id",
        "owners.first_name",
        "owners.last_name",
        "roles.id",
        "roles.name",
        "is_managed_externally",
        "tags.id",
        "tags.name",
        "tags.type",
    ]

    list_select_columns = list_columns + ["changed_on", "created_on", "changed_by_fk"]
    order_columns = [
        "changed_by.first_name",
        "changed_on_delta_humanized",
        "created_by.first_name",
        "dashboard_title",
        "published",
        "changed_on",
    ]

    add_columns = [
        "certified_by",
        "certification_details",
        "dashboard_title",
        "slug",
        "owners",
        "roles",
        "position_json",
        "css",
        "json_metadata",
        "published",
    ]
    edit_columns = add_columns

    search_columns = (
        "created_by",
        "changed_by",
        "dashboard_title",
        "id",
        "owners",
        "published",
        "roles",
        "slug",
        "tags",
    )
    search_filters = {
        "dashboard_title": [DashboardTitleOrSlugFilter],
        "id": [DashboardFavoriteFilter, DashboardCertifiedFilter],
        "created_by": [DashboardCreatedByMeFilter, DashboardHasCreatedByFilter],
        "tags": [DashboardTagFilter],
    }

    base_order = ("changed_on", "desc")

    add_model_schema = DashboardPostSchema()
    edit_model_schema = DashboardPutSchema()
    chart_entity_response_schema = ChartEntityResponseSchema()
    dashboard_get_response_schema = DashboardGetResponseSchema()
    dashboard_dataset_schema = DashboardDatasetSchema()
    embedded_response_schema = EmbeddedDashboardResponseSchema()
    embedded_config_schema = EmbeddedDashboardConfigSchema()

    base_filters = [
        ["id", DashboardAccessFilter, lambda: []],
    ]

    order_rel_fields = {
        "slices": ("slice_name", "asc"),
        "owners": ("first_name", "asc"),
        "roles": ("name", "asc"),
    }
    base_related_field_filters = {
        "owners": [["id", BaseFilterRelatedUsers, lambda: []]],
        "created_by": [["id", BaseFilterRelatedUsers, lambda: []]],
        "roles": [["id", BaseFilterRelatedRoles, lambda: []]],
    }

    related_field_filters = {
        "owners": RelatedFieldFilter("first_name", FilterRelatedOwners),
        "roles": RelatedFieldFilter("name", FilterRelatedRoles),
        "created_by": RelatedFieldFilter("first_name", FilterRelatedOwners),
    }
    allowed_rel_fields = {"owners", "roles", "created_by", "changed_by"}

    openapi_spec_tag = "Dashboards"
    """ Override the name set for this collection of endpoints """
    openapi_spec_component_schemas = (
        ChartEntityResponseSchema,
        DashboardCopySchema,
        DashboardGetResponseSchema,
        DashboardDatasetSchema,
        GetFavStarIdsSchema,
        EmbeddedDashboardResponseSchema,
    )
    apispec_parameter_schemas = {
        "get_delete_ids_schema": get_delete_ids_schema,
        "get_export_ids_schema": get_export_ids_schema,
        "thumbnail_query_schema": thumbnail_query_schema,
        "get_fav_star_ids_schema": get_fav_star_ids_schema,
    }
    openapi_spec_methods = openapi_spec_methods_override
    """ Overrides GET methods OpenApi descriptions """

    def __repr__(self) -> str:
        """Deterministic string representation of the API instance for etag_cache."""
        # pylint: disable=consider-using-f-string
        return "Superset.dashboards.api.DashboardRestApi@v{}{}".format(
            self.appbuilder.app.config["VERSION_STRING"],
            self.appbuilder.app.config["VERSION_SHA"],
        )

    @expose("/<id_or_slug>", methods=("GET",))
    @protect()
    @safe
    @statsd_metrics
    @with_dashboard
    @event_logger.log_this_with_extra_payload
    # pylint: disable=arguments-differ,arguments-renamed
    def get(
        self,
        dash: Dashboard,
        add_extra_log_payload: Callable[..., None] = lambda **kwargs: None,
    ) -> Response:
        """Get a dashboard.
        ---
        get:
          summary: Get a dashboard
          parameters:
          - in: path
            schema:
              type: string
            name: id_or_slug
            description: Either the id of the dashboard, or its slug
          responses:
            200:
              description: Dashboard
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      result:
                        $ref: '#/components/schemas/DashboardGetResponseSchema'
            400:
              $ref: '#/components/responses/400'
            401:
              $ref: '#/components/responses/401'
            403:
              $ref: '#/components/responses/403'
            404:
              $ref: '#/components/responses/404'
        """
        result = self.dashboard_get_response_schema.dump(dash)
        add_extra_log_payload(
            dashboard_id=dash.id, action=f"{self.__class__.__name__}.get"
        )
        return self.response(200, result=result)

    @expose("/<id_or_slug>/datasets", methods=("GET",))
    @protect()
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.get_datasets",
        log_to_statsd=False,
    )
    def get_datasets(self, id_or_slug: str) -> Response:
        """Get dashboard's datasets.
        ---
        get:
          summary: Get dashboard's datasets
          description: >-
            Returns a list of a dashboard's datasets. Each dataset includes only
            the information necessary to render the dashboard's charts.
          parameters:
          - in: path
            schema:
              type: string
            name: id_or_slug
            description: Either the id of the dashboard, or its slug
          responses:
            200:
              description: Dashboard dataset definitions
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      result:
                        type: array
                        items:
                          $ref: '#/components/schemas/DashboardDatasetSchema'
            400:
              $ref: '#/components/responses/400'
            401:
              $ref: '#/components/responses/401'
            403:
              $ref: '#/components/responses/403'
            404:
              $ref: '#/components/responses/404'
        """
        try:
            datasets = DashboardDAO.get_datasets_for_dashboard(id_or_slug)
            result = [
                self.dashboard_dataset_schema.dump(dataset) for dataset in datasets
            ]
            return self.response(200, result=result)
        except (TypeError, ValueError) as err:
            return self.response_400(
                message=gettext(
                    "Dataset schema is invalid, caused by: %(error)s", error=str(err)
                )
            )
        except DashboardAccessDeniedError:
            return self.response_403()
        except DashboardNotFoundError:
            return self.response_404()

    @expose("/<id_or_slug>/charts", methods=("GET",))
    @protect()
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.get_charts",
        log_to_statsd=False,
    )
    def get_charts(self, id_or_slug: str) -> Response:
        """Get a dashboard's chart definitions.
        ---
        get:
          summary: Get a dashboard's chart definitions.
          parameters:
          - in: path
            schema:
              type: string
            name: id_or_slug
          responses:
            200:
              description: Dashboard chart definitions
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      result:
                        type: array
                        items:
                          $ref: '#/components/schemas/ChartEntityResponseSchema'
            400:
              $ref: '#/components/responses/400'
            401:
              $ref: '#/components/responses/401'
            403:
              $ref: '#/components/responses/403'
            404:
              $ref: '#/components/responses/404'
        """
        try:
            charts = DashboardDAO.get_charts_for_dashboard(id_or_slug)
            result = [self.chart_entity_response_schema.dump(chart) for chart in charts]

            if is_feature_enabled("REMOVE_SLICE_LEVEL_LABEL_COLORS"):
                # dashboard metadata has dashboard-level label_colors,
                # so remove slice-level label_colors from its form_data
                for chart in result:
                    form_data = chart.get("form_data")
                    form_data.pop("label_colors", None)

            return self.response(200, result=result)
        except DashboardAccessDeniedError:
            return self.response_403()
        except DashboardNotFoundError:
            return self.response_404()

    @expose("/", methods=("POST",))
    @protect()
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.post",
        log_to_statsd=False,
    )
    @requires_json
    def post(self) -> Response:
        """Create a new dashboard.
        ---
        post:
          summary: Create a new dashboard
          requestBody:
            description: Dashboard schema
            required: true
            content:
              application/json:
                schema:
                  $ref: '#/components/schemas/{{self.__class__.__name__}}.post'
          responses:
            201:
              description: Dashboard added
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      id:
                        type: number
                      result:
                        $ref: '#/components/schemas/{{self.__class__.__name__}}.post'
            400:
              $ref: '#/components/responses/400'
            401:
              $ref: '#/components/responses/401'
            404:
              $ref: '#/components/responses/404'
            500:
              $ref: '#/components/responses/500'
        """
        item = request.json

        try:
            item = self.add_model_schema.load(request.json)
        # This validates custom Schema with custom validations
        except ValidationError as error:
            return self.response_400(message=error.messages)
        try:
            new_model = CreateDashboardCommand(item).run()
            return self.response(201, id=new_model.id, result=item)
        except DashboardInvalidError as ex:
            return self.response_422(message=ex.normalized_messages())
        except DashboardCreateFailedError as ex:
            logger.error(
                "Error creating model %s: %s",
                self.__class__.__name__,
                str(ex),
                exc_info=True,
            )
            return self.response_422(message=str(ex))

    @expose("/<pk>", methods=("PUT",))
    # @protect()
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.put",
        log_to_statsd=False,
    )
    @requires_json
    def put(self, pk: int) -> Response:
        """Update a dashboard.
        ---
        put:
          summary: Update a dashboard
          parameters:
          - in: path
            schema:
              type: integer
            name: pk
          requestBody:
            description: Dashboard schema
            required: true
            content:
              application/json:
                schema:
                  $ref: '#/components/schemas/{{self.__class__.__name__}}.put'
          responses:
            200:
              description: Dashboard changed
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      id:
                        type: number
                      result:
                        $ref: '#/components/schemas/{{self.__class__.__name__}}.put'
                      last_modified_time:
                        type: number
            400:
              $ref: '#/components/responses/400'
            401:
              $ref: '#/components/responses/401'
            403:
              $ref: '#/components/responses/403'
            404:
              $ref: '#/components/responses/404'
            422:
              $ref: '#/components/responses/422'
            500:
              $ref: '#/components/responses/500'
        """
        try:
            logger.info(f"The request is coming...")
            # 加载并验证请求数据
            item = self.edit_model_schema.load(request.json)
            logger.info(f"The update permission body is: {item}")
        except ValidationError as error:
            logger.error(f"Validation error while updating dashboard: {error.messages}")
            return self.response_400(message=error.messages)

        try:
            # 检查是否需要跳过权限检查
            if 'published' in item:
                logger.info("Published flag is exist. Skipping permission checks.")
                # 直接执行更新操作
                changed_model = UpdateDashboardCommand(pk, item).run()
            else:
                # 获取当前用户
                user = get_current_user_object()
                if not user:
                    logger.warning("No user found while updating dashboard.")
                    raise DashboardForbiddenError(
                        "No user found to assign permissions.")
                user_id = user.id  # 获取当前用户的ID
                # 获取用户的角色
                role_ids = DashboardRestApi.get_user_role_ids(user)
                logger.info(f"Current user's role IDs: {role_ids}")
                json_data = item.get("json_metadata")
                logger.info(f"json_data: {json_data}")
                charts = DashboardDAO.extract_chart_info(json_data=json_data)
                logger.info(f"charts: {charts}")
                for chart in charts:
                    chart_id = chart.get("chartId")
                    slice_name = ChartDAO.get_slice_name_by_id(chart_id)

                    # 调用 DashboardDAO 的方法检查权限
                    is_admin = DashboardPermissions.check_chart_admin_permissions(
                        user_id=user_id, role_ids=role_ids, chart_id=chart_id
                    )
                    logger.info(f"DashboardRestApi's is_admin: {is_admin}")
                    if not is_admin:
                        logger.warning(
                            f"User does not have admin permissions for chartId={chart_id}, "
                            f"sliceName={slice_name}"
                        )
                        # 返回 403 错误并提示 sliceName
                        return make_response(
                            {
                                "message": f"chart:{slice_name}, chartId: {chart_id}"
                                           f"你没有管理员权限，无法保存"
                            },
                            403,
                        )
                changed_model = UpdateDashboardCommand(pk, item).run()
            last_modified_time = changed_model.changed_on.replace(
                microsecond=0
            ).timestamp()
            response = self.response(
                200,
                id=changed_model.id,
                result=item,
                last_modified_time=last_modified_time,
            )

        except DashboardNotFoundError:
            return self.response_404()

        except DashboardForbiddenError:
            return self.response_403()

        except DashboardInvalidError as ex:
            logger.error(f"Invalid dashboard data: {ex.normalized_messages()}")
            return self.response_422(message=ex.normalized_messages())

        except DashboardUpdateFailedError as ex:
            logger.error(
                "Error updating model %s: %s",
                self.__class__.__name__,
                str(ex),
                exc_info=True,
            )
            return self.response_422(message=str(ex))

        except SQLAlchemyError as ex:
            logger.error(
                f"Database error while updating dashboard: {ex}",
                exc_info=True,
            )
            # 不需要在这里回滚，因为在 `DashboardPermissions.update_dashboard_with_permissions`
            # 中已经处理了
            return self.response_500(message="Internal server error.")

        except Exception as ex:
            logger.error(
                f"Unexpected error while updating dashboard: {ex}",
                exc_info=True,
            )
            # 不需要在这里回滚，因为在 `DashboardPermissions.update_dashboard_with_permissions`
            # 中已经处理了
            return self.response_500(message="Internal server error.")
        return response

    @expose("/<pk>", methods=("DELETE",))
    @protect()
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.delete",
        log_to_statsd=False,
    )
    def delete(self, pk: int) -> Response:
        """Delete a dashboard.
        ---
        delete:
          summary: Delete a dashboard
          parameters:
          - in: path
            schema:
              type: integer
            name: pk
          responses:
            200:
              description: Dashboard deleted
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      message:
                        type: string
            401:
              $ref: '#/components/responses/401'
            403:
              $ref: '#/components/responses/403'
            404:
              $ref: '#/components/responses/404'
            422:
              $ref: '#/components/responses/422'
            500:
              $ref: '#/components/responses/500'
        """
        try:
            DeleteDashboardCommand([pk]).run()
            return self.response(200, message="OK")
        except DashboardNotFoundError:
            return self.response_404()
        except DashboardForbiddenError:
            return self.response_403()
        except DashboardDeleteFailedError as ex:
            logger.error(
                "Error deleting model %s: %s",
                self.__class__.__name__,
                str(ex),
                exc_info=True,
            )
            return self.response_422(message=str(ex))

    @expose("/", methods=("DELETE",))
    @protect()
    @safe
    @statsd_metrics
    @rison(get_delete_ids_schema)
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.bulk_delete",
        log_to_statsd=False,
    )
    def bulk_delete(self, **kwargs: Any) -> Response:
        """Bulk delete dashboards.
        ---
        delete:
          summary: Bulk delete dashboards
          parameters:
          - in: query
            name: q
            content:
              application/json:
                schema:
                  $ref: '#/components/schemas/get_delete_ids_schema'
          responses:
            200:
              description: Dashboard bulk delete
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      message:
                        type: string
            401:
              $ref: '#/components/responses/401'
            403:
              $ref: '#/components/responses/403'
            404:
              $ref: '#/components/responses/404'
            422:
              $ref: '#/components/responses/422'
            500:
              $ref: '#/components/responses/500'
        """
        item_ids = kwargs["rison"]
        try:
            DeleteDashboardCommand(item_ids).run()
            return self.response(
                200,
                message=ngettext(
                    "Deleted %(num)d dashboard",
                    "Deleted %(num)d dashboards",
                    num=len(item_ids),
                ),
            )
        except DashboardNotFoundError:
            return self.response_404()
        except DashboardForbiddenError:
            return self.response_403()
        except DashboardDeleteFailedError as ex:
            return self.response_422(message=str(ex))

    @expose("/export/", methods=("GET",))
    @protect()
    @safe
    @statsd_metrics
    @rison(get_export_ids_schema)
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.export",
        log_to_statsd=False,
    )
    def export(self, **kwargs: Any) -> Response:  # pylint: disable=too-many-locals
        """Download multiple dashboards as YAML files.
        ---
        get:
          summary: Download multiple dashboards as YAML files
          parameters:
          - in: query
            name: q
            content:
              application/json:
                schema:
                  $ref: '#/components/schemas/get_export_ids_schema'
          responses:
            200:
              description: Dashboard export
              content:
                text/plain:
                  schema:
                    type: string
            400:
              $ref: '#/components/responses/400'
            401:
              $ref: '#/components/responses/401'
            404:
              $ref: '#/components/responses/404'
            422:
              $ref: '#/components/responses/422'
            500:
              $ref: '#/components/responses/500'
        """
        requested_ids = kwargs["rison"]
        token = request.args.get("token")

        if is_feature_enabled("VERSIONED_EXPORT"):
            timestamp = datetime.now().strftime("%Y%m%dT%H%M%S")
            root = f"dashboard_export_{timestamp}"
            filename = f"{root}.zip"

            buf = BytesIO()
            with ZipFile(buf, "w") as bundle:
                try:
                    for file_name, file_content in ExportDashboardsCommand(
                        requested_ids
                    ).run():
                        with bundle.open(f"{root}/{file_name}", "w") as fp:
                            fp.write(file_content.encode())
                except DashboardNotFoundError:
                    return self.response_404()
            buf.seek(0)

            response = send_file(
                buf,
                mimetype="application/zip",
                as_attachment=True,
                download_name=filename,
            )
            if token:
                response.set_cookie(token, "done", max_age=600)
            return response

        query = self.datamodel.session.query(Dashboard).filter(
            Dashboard.id.in_(requested_ids)
        )
        query = self._base_filters.apply_all(query)
        ids = {item.id for item in query.all()}
        if not ids:
            return self.response_404()
        export = Dashboard.export_dashboards(ids)
        resp = make_response(export, 200)
        resp.headers["Content-Disposition"] = generate_download_headers("json")[
            "Content-Disposition"
        ]
        if token:
            resp.set_cookie(token, "done", max_age=600)
        return resp

    @expose("/<pk>/thumbnail/<digest>/", methods=("GET",))
    @protect()
    @safe
    @rison(thumbnail_query_schema)
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.thumbnail",
        log_to_statsd=False,
    )
    def thumbnail(self, pk: int, digest: str, **kwargs: Any) -> WerkzeugResponse:
        """Compute async or get already computed dashboard thumbnail from cache.
        ---
        get:
          summary: Get dashboard's thumbnail
          description: >-
            Computes async or get already computed dashboard thumbnail from cache.
          parameters:
          - in: path
            schema:
              type: integer
            name: pk
          - in: path
            name: digest
            description: A hex digest that makes this dashboard unique
            schema:
              type: string
          - in: query
            name: q
            content:
              application/json:
                schema:
                  $ref: '#/components/schemas/thumbnail_query_schema'
          responses:
            200:
              description: Dashboard thumbnail image
              content:
               image/*:
                 schema:
                   type: string
                   format: binary
            202:
              description: Thumbnail does not exist on cache, fired async to compute
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      message:
                        type: string
            302:
              description: Redirects to the current digest
            401:
              $ref: '#/components/responses/401'
            404:
              $ref: '#/components/responses/404'
            422:
              $ref: '#/components/responses/422'
            500:
              $ref: '#/components/responses/500'
        """
        dashboard = cast(Dashboard, self.datamodel.get(pk, self._base_filters))
        if not dashboard:
            return self.response_404()

        dashboard_url = get_url_path(
            "Superset.dashboard", dashboard_id_or_slug=dashboard.id
        )
        # If force, request a screenshot from the workers
        current_user = get_current_user()
        if kwargs["rison"].get("force", False):
            cache_dashboard_thumbnail.delay(
                current_user=current_user,
                dashboard_id=dashboard.id,
                force=True,
            )
            return self.response(202, message="OK Async")
        # fetch the dashboard screenshot using the current user and cache if set
        screenshot = DashboardScreenshot(
            dashboard_url, dashboard.digest
        ).get_from_cache(cache=thumbnail_cache)
        # If the screenshot does not exist, request one from the workers
        if not screenshot:
            self.incr_stats("async", self.thumbnail.__name__)
            cache_dashboard_thumbnail.delay(
                current_user=current_user,
                dashboard_id=dashboard.id,
                force=True,
            )
            return self.response(202, message="OK Async")
        # If digests
        if dashboard.digest != digest:
            self.incr_stats("redirect", self.thumbnail.__name__)
            return redirect(
                url_for(
                    f"{self.__class__.__name__}.thumbnail",
                    pk=pk,
                    digest=dashboard.digest,
                )
            )
        self.incr_stats("from_cache", self.thumbnail.__name__)
        return Response(
            FileWrapper(screenshot), mimetype="image/png", direct_passthrough=True
        )

    @expose("/favorite_status/", methods=("GET",))
    @protect()
    @safe
    @statsd_metrics
    @rison(get_fav_star_ids_schema)
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}"
                                             f".favorite_status",
        log_to_statsd=False,
    )
    def favorite_status(self, **kwargs: Any) -> Response:
        """Check favorited dashboards for current user.
        ---
        get:
          summary: Check favorited dashboards for current user
          parameters:
          - in: query
            name: q
            content:
              application/json:
                schema:
                  $ref: '#/components/schemas/get_fav_star_ids_schema'
          responses:
            200:
              description:
              content:
                application/json:
                  schema:
                    $ref: "#/components/schemas/GetFavStarIdsSchema"
            400:
              $ref: '#/components/responses/400'
            401:
              $ref: '#/components/responses/401'
            404:
              $ref: '#/components/responses/404'
            500:
              $ref: '#/components/responses/500'
        """
        requested_ids = kwargs["rison"]
        dashboards = DashboardDAO.find_by_ids(requested_ids)
        if not dashboards:
            return self.response_404()

        favorited_dashboard_ids = DashboardDAO.favorited_ids(dashboards)
        res = [
            {"id": request_id, "value": request_id in favorited_dashboard_ids}
            for request_id in requested_ids
        ]
        return self.response(200, result=res)

    @expose("/<pk>/favorites/", methods=("POST",))
    @protect()
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}"
                                             f".add_favorite",
        log_to_statsd=False,
    )
    def add_favorite(self, pk: int) -> Response:
        """Mark the dashboard as favorite for the current user.
        ---
        post:
          summary: Mark the dashboard as favorite for the current user
          parameters:
          - in: path
            schema:
              type: integer
            name: pk
          responses:
            200:
              description: Dashboard added to favorites
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      result:
                        type: object
            401:
              $ref: '#/components/responses/401'
            404:
              $ref: '#/components/responses/404'
            500:
              $ref: '#/components/responses/500'
        """
        dashboard = DashboardDAO.find_by_id(pk)
        if not dashboard:
            return self.response_404()

        DashboardDAO.add_favorite(dashboard)
        return self.response(200, result="OK")

    @expose("/<pk>/favorites/", methods=("DELETE",))
    @protect()
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}"
                                             f".remove_favorite",
        log_to_statsd=False,
    )
    def remove_favorite(self, pk: int) -> Response:
        """Remove the dashboard from the user favorite list.
        ---
        delete:
          summary: Remove the dashboard from the user favorite list
          parameters:
          - in: path
            schema:
              type: integer
            name: pk
          responses:
            200:
              description: Dashboard removed from favorites
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      result:
                        type: object
            401:
              $ref: '#/components/responses/401'
            404:
              $ref: '#/components/responses/404'
            500:
              $ref: '#/components/responses/500'
        """
        dashboard = DashboardDAO.find_by_id(pk)
        if not dashboard:
            return self.response_404()

        DashboardDAO.remove_favorite(dashboard)
        return self.response(200, result="OK")

    @expose("/import/", methods=("POST",))
    @protect()
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.import_",
        log_to_statsd=False,
    )
    @requires_form_data
    def import_(self) -> Response:
        """Import dashboard(s) with associated charts/datasets/databases.
        ---
        post:
          summary: Import dashboard(s) with associated charts/datasets/databases
          requestBody:
            required: true
            content:
              multipart/form-data:
                schema:
                  type: object
                  properties:
                    formData:
                      description: upload file (ZIP or JSON)
                      type: string
                      format: binary
                    passwords:
                      description: >-
                        JSON map of passwords for each featured database in the
                        ZIP file. If the ZIP includes a database config in the path
                        `databases/MyDatabase.yaml`, the password should be provided
                        in the following format:
                        `{"databases/MyDatabase.yaml": "my_password"}`.
                      type: string
                    overwrite:
                      description: overwrite existing dashboards?
                      type: boolean
                    ssh_tunnel_passwords:
                      description: >-
                        JSON map of passwords for each ssh_tunnel associated to a
                        featured database in the ZIP file. If the ZIP includes a
                        ssh_tunnel config in the path `databases/MyDatabase.yaml`,
                        the password should be provided in the following format:
                        `{"databases/MyDatabase.yaml": "my_password"}`.
                      type: string
                    ssh_tunnel_private_keys:
                      description: >-
                        JSON map of private_keys for each ssh_tunnel associated to a
                        featured database in the ZIP file. If the ZIP includes a
                        ssh_tunnel config in the path `databases/MyDatabase.yaml`,
                        the private_key should be provided in the following format:
                        `{"databases/MyDatabase.yaml": "my_private_key"}`.
                      type: string
                    ssh_tunnel_private_key_passwords:
                      description: >-
                        JSON map of private_key_passwords for each ssh_tunnel associated
                        to a featured database in the ZIP file. If the ZIP includes a
                        ssh_tunnel config in the path `databases/MyDatabase.yaml`,
                        the private_key should be provided in the following format:
                        `{"databases/MyDatabase.yaml": "my_private_key_password"}`.
                      type: string
          responses:
            200:
              description: Dashboard import result
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      message:
                        type: string
            400:
              $ref: '#/components/responses/400'
            401:
              $ref: '#/components/responses/401'
            422:
              $ref: '#/components/responses/422'
            500:
              $ref: '#/components/responses/500'
        """
        upload = request.files.get("formData")
        if not upload:
            return self.response_400()
        if is_zipfile(upload):
            with ZipFile(upload) as bundle:
                contents = get_contents_from_bundle(bundle)
        else:
            upload.seek(0)
            contents = {upload.filename: upload.read()}

        if not contents:
            raise NoValidFilesFoundError()

        passwords = (
            json.loads(request.form["passwords"])
            if "passwords" in request.form
            else None
        )
        overwrite = request.form.get("overwrite") == "true"

        ssh_tunnel_passwords = (
            json.loads(request.form["ssh_tunnel_passwords"])
            if "ssh_tunnel_passwords" in request.form
            else None
        )
        ssh_tunnel_private_keys = (
            json.loads(request.form["ssh_tunnel_private_keys"])
            if "ssh_tunnel_private_keys" in request.form
            else None
        )
        ssh_tunnel_priv_key_passwords = (
            json.loads(request.form["ssh_tunnel_private_key_passwords"])
            if "ssh_tunnel_private_key_passwords" in request.form
            else None
        )

        command = ImportDashboardsCommand(
            contents,
            passwords=passwords,
            overwrite=overwrite,
            ssh_tunnel_passwords=ssh_tunnel_passwords,
            ssh_tunnel_private_keys=ssh_tunnel_private_keys,
            ssh_tunnel_priv_key_passwords=ssh_tunnel_priv_key_passwords,
        )
        command.run()
        return self.response(200, message="OK")

    @expose("/<id_or_slug>/embedded", methods=("GET",))
    @protect()
    @safe
    @permission_name("read")
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.get_embedded",
        log_to_statsd=False,
    )
    @with_dashboard
    def get_embedded(self, dashboard: Dashboard) -> Response:
        """Get the dashboard's embedded configuration.
        ---
        get:
          summary: Get the dashboard's embedded configuration
          parameters:
          - in: path
            schema:
              type: string
            name: id_or_slug
            description: The dashboard id or slug
          responses:
            200:
              description: Result contains the embedded dashboard config
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      result:
                        $ref: '#/components/schemas/EmbeddedDashboardResponseSchema'
            401:
              $ref: '#/components/responses/401'
            500:
              $ref: '#/components/responses/500'
        """
        if not dashboard.embedded:
            return self.response(404)
        embedded: EmbeddedDashboard = dashboard.embedded[0]
        result = self.embedded_response_schema.dump(embedded)
        return self.response(200, result=result)

    @expose("/<id_or_slug>/embedded", methods=["POST", "PUT"])
    @protect()
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.set_embedded",
        log_to_statsd=False,
    )
    @with_dashboard
    def set_embedded(self, dashboard: Dashboard) -> Response:
        """Set a dashboard's embedded configuration.
        ---
        post:
          summary: Set a dashboard's embedded configuration
          parameters:
          - in: path
            schema:
              type: string
            name: id_or_slug
            description: The dashboard id or slug
          requestBody:
            description: The embedded configuration to set
            required: true
            content:
              application/json:
                schema: EmbeddedDashboardConfigSchema
          responses:
            200:
              description: Successfully set the configuration
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      result:
                        $ref: '#/components/schemas/EmbeddedDashboardResponseSchema'
            401:
              $ref: '#/components/responses/401'
            500:
              $ref: '#/components/responses/500'
        put:
          description: >-
            Sets a dashboard's embedded configuration.
          parameters:
          - in: path
            schema:
              type: string
            name: id_or_slug
            description: The dashboard id or slug
          requestBody:
            description: The embedded configuration to set
            required: true
            content:
              application/json:
                schema: EmbeddedDashboardConfigSchema
          responses:
            200:
              description: Successfully set the configuration
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      result:
                        $ref: '#/components/schemas/EmbeddedDashboardResponseSchema'
            401:
              $ref: '#/components/responses/401'
            500:
              $ref: '#/components/responses/500'
        """
        try:
            body = self.embedded_config_schema.load(request.json)
            embedded = EmbeddedDashboardDAO.upsert(dashboard, body["allowed_domains"])
            result = self.embedded_response_schema.dump(embedded)
            return self.response(200, result=result)
        except ValidationError as error:
            return self.response_400(message=error.messages)

    @expose("/<id_or_slug>/embedded", methods=("DELETE",))
    @protect()
    @safe
    @permission_name("set_embedded")
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args,
                      **kwargs: f"{self.__class__.__name__}.delete_embedded",
        log_to_statsd=False,
    )
    @with_dashboard
    def delete_embedded(self, dashboard: Dashboard) -> Response:
        """Delete a dashboard's embedded configuration.
        ---
        delete:
          summary: Delete a dashboard's embedded configuration
          parameters:
          - in: path
            schema:
              type: string
            name: id_or_slug
            description: The dashboard id or slug
          responses:
            200:
              description: Successfully removed the configuration
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      message:
                        type: string
            401:
              $ref: '#/components/responses/401'
            500:
              $ref: '#/components/responses/500'
        """
        EmbeddedDashboardDAO.delete(dashboard.embedded)
        return self.response(200, message="OK")

    @expose("/<id_or_slug>/copy/", methods=("POST",))
    @protect()
    @safe
    @permission_name("write")
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.copy_dash",
        log_to_statsd=False,
    )
    @with_dashboard
    def copy_dash(self, original_dash: Dashboard) -> Response:
        """Create a copy of an existing dashboard.
        ---
        post:
          summary: Create a copy of an existing dashboard
          parameters:
          - in: path
            schema:
              type: string
            name: id_or_slug
            description: The dashboard id or slug
          requestBody:
            required: true
            content:
              application/json:
                schema:
                  $ref: '#/components/schemas/DashboardCopySchema'
          responses:
            200:
              description: Id of new dashboard and last modified time
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      id:
                        type: number
                      last_modified_time:
                        type: number
            400:
              $ref: '#/components/responses/400'
            401:
              $ref: '#/components/responses/401'
            403:
              $ref: '#/components/responses/403'
            404:
              $ref: '#/components/responses/404'
            500:
              $ref: '#/components/responses/500'
        """
        try:
            data = DashboardCopySchema().load(request.json)
        except ValidationError as error:
            return self.response_400(message=error.messages)

        try:
            dash = DashboardDAO.copy_dashboard(original_dash, data)
        except DashboardForbiddenError:
            return self.response_403()

        return self.response(
            200,
            result={
                "id": dash.id,
                "last_modified_time": dash.changed_on.replace(
                    microsecond=0
                ).timestamp(),
            },
        )

    def _filter_dashboards_based_on_permissions(
        self, original_result: list, original_ids: list,
        current_user
    ) -> tuple:
        """
        根据用户和角色权限，过滤仪表盘数据。
        支持多个权限类型（例如：'read' 和 'edit'）。

        :param original_result: 原始的仪表盘数据列表
        :param original_ids: 原始的仪表盘 ID 列表
        :param current_user: 当前用户对象
        :return: 过滤后的仪表盘数据列表和允许的仪表盘 ID 列表
        """
        # 获取用户的 'read' 和 'edit' 权限
        user_read_permissions = DashboardPermissions.get_user_permissions(
            current_user.id, 'read')
        logger.info(f"User {current_user.id} read permissions: {user_read_permissions}")
        user_edit_permissions = DashboardPermissions.get_user_permissions(
            current_user.id, 'edit')
        logger.info(f"User {current_user.id} edit permissions: {user_edit_permissions}")
        user_permissions = user_read_permissions + user_edit_permissions

        # 获取角色的 'read' 和 'edit' 权限
        role_read_permissions = DashboardPermissions.get_role_permissions(
            current_user.roles, 'read')
        logger.info(f"User's roles read permissions: {role_read_permissions}")
        role_edit_permissions = DashboardPermissions.get_role_permissions(
            current_user.roles, 'edit')
        logger.info(f"User's roles edit permissions: {role_edit_permissions}")
        role_permissions = role_read_permissions + role_edit_permissions

        # 合并用户和角色的权限，去重
        all_permissions = set(user_permissions + role_permissions)
        logger.info(f"User {current_user.id} all permissions: {all_permissions}")

        # 过滤用户有权限访问的仪表盘 ID
        logger.info(f"Original dashboard IDs: {original_ids}")
        allowed_ids = [
            dashboard_id
            for dashboard_id in original_ids
            if dashboard_id in all_permissions
        ]
        logger.info(f"Allowed dashboard IDs: {allowed_ids}")

        # 过滤结果，只返回用户有权限的仪表盘
        filtered_result = [
            dashboard for dashboard in original_result if dashboard["id"] in allowed_ids
        ]

        return filtered_result, allowed_ids

    @expose("/<int:dashboard_id>/access-info", methods=["GET"])
    # @protect()
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}"
                                             f".access_info",
        log_to_statsd=False,
    )
    def get_access_info(self, dashboard_id: int):
        """
        获取指定 chart 的访问权限信息。
        """
        try:
            access_info = DashboardDAO.get_dashboard_access_info(dashboard_id)
            return self.response(200, result=access_info)
        except Exception as ex:
            logger.error(f"Error fetching dashboard access info: {ex}")
            return self.response_500(message="Failed to fetch dashboard access info.")

    @expose('/<int:dashboard_id>/add-collaborator', methods=["POST"])
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args,
                      **kwargs: f"{self.__class__.__name__}.add_collaborator",
        log_to_statsd=False,
    )
    def add_collaborator(self, dashboard_id: int):
        """
        添加协作者接口:
        - 检查协作者是否已经存在。
        - 如果不存在，添加到协作者列表。
        """
        data = request.json
        collaborator_id = data.get("id")
        collaborator_type = data.get("type")
        logger.info(f"当前的collaborator_id: {collaborator_id}")
        logger.info(f"当前的collaborator_type: {collaborator_type}")
        logger.info(f"当前的dashboardId是: {dashboard_id}")

        # 添加一个映射，将中文类型映射为英文类型
        type_mapping = {
            "用户": "user",
            "角色": "role",
        }

        # 将 collaborator_type 转换为后端识别的值
        collaborator_type = type_mapping.get(collaborator_type, collaborator_type)

        if not collaborator_id or collaborator_type not in ["user", "role"]:
            return self.response_400(
                message=f"Invalid collaborator_type: "
                        f"{collaborator_type}. "
                        f"Must be 'user' or 'role'."
            )

        # 检查协作者是否已经存在
        try:
            dashboard = DashboardDAO.find_dashboard(dashboard_id=dashboard_id)
            if not dashboard:
                return self.response_404(message=f"Dashboard ID {dashboard_id} 不存在。")

            current_user = get_current_user_object()
            user_id = current_user.id
            logger.info(f"current_user id is: {user_id}")
            # 检查当前用户对该图表是否具备 can_read, can_edit, can_delete, can_add 四种权限
            user_permissions = DashboardPermissions.get_permissions_for_dashboard(
                user_id,
                dashboard_id)
            if not all(user_permissions.get(permission, False) for permission in
                       ["can_read", "can_edit", "can_delete", "can_add"]):
                response = make_response(
                    jsonify({
                        "error": "您没有足够的权限来修改其他人的图表权限。",
                        "code": 403,
                        "message": "Forbidden"
                    }), 403
                )
                return response
            
            if DashboardDAO.is_collaborator_exist(dashboard_id, collaborator_id,
                                                  collaborator_type):
                response = make_response(
                    jsonify({
                        "error": f"该用户已经是协作者了！",
                        "code": 400,
                        "message": "BAD REQUEST"
                    }), 400
                )
                return response
            # 去查询跟dashboard_id关联的chart列表
            chart_ids = DashboardDAO.get_slice_ids_by_dashboard_id(
                dashboard_id=dashboard_id
            )
            logger.info(f"DashboardRestApi's chart_ids: {chart_ids}")
            chart_datasource_map = {}
            for chart_id in chart_ids:
                datasource_id = ChartDAO.get_datasource_id_by_resource('chart',
                                                                       chart_id)
                if datasource_id:
                    chart_datasource_map[chart_id] = datasource_id
                else:
                    logger.warning(f"Chart ID {chart_id} 没有关联的 Datasource。")
            # # 获取 Dashboard 的 Datasource ID
            # dashboard_datasource_id = DashboardDAO.get_datasource_ids_by_resource(
            #     'dashboard',
            #     resource_id=dashboard_id
            # )
            # logger.info(f"DashboardRestApi's dashboard_datasource_id: "
            #             f"{dashboard_datasource_id}")
            # # 检查协作者对Dashboard数据源的权限检查
            # if dashboard_datasource_id:
            #     if collaborator_type == "user":
            #         has_dashboard_datasource_permission = DashboardPermissions.check_dashboard_datasource_user_permission(
            #             collaborator_id,
            #             dashboard_datasource_id)
            #     elif collaborator_type == "role":
            #         has_dashboard_datasource_permission = DashboardPermissions.check_dashboard_datasource_role_permission(
            #             collaborator_id,
            #             dashboard_datasource_id
            #         )
            # else:
            #     # 如果 Dashboard 没有关联的 Datasource，假设可以赋予基本权限
            #     # 根据业务需求调整，此处假设没有 Datasource 时不赋予权限
            #     has_dashboard_datasource_permission = False
            #     logger.info(f"该用户没有关联的Datasource，暂时不赋予权限")
            # # 如果 Dashboard 有 Datasource 且协作者没有权限，拒绝
            # if dashboard_datasource_id and not has_dashboard_datasource_permission:
            #     return make_response(
            #         jsonify({
            #             "error": f"该{'用户' if collaborator_type == 'user' else '角色'}"
            #                      f"没有权限访问 Dashboard 的数据源！",
            #             "code": 403,
            #             "message": "Forbidden"
            #         }), 403
            #     )
            #
            # # 检查协作者是否有权限
            # authorized_charts = []
            #
            # if collaborator_type == "user":
            #     # 如果是用户类型，检查用户对 chart 是否有权限
            #     for chart_id, datasource_id in chart_datasource_map.items():
            #         has_permission = ChartPermissions.check_user_permission(
            #             collaborator_id,
            #             datasource_id
            #         )
            #         if has_permission:
            #             authorized_charts.append(chart_id)
            # elif collaborator_type == "role":
            #     # 如果是角色类型，检查角色对 chart 是否有权限
            #     for chart_id, datasource_id in chart_datasource_map.items():
            #         has_permission = ChartPermissions.check_role_permission(
            #             collaborator_id,
            #             datasource_id
            #         )
            #         if has_permission:
            #             authorized_charts.append(chart_id)
            # # 处理 Dashboard 的授权
            # if dashboard_datasource_id and has_dashboard_datasource_permission:
            #     # 将 Dashboard 作为一个特殊的资源类型处理
            #     authorized_resources = {
            #         'dashboard': dashboard_id,
            #         'charts': authorized_charts
            #     }
            # else:
            #     authorized_resources = {
            #         'dashboard': None,  # 无法授权 Dashboard
            #         'charts': authorized_charts
            #     }
            #
            # if not authorized_resources:
            #     return make_response(
            #         jsonify({
            #             "error": f"该{'用户' if collaborator_type == 'user' else '角色'}"
            #                      f"对 Dashboard 下的所有 Charts 都没有权限。",
            #             "code": 403,
            #             "message": "Forbidden"
            #         }), 403
            #     )
            #     # 如果不存在，则添加协作者
            # # 检查协作者是否已经是协作者
            # existing_collaborators_charts = []
            # existing_collaborators_dashboard = False
            # charts_to_add = []
            # if authorized_resources['dashboard']:
            #     if DashboardDAO.is_collaborator_exist(dashboard_id,
            #                                           collaborator_id,
            #                                           collaborator_type):
            #         existing_collaborators_dashboard = True
            # for chart_id in authorized_resources['charts']:
            #     if ChartDAO.is_collaborator_exist(chart_id, collaborator_id,
            #                                       collaborator_type):
            #         existing_collaborators_charts.append(chart_id)
            #     else:
            #         charts_to_add.append(chart_id)
            #
            # # 判断是否需要添加 Dashboard
            # if authorized_resources[
            #     'dashboard'] and not existing_collaborators_dashboard:
            #     add_dashboard = True
            # else:
            #     add_dashboard = False
            #
            # # 分配权限
            # if add_dashboard:
            #     DashboardDAO.add_collaborator(dashboard_id,
            #                                   collaborator_id, collaborator_type)
            DashboardDAO.add_collaborator(
                dashboard_id,
                collaborator_id,
                collaborator_type
            )
            for chart_id, datasource_id in chart_datasource_map.items():
                exists = ChartDAO.is_collaborator_exist(chart_id, collaborator_id,
                                                        collaborator_type)
                if exists:
                    logger.info(f"协作者已存在于 Chart ID {chart_id}，跳过添加。")
                    continue

                try:
                    ChartDAO.add_collaborator(
                        chart_id=chart_id,
                        collaborator_id=collaborator_id,
                        collaborator_type=collaborator_type,
                        datasource_id=datasource_id
                    )
                    logger.info(f"成功为 Chart ID {chart_id} 添加协作者。")
                except Exception as e:
                    logger.error(f"为 Chart ID {chart_id} 添加协作者时出错: {e}")

            response_data = {
                "message": f"协作者成功添加了 {len(chart_datasource_map)} 个 Charts。" + (
                    "以及 Dashboard。"), "dashboard": dashboard_id}

            return make_response(
                jsonify(response_data), 200
            )

            # return self.response(
            #     200,
            #     message=f"{collaborator_type} (ID: {collaborator_id}) 添加成功！",
            # )
        except Exception as ex:
            logger.error(f"Error adding collaborator: {ex}")
            return self.response_500(message="Failed to add collaborator.")

    # 增加权限管理的接口
    @expose("/<pk>/permissions/modify", methods=["POST"])
    @safe
    @statsd_metrics
    def modify_permissions(self, pk: int) -> Response:
        """
        修改图表的权限。
        JSON 请求体格式:
        {
          "entity_type": "user" or "role",
          "entity_id": 123,
          "permissions": ["can_read", "can_edit", "can_add", "can_delete"],
          "action": "add" or "remove"
        }
        """
        try:
            current_user = get_current_user_object()
            user_id = current_user.id
            logger.info(f"current_user id is: {user_id}")
            # 检查当前用户对该图表是否具备 can_read, can_edit, can_delete, can_add 四种权限
            user_permissions = DashboardPermissions.get_permissions_for_dashboard(
                user_id,
                pk)
            if not all(user_permissions.get(permission, False) for permission in
                       ["can_read", "can_edit", "can_delete", "can_add"]):
                response = make_response(
                    jsonify({
                        "error": "您没有足够的权限来修改其他人的图表权限。",
                        "code": 403,
                        "message": "Forbidden"
                    }), 403
                )
                return response
            data = request.json
            entity_type = data.get("entity_type")
            entity_id = data.get("entity_id")
            permissions = data.get("permissions", [])
            action = data.get("action")

            # 验证输入
            if entity_type not in ["user", "role"]:
                return self.response_400(
                    message=f"Invalid entity_type: {entity_type}. "
                            f"Must be 'user' or 'role'."
                )
            if not isinstance(entity_id, int):
                return self.response_400(
                    message=f"Invalid entity_id: {entity_id}. Must be an integer."
                )
            if not isinstance(permissions, list) or not all(
                isinstance(p, str) for p in permissions):
                return self.response_400(
                    message="Invalid permissions format. Must be a list of strings."
                )
            if action not in ["add", "remove"]:
                return self.response_400(
                    message=f"Invalid action: {action}. Must be 'add' or 'remove'."
                )

            # Interpret the frontend permissions
            perm_dict = DashboardPermissions.interpret_frontend_permissions(permissions)
            logger.info(f"推导出的权限集合: {perm_dict}")
            # 去查询跟dashboard_id关联的chart列表
            chart_ids = DashboardDAO.get_slice_ids_by_dashboard_id(
                dashboard_id=pk
            )
            logger.info(f"跟dashboard关联的chart_ids: {chart_ids}")
            if action == "add":
                add_perms = [k for k, v in perm_dict.items() if v]
                DashboardDAO.modify_permissions(
                    dashboard_id=pk,
                    entity_type=entity_type,
                    entity_id=entity_id,
                    permissions=add_perms,
                    action="add",
                )

                for chart_id in chart_ids:
                    logger.info(f"开始更新chart_id: {chart_id} 的权限")
                    ChartDAO.modify_permissions(
                        chart_id=chart_id,
                        entity_type=entity_type,
                        entity_id=entity_id,
                        permissions=add_perms,
                        action="add",
                    )
            elif action == "remove":
                remove_perms = [k for k, v in perm_dict.items() if v]
                if "admin" in permissions:
                    # 移除管理员权限时，需要移除所有相关权限
                    remove_perms = ["can_read", "can_edit", "can_add", "can_delete"]
                DashboardDAO.modify_permissions(
                    dashboard_id=pk,
                    entity_type=entity_type,
                    entity_id=entity_id,
                    permissions=remove_perms,
                    action="remove",
                )
                for chart_id in chart_ids:
                    ChartDAO.modify_permissions(
                        chart_id=chart_id,
                        entity_type=entity_type,
                        entity_id=entity_id,
                        permissions=remove_perms,
                        action="remove",
                    )

            return self.response(200, message="权限更新成功。")

        except ValueError as ve:
            logger.error(f"ValueError modifying permissions: {ve}")
            return self.response_400(message=str(ve))
        except Exception as ex:
            logger.error(f"Error modifying permissions: {ex}", exc_info=True)
            return self.response_500(message="权限更新失败。")

    @staticmethod
    def get_user_role_ids(user) -> list:
        """
        获取当前用户的角色ID列表
        :param user: 当前用户对象
        :return: 用户角色ID列表
        """
        return [role.id for role in user.roles]  # 假设 user.roles 是用户角色的列表

    @expose("/_info", methods=["GET"])
    # @protect()  # 确保用户已认证
    def info(self) -> Any:
        """
        获取当前用户对所有图表的权限信息。
        ---
        get:
          summary: 获取所有图表的权限信息
          responses:
            200:
              description: 成功获取权限信息
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      permissions:
                        type: object
                        additionalProperties:
                          type: object
                          properties:
                            can_write:
                              type: boolean
                            can_add:
                              type: boolean
                            can_delete:
                              type: boolean
                            can_read:
                              type: boolean
                            can_export:
                              type: boolean
                            role:
                              type: string
            403:
              description: 权限不足
            500:
              description: 服务器内部错误
        """
        logger.debug("访问 /_info 接口。")

        # 获取当前用户对象
        user = get_current_user_object()
        if not user:
            logger.error("没有用户登录。")
            return self.response_403(message="权限拒绝。")

        logger.info(f"current login user is: {user.first_name} {user.last_name}")
        logger.info(
            f"current login user's role is: {[role.name for role in user.roles]}")

        try:
            # 获取用户对所有仪表盘的权限
            all_permissions = DashboardPermissions.get_all_dashboard_permissions(user)
            if all_permissions is None:
                # 如果没有权限数据，返回空列表
                return self.response(200, info={"permissions": []})

        except Exception as e:
            logger.error(f"获取权限信息时出错: {e}")
            return self.response_500(message="内部服务器错误。")

        # 过滤并格式化权限信息
        filtered_permissions = {}
        for dashboard_id, perm in all_permissions.items():
            # 仅包含用户拥有至少一种权限的图表
            if perm["can_write"] or perm["can_add"] or perm["can_delete"] or perm[
                "can_read"]:
                filtered_permissions[dashboard_id] = {
                    "can_write": perm["can_write"],  # 替换 can_edit 为 can_write
                    "can_add": perm["can_add"],
                    "can_delete": perm["can_delete"],
                    "can_read": perm["can_read"],
                    "can_export": perm["can_export"],  # 基于 can_read 推导
                    "role": perm["role"]
                }
        # 获取全局权限
        global_permissions = {
            "can_write": security_manager.can_access('can_write', 'Dashboard')
        }

        logger.debug(f"获取到的权限信息: {filtered_permissions}")
        res = {"permissions": filtered_permissions,
                                        "global_permissions": global_permissions}
        # 返回 JSON 响应
        return self.response(200, **res)
