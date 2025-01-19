import json
import logging
from datetime import datetime
from io import BytesIO
from typing import Any, cast, Optional, Union
from zipfile import is_zipfile, ZipFile

from flask import redirect, request, Response, send_file, url_for, jsonify, \
    make_response
from flask_appbuilder.api import expose, protect, rison, safe
from flask_appbuilder.hooks import before_request
from flask_appbuilder.models.sqla.interface import SQLAInterface
from flask_appbuilder.api.schemas import get_item_schema, get_list_schema

from superset.exceptions import SupersetException
from superset.tasks.utils import get_current_user_object
from flask_appbuilder.security.sqla.models import User, Role
from flask_appbuilder.exceptions import FABException
from flask_babel import ngettext
from marshmallow import ValidationError
from werkzeug.wrappers import Response as WerkzeugResponse
from werkzeug.wsgi import FileWrapper
from superset import app, is_feature_enabled, thumbnail_cache
from superset.charts.filters import (
    ChartAllTextFilter,
    ChartCertifiedFilter,
    ChartCreatedByMeFilter,
    ChartFavoriteFilter,
    ChartFilter,
    ChartHasCreatedByFilter,
    ChartOwnedCreatedFavoredByMeFilter,
    ChartTagFilter,
)
from superset.charts.schemas import (
    CHART_SCHEMAS,
    ChartCacheWarmUpRequestSchema,
    ChartPostSchema,
    ChartPutSchema,
    get_delete_ids_schema,
    get_export_ids_schema,
    get_fav_star_ids_schema,
    openapi_spec_methods_override,
    screenshot_query_schema,
    thumbnail_query_schema,
)
from superset.charts.permissions import ChartPermissions, get_current_user_role_id
from superset.commands.chart.create import CreateChartCommand
from superset.commands.chart.delete import DeleteChartCommand
from superset.commands.chart.exceptions import (
    ChartCreateFailedError,
    ChartDeleteFailedError,
    ChartForbiddenError,
    ChartInvalidError,
    ChartNotFoundError,
    ChartUpdateFailedError,
    DashboardsForbiddenError,
    CreateChartForbiddenError,
)
from superset.commands.chart.export import ExportChartsCommand
from superset.commands.chart.importers.dispatcher import ImportChartsCommand
from superset.commands.chart.update import UpdateChartCommand
from superset.commands.chart.warm_up_cache import ChartWarmUpCacheCommand
from superset.commands.exceptions import CommandException
from superset.commands.importers.exceptions import (
    IncorrectFormatError,
    NoValidFilesFoundError,
)
from superset.commands.importers.v1.utils import get_contents_from_bundle
from superset.constants import MODEL_API_RW_METHOD_PERMISSION_MAP, RouteMethod
from superset.daos.chart import ChartDAO
from superset.extensions import event_logger, security_manager
from superset.models.slice import Slice
from superset.tasks.thumbnails import cache_chart_thumbnail
from superset.tasks.utils import get_current_user
from superset.utils.screenshots import ChartScreenshot, DEFAULT_CHART_WINDOW_SIZE
from superset.utils.urls import get_url_path
from superset.views.base_api import (
    BaseSupersetModelRestApi,
    RelatedFieldFilter,
    requires_form_data,
    requires_json,
    statsd_metrics,
)
from superset.views.filters import BaseFilterRelatedUsers, FilterRelatedOwners
from flask_appbuilder.exceptions import InvalidOrderByColumnFABException

logger = logging.getLogger(__name__)
config = app.config


class ChartRestApi(BaseSupersetModelRestApi):
    datamodel = SQLAInterface(Slice)

    resource_name = "chart"
    allow_browser_login = True

    @before_request(only=["thumbnail", "screenshot", "cache_screenshot"])
    def ensure_thumbnails_enabled(self) -> Optional[Response]:
        if not is_feature_enabled("THUMBNAILS"):
            return self.response_404()
        return None

    include_route_methods = RouteMethod.REST_MODEL_VIEW_CRUD_SET | {
        RouteMethod.EXPORT,
        RouteMethod.IMPORT,
        RouteMethod.RELATED,
        "bulk_delete",  # not using RouteMethod since locally defined
        "viz_types",
        "favorite_status",
        "add_favorite",
        "remove_favorite",
        "thumbnail",
        "screenshot",
        "cache_screenshot",
        "warm_up_cache",
        "get_access_info",
        "add_collaborator",
        "modify_permissions",
        "get_permissions",
    }
    class_permission_name = "Chart"
    method_permission_name = MODEL_API_RW_METHOD_PERMISSION_MAP
    show_columns = [
        "cache_timeout",
        "certified_by",
        "certification_details",
        "changed_on_delta_humanized",
        "dashboards.dashboard_title",
        "dashboards.id",
        "dashboards.json_metadata",
        "description",
        "id",
        "owners.first_name",
        "owners.id",
        "owners.last_name",
        "dashboards.id",
        "dashboards.dashboard_title",
        "params",
        "slice_name",
        "thumbnail_url",
        "url",
        "viz_type",
        "query_context",
        "is_managed_externally",
        "tags.id",
        "tags.name",
        "tags.type",
    ]

    show_select_columns = show_columns + ["table.id"]
    list_columns = [
        "is_managed_externally",
        "certified_by",
        "certification_details",
        "cache_timeout",
        "changed_by.first_name",
        "changed_by.last_name",
        "changed_by_name",
        "changed_on_delta_humanized",
        "changed_on_dttm",
        "changed_on_utc",
        "created_by.first_name",
        "created_by.id",
        "created_by.last_name",
        "created_by_name",
        "created_on_delta_humanized",
        "datasource_id",
        "datasource_name_text",
        "datasource_type",
        "datasource_url",
        "description",
        "description_markeddown",
        "edit_url",
        "form_data",
        "id",
        "last_saved_at",
        "last_saved_by.id",
        "last_saved_by.first_name",
        "last_saved_by.last_name",
        "owners.first_name",
        "owners.id",
        "owners.last_name",
        "dashboards.id",
        "dashboards.dashboard_title",
        "params",
        "slice_name",
        "slice_url",
        "table.default_endpoint",
        "table.table_name",
        "thumbnail_url",
        "url",
        "viz_type",
        "tags.id",
        "tags.name",
        "tags.type",
    ]
    list_select_columns = list_columns + ["changed_by_fk", "changed_on"]
    order_columns = [
        "changed_by.first_name",
        "changed_on_delta_humanized",
        "datasource_id",
        "datasource_name",
        "last_saved_at",
        "last_saved_by.id",
        "last_saved_by.first_name",
        "last_saved_by.last_name",
        "slice_name",
        "viz_type",
    ]
    search_columns = [
        "created_by",
        "changed_by",
        "last_saved_at",
        "last_saved_by",
        "datasource_id",
        "datasource_name",
        "datasource_type",
        "description",
        "id",
        "owners",
        "dashboards",
        "slice_name",
        "viz_type",
        "tags",
    ]
    base_order = ("changed_on", "desc")
    base_filters = [["id", ChartFilter, lambda: []]]
    search_filters = {
        "id": [
            ChartFavoriteFilter,
            ChartCertifiedFilter,
            ChartOwnedCreatedFavoredByMeFilter,
        ],
        "slice_name": [ChartAllTextFilter],
        "created_by": [ChartHasCreatedByFilter, ChartCreatedByMeFilter],
        "tags": [ChartTagFilter],
    }
    edit_columns = ["slice_name"]
    add_columns = edit_columns

    add_model_schema = ChartPostSchema()
    edit_model_schema = ChartPutSchema()

    openapi_spec_tag = "Charts"
    openapi_spec_component_schemas = CHART_SCHEMAS

    apispec_parameter_schemas = {
        "screenshot_query_schema": screenshot_query_schema,
        "get_delete_ids_schema": get_delete_ids_schema,
        "get_export_ids_schema": get_export_ids_schema,
        "get_fav_star_ids_schema": get_fav_star_ids_schema,
    }
    openapi_spec_methods = openapi_spec_methods_override

    order_rel_fields = {
        "slices": ("slice_name", "asc"),
        "owners": ("first_name", "asc"),
    }
    base_related_field_filters = {
        "owners": [["id", BaseFilterRelatedUsers, lambda: []]],
        "created_by": [["id", BaseFilterRelatedUsers, lambda: []]],
    }
    related_field_filters = {
        "owners": RelatedFieldFilter("first_name", FilterRelatedOwners),
        "created_by": RelatedFieldFilter("first_name", FilterRelatedOwners),
    }

    allowed_rel_fields = {"owners", "created_by", "changed_by"}

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
        """Create a new chart.
        ---
        post:
          summary: Create a new chart
          requestBody:
            description: Chart schema
            required: true
            content:
              application/json:
                schema:
                  $ref: '#/components/schemas/{{self.__class__.__name__}}.post'
          responses:
            201:
              description: Chart added
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
            403:
              $ref: '#/components/responses/403'
            422:
              $ref: '#/components/responses/422'
            500:
              $ref: '#/components/responses/500'
        """

        try:
            item = self.add_model_schema.load(request.json)
        except ValidationError as error:
            return self.response_400(message=error.messages)

        try:
            new_model = CreateChartCommand(item).run()
            return self.response(201, id=new_model.id, result=item)
        except CreateChartForbiddenError as ex:
            logger.error(f"ChartsForbidden error: {ex.message}")
            return self.response(ex.status, message=ex.message)
        except DashboardsForbiddenError as ex:
            logger.error(f"DashboardsForbidden error: {ex.message}")
            return self.response(ex.status, message=ex.message)
        except ChartInvalidError as ex:
            logger.error(f"Invalid chart data: {ex.normalized_messages()}")
            return self.response_422(message=ex.normalized_messages())
        except ChartCreateFailedError as ex:
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
        """Update a chart.
        ---
        put:
          summary: Update a chart
          parameters:
          - in: path
            schema:
              type: integer
            name: pk
          requestBody:
            description: Chart schema
            required: true
            content:
              application/json:
                schema:
                  $ref: '#/components/schemas/{{self.__class__.__name__}}.put'
          responses:
            200:
              description: Chart changed
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      id:
                        type: number
                      result:
                        $ref: '#/components/schemas/{{self.__class__.__name__}}.put'
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
            logger.error(f"the request body: {request.json}")
            current_user = get_current_user_object()
            user_id = current_user.id
            logger.info(f"current_user id is: {user_id}")
            # 检查当前用户对该图表是否具备 can_read, can_edit, can_delete, can_add 四种权限
            user_permissions = ChartPermissions.get_permissions_for_chart(user_id, pk)
            can_edit = user_permissions.get("can_edit", False)
            logger.info(f"ChartRestApi's can edit: {can_edit}")
            if not user_permissions.get("can_edit", False):
                response = make_response(
                    jsonify({
                        "error": "您没有足够的权限来修改其他人的图表。",
                        "code": 403,
                        "message": "Forbidden"
                    }), 403
                )
                return response
            item = self.edit_model_schema.load(request.json)
            logger.info(f"the update permission body is : {item}")
        except ValidationError as error:
            return self.response_400(message=error.messages)
        try:
            changed_model = UpdateChartCommand(pk, item).run()
            response = self.response(200, id=changed_model.id, result=item)
        except ChartNotFoundError:
            response = self.response_404()
        except ChartForbiddenError:
            response = self.response_403()
        except ChartInvalidError as ex:
            response = self.response_422(message=ex.normalized_messages())
        except ChartUpdateFailedError as ex:
            logger.error(
                "Error updating model %s: %s",
                self.__class__.__name__,
                str(ex),
                exc_info=True,
            )
            response = self.response_422(message=str(ex))

        return response

    @expose("/<pk>", methods=("DELETE",))
    # @protect()
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.delete",
        log_to_statsd=False,
    )
    def delete(self, pk: int) -> Response:
        """Delete a chart.
        ---
        delete:
          summary: Delete a chart
          parameters:
          - in: path
            schema:
              type: integer
            name: pk
          responses:
            200:
              description: Chart delete
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
            DeleteChartCommand([pk]).run()
            logger.info(f"begin to delete the char_id "
                        f"in UserPermissions and RolePermissions")
            resource_type = 'chart'
            ChartPermissions.delete_permissions_by_resource_ids(pk, resource_type)
            return self.response(200, message="OK")
        except ChartNotFoundError:
            return self.response_404()
        except ChartForbiddenError:
            return self.response_403()
        except ChartDeleteFailedError as ex:
            logger.error(
                "Error deleting model %s: %s",
                self.__class__.__name__,
                str(ex),
                exc_info=True,
            )
            return self.response_422(message=str(ex))

    @expose("/", methods=("DELETE",))
    # @protect()
    @safe
    @statsd_metrics
    @rison(get_delete_ids_schema)
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.bulk_delete",
        log_to_statsd=False,
    )
    def bulk_delete(self, **kwargs: Any) -> Response:
        """Bulk delete charts.
        ---
        delete:
          summary: Bulk delete charts
          parameters:
          - in: query
            name: q
            content:
              application/json:
                schema:
                  $ref: '#/components/schemas/get_delete_ids_schema'
          responses:
            200:
              description: Charts bulk delete
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
            DeleteChartCommand(item_ids).run()
            return self.response(
                200,
                message=ngettext(
                    "Deleted %(num)d chart", "Deleted %(num)d charts", num=len(item_ids)
                ),
            )
        except ChartNotFoundError:
            return self.response_404()
        except ChartForbiddenError:
            return self.response_403()
        except ChartDeleteFailedError as ex:
            return self.response_422(message=str(ex))

    @expose("/<pk>/cache_screenshot/", methods=("GET",))
    @protect()
    @rison(screenshot_query_schema)
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}"
                                             f".cache_screenshot",
        log_to_statsd=False,
    )
    def cache_screenshot(self, pk: int, **kwargs: Any) -> WerkzeugResponse:
        """Compute and cache a screenshot.
        ---
        get:
          summary: Compute and cache a screenshot
          parameters:
          - in: path
            schema:
              type: integer
            name: pk
          - in: query
            name: q
            content:
              application/json:
                schema:
                  $ref: '#/components/schemas/screenshot_query_schema'
          responses:
            202:
              description: Chart async result
              content:
                application/json:
                  schema:
                    $ref: "#/components/schemas/ChartCacheScreenshotResponseSchema"
            400:
              $ref: '#/components/responses/400'
            401:
              $ref: '#/components/responses/401'
            404:
              $ref: '#/components/responses/404'
            500:
              $ref: '#/components/responses/500'
        """
        rison_dict = kwargs["rison"]
        window_size = rison_dict.get("window_size") or DEFAULT_CHART_WINDOW_SIZE

        # Don't shrink the image if thumb_size is not specified
        thumb_size = rison_dict.get("thumb_size") or window_size
        # 检查权限：用户是否具有 can_read 权限
        user = get_current_user()
        if not user:
            logger.warning("No user is currently logged in.")
            return self.response_403()

        if not ChartPermissions.has_permission(chart_id=pk, user=user,
                                               permission_type="read"):
            logger.warning(
                "User %s does not have read permission for chart %s", user.username, pk
            )
            return self.response_403()

        chart = cast(Slice, self.datamodel.get(pk, self._base_filters))
        if not chart:
            return self.response_404()
        chart_url = get_url_path("Superset.slice", slice_id=chart.id)
        screenshot_obj = ChartScreenshot(chart_url, chart.digest)
        cache_key = screenshot_obj.cache_key(window_size, thumb_size)
        image_url = get_url_path(
            "ChartRestApi.screenshot", pk=chart.id, digest=cache_key
        )

        def trigger_celery() -> WerkzeugResponse:
            logger.info("Triggering screenshot ASYNC")
            cache_chart_thumbnail.delay(
                current_user=get_current_user(),
                chart_id=chart.id,
                force=True,
                window_size=window_size,
                thumb_size=thumb_size,
            )
            return self.response(
                202, cache_key=cache_key, chart_url=chart_url, image_url=image_url
            )

        return trigger_celery()

    @expose("/<pk>/screenshot/<digest>/", methods=("GET",))
    @protect()
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.screenshot",
        log_to_statsd=False,
    )
    def screenshot(self, pk: int, digest: str) -> WerkzeugResponse:
        """Get a computed screenshot from cache.
        ---
        get:
          summary: Get a computed screenshot from cache
          parameters:
          - in: path
            schema:
              type: integer
            name: pk
          - in: path
            schema:
              type: string
            name: digest
          responses:
            200:
              description: Chart thumbnail image
              content:
               image/*:
                 schema:
                   type: string
                   format: binary
            400:
              $ref: '#/components/responses/400'
            401:
              $ref: '#/components/responses/401'
            404:
              $ref: '#/components/responses/404'
            500:
              $ref: '#/components/responses/500'
        """
        # 获取当前用户
        user = get_current_user()
        if not user:
            logger.warning("No user is currently logged in.")
            return self.response_403()

        # 检查用户是否具有 can_read 权限
        if not ChartPermissions.has_permission(chart_id=pk, user=user,
                                               permission_type="read"):
            logger.warning(
                "User %s does not have read permission for chart %s", user.username, pk
            )
            return self.response_403()

        chart = self.datamodel.get(pk, self._base_filters)

        # Making sure the chart still exists
        if not chart:
            return self.response_404()

        # fetch the chart screenshot using the current user and cache if set
        if img := ChartScreenshot.get_from_cache_key(thumbnail_cache, digest):
            return Response(
                FileWrapper(img), mimetype="image/png", direct_passthrough=True
            )
        # TODO: return an empty image
        return self.response_404()

    @expose("/<pk>/thumbnail/<digest>/", methods=("GET",))
    @protect()
    @rison(thumbnail_query_schema)
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.thumbnail",
        log_to_statsd=False,
    )
    def thumbnail(self, pk: int, digest: str, **kwargs: Any) -> WerkzeugResponse:
        """Compute or get already computed chart thumbnail from cache.
        ---
        get:
          summary: Get chart thumbnail
          description: Compute or get already computed chart thumbnail from cache.
          parameters:
          - in: path
            schema:
              type: integer
            name: pk
          - in: path
            schema:
              type: string
            name: digest
          responses:
            200:
              description: Chart thumbnail image
              content:
               image/*:
                 schema:
                   type: string
                   format: binary
            302:
              description: Redirects to the current digest
            400:
              $ref: '#/components/responses/400'
            401:
              $ref: '#/components/responses/401'
            404:
              $ref: '#/components/responses/404'
            500:
              $ref: '#/components/responses/500'
        """
        chart = cast(Slice, self.datamodel.get(pk, self._base_filters))
        if not chart:
            return self.response_404()

        current_user = get_current_user()
        url = get_url_path("Superset.slice", slice_id=chart.id)
        if kwargs["rison"].get("force", False):
            logger.info(
                "Triggering thumbnail compute (chart id: %s) ASYNC", str(chart.id)
            )
            cache_chart_thumbnail.delay(
                current_user=current_user,
                chart_id=chart.id,
                force=True,
            )
            return self.response(202, message="OK Async")
        # fetch the chart screenshot using the current user and cache if set
        screenshot = ChartScreenshot(url, chart.digest).get_from_cache(
            cache=thumbnail_cache
        )
        # If not screenshot then send request to compute thumb to celery
        if not screenshot:
            self.incr_stats("async", self.thumbnail.__name__)
            logger.info(
                "Triggering thumbnail compute (chart id: %s) ASYNC", str(chart.id)
            )
            cache_chart_thumbnail.delay(
                current_user=current_user,
                chart_id=chart.id,
                force=True,
            )
            return self.response(202, message="OK Async")
        # If digests
        if chart.digest != digest:
            self.incr_stats("redirect", self.thumbnail.__name__)
            return redirect(
                url_for(
                    f"{self.__class__.__name__}.thumbnail", pk=pk, digest=chart.digest
                )
            )
        self.incr_stats("from_cache", self.thumbnail.__name__)
        return Response(
            FileWrapper(screenshot), mimetype="image/png", direct_passthrough=True
        )

    @expose("/export/", methods=("GET",))
    # @protect()
    @safe
    @statsd_metrics
    @rison(get_export_ids_schema)
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.export",
        log_to_statsd=False,
    )
    def export(self, **kwargs: Any) -> Response:
        """Download multiple charts as YAML files.
        ---
        get:
          summary: Download multiple charts as YAML files
          parameters:
          - in: query
            name: q
            content:
              application/json:
                schema:
                  $ref: '#/components/schemas/get_export_ids_schema'
          responses:
            200:
              description: A zip file with chart(s), dataset(s) and database(s) as YAML
              content:
                application/zip:
                  schema:
                    type: string
                    format: binary
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
        timestamp = datetime.now().strftime("%Y%m%dT%H%M%S")
        root = f"chart_export_{timestamp}"
        filename = f"{root}.zip"

        buf = BytesIO()
        with ZipFile(buf, "w") as bundle:
            try:
                for file_name, file_content in ExportChartsCommand(requested_ids).run():
                    with bundle.open(f"{root}/{file_name}", "w") as fp:
                        fp.write(file_content.encode())
            except ChartNotFoundError:
                return self.response_404()
        buf.seek(0)

        response = send_file(
            buf,
            mimetype="application/zip",
            as_attachment=True,
            download_name=filename,
        )
        if token := request.args.get("token"):
            response.set_cookie(token, "done", max_age=600)
        return response

    @expose("/favorite_status/", methods=("GET",))
    @protect()
    @safe
    @rison(get_fav_star_ids_schema)
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}"
                                             f".favorite_status",
        log_to_statsd=False,
    )
    def favorite_status(self, **kwargs: Any) -> Response:
        """Check favorited charts for current user.
        ---
        get:
          summary: Check favorited charts for current user
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
        logging.info(f"Requested IDs: {requested_ids}")
        # 调用 ChartDAO.find_by_ids 时，检查权限
        charts = ChartDAO.find_by_ids(
            requested_ids,
            permission_type="read",  # 权限类型为 'read'，可以根据需要调整
            check_permission=True  # 校验权限
        )
        if not charts:
            return self.response_404()
        favorited_chart_ids = ChartDAO.favorited_ids(charts)
        res = [
            {"id": request_id, "value": request_id in favorited_chart_ids}
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
        """Mark the chart as favorite for the current user.
        ---
        post:
          summary: Mark the chart as favorite for the current user
          parameters:
          - in: path
            schema:
              type: integer
            name: pk
          responses:
            200:
              description: Chart added to favorites
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
        chart = ChartDAO.find_by_chart_id(
            pk,
            check_permission=False,
            permission_type="read"  # 读取权限
        )
        if not chart:
            return self.response_404()

        ChartDAO.add_favorite(chart)
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
        """Remove the chart from the user favorite list.
        ---
        delete:
          summary: Remove the chart from the user favorite list
          parameters:
          - in: path
            schema:
              type: integer
            name: pk
          responses:
            200:
              description: Chart removed from favorites
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
        chart = ChartDAO.find_by_chart_id(
            pk,
            check_permission=False,
            permission_type="delete"  # 删除权限
        )
        if not chart:
            return self.response_404()

        ChartDAO.remove_favorite(chart)
        return self.response(200, result="OK")

    @expose("/warm_up_cache", methods=("PUT",))
    @protect()
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}"
                                             f".warm_up_cache",
        log_to_statsd=False,
    )
    def warm_up_cache(self) -> Response:
        """Warm up the cache for the chart.
        ---
        put:
          summary: Warm up the cache for the chart
          description: >-
            Warms up the cache for the chart.
            Note for slices a force refresh occurs.
            In terms of the `extra_filters` these can be obtained from records in the JSON
            encoded `logs.json` column associated with the `explore_json` action.
          requestBody:
            description: >-
              Identifies the chart to warm up cache for, and any additional dashboard or
              filter context to use.
            required: true
            content:
              application/json:
                schema:
                  $ref: "#/components/schemas/ChartCacheWarmUpRequestSchema"
          responses:
            200:
              description: Each chart's warmup status
              content:
                application/json:
                  schema:
                    $ref: "#/components/schemas/ChartCacheWarmUpResponseSchema"
            400:
              $ref: '#/components/responses/400'
            404:
              $ref: '#/components/responses/404'
            500:
              $ref: '#/components/responses/500'
        """
        try:
            body = ChartCacheWarmUpRequestSchema().load(request.json)
        except ValidationError as error:
            return self.response_400(message=error.messages)
        try:
            result = ChartWarmUpCacheCommand(
                body["chart_id"],
                body.get("dashboard_id"),
                body.get("extra_filters"),
            ).run()
            return self.response(200, result=[result])
        except CommandException as ex:
            return self.response(ex.status, message=ex.message)

    @expose("/import/", methods=("POST",))
    @protect()
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}.import_",
        log_to_statsd=False,
    )
    @requires_form_data
    def import_(self) -> Response:
        """Import chart(s) with associated datasets and databases.
        ---
        post:
          summary: Import chart(s) with associated datasets and databases
          requestBody:
            required: true
            content:
              multipart/form-data:
                schema:
                  type: object
                  properties:
                    formData:
                      description: upload file (ZIP)
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
                      description: overwrite existing charts?
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
              description: Chart import result
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
        if not is_zipfile(upload):
            raise IncorrectFormatError("Not a ZIP file")
        with ZipFile(upload) as bundle:
            contents = get_contents_from_bundle(bundle)

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

        command = ImportChartsCommand(
            contents,
            passwords=passwords,
            overwrite=overwrite,
            ssh_tunnel_passwords=ssh_tunnel_passwords,
            ssh_tunnel_private_keys=ssh_tunnel_private_keys,
            ssh_tunnel_priv_key_passwords=ssh_tunnel_priv_key_passwords,
        )
        command.run()
        return self.response(200, message="OK")

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
            user_permissions = ChartPermissions.get_permissions_for_chart(user_id, pk)
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
            perm_dict = ChartPermissions.interpret_frontend_permissions(permissions)
            logger.info(f"推导出的权限集合: {perm_dict}")

            if action == "add":
                add_perms = [k for k, v in perm_dict.items() if v]
                ChartDAO.modify_permissions(
                    chart_id=pk,
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
                ChartDAO.modify_permissions(
                    chart_id=pk,
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

    def _filter_charts_based_on_permissions(
        self, original_result: list, original_ids: list, current_user
    ) -> tuple:
        """
        根据用户和角色权限，过滤图表数据。
        现在支持多个权限类型（例如：'read' 和 'edit'）。
        """

        # 获取用户的 'read' 和 'edit' 权限
        user_read_permissions = ChartPermissions.get_user_permissions(current_user.id,
                                                                      'read')
        logger.info(
            f"current user's read userpermission chart_id: {user_read_permissions}")
        user_edit_permissions = ChartPermissions.get_user_permissions(current_user.id,
                                                                      'edit')
        logger.info(
            f"current user's edit userpermission chart_id: {user_edit_permissions}")
        user_permissions = user_read_permissions + user_edit_permissions

        # 获取角色的 'read' 和 'edit' 权限
        role_read_permissions = ChartPermissions.get_role_permissions(
            current_user.roles, 'read')
        logger.info(
            f"current user's read rolepermission chart_id: {role_read_permissions}")
        role_edit_permissions = ChartPermissions.get_role_permissions(
            current_user.roles, 'edit')
        logger.info(
            f"current user's edit rolepermission chart_id: {role_edit_permissions}")
        role_permissions = role_read_permissions + role_edit_permissions

        # 合并用户和角色的权限
        all_permissions = set(user_permissions + role_permissions)
        logger.info(f"current user's all_permissions: {all_permissions}")
        # 过滤用户有权限访问的图表ID
        logger.info(f"current user's original_ids: {original_ids}")
        allowed_ids = [
            chart_id
            for chart_id in original_ids
            if chart_id in all_permissions
        ]
        logger.info(f"current user's allowed_ids: {allowed_ids}")
        # 过滤结果，只返回用户有权限的图表
        filtered_result = [
            chart for chart in original_result if chart["id"] in allowed_ids
        ]

        return filtered_result, allowed_ids

    @expose("/<int:chart_id>/access-info", methods=["GET"])
    # @protect()
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args, **kwargs: f"{self.__class__.__name__}"
                                             f".access_info",
        log_to_statsd=False,
    )
    def get_access_info(self, chart_id: int):
        """
        获取指定 chart 的访问权限信息。
        """
        try:
            access_info = ChartDAO.get_chart_access_info(chart_id)
            return self.response(200, result=access_info)
        except Exception as ex:
            logger.error(f"Error fetching chart access info: {ex}")
            return self.response_500(message="Failed to fetch chart access info.")

    @expose('/<int:chart_id>/add-collaborator', methods=["POST"])
    @safe
    @statsd_metrics
    @event_logger.log_this_with_context(
        action=lambda self, *args,
                      **kwargs: f"{self.__class__.__name__}.add_collaborator",
        log_to_statsd=False,
    )
    def add_collaborator(self, chart_id: int):
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
        logger.info(f"当前的chartId是: {chart_id}")

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
            if ChartDAO.is_collaborator_exist(chart_id, collaborator_id,
                                              collaborator_type):
                response = make_response(
                    jsonify({
                        "error": f"该用户已经是协作者了！",
                        "code": 400,
                        "message": "BAD REQUEST"
                    }), 400
                )
                return response
            resource_type = 'chart'
            datasource_id = ChartDAO.get_datasource_id_by_resource(resource_type,
                                                                   chart_id)
            logger.info(f"获取到的datasource_id: {datasource_id}")
            if collaborator_type == "user":
                # 如果是用户类型，检查用户对 chart 是否有权限
                has_permission = ChartPermissions.check_user_permission(collaborator_id,
                                                                        datasource_id)
            elif collaborator_type == "role":
                # 如果是角色类型，检查角色对 chart 是否有权限
                has_permission = ChartPermissions.check_role_permission(collaborator_id,
                                                                        datasource_id)

            if not has_permission:
                return make_response(
                    jsonify({
                        "error": f"该{'用户' if collaborator_type == 'user' else '角色'}没有权限访问数据源！",
                        "code": 403,
                        "message": "Forbidden"
                    }), 403
                )
                # 如果不存在，则添加协作者

            ChartDAO.add_collaborator(
                chart_id,
                collaborator_id,
                collaborator_type,
                datasource_id)

            return self.response(
                200,
                message=f"{collaborator_type} (ID: {collaborator_id}) 添加成功！",
            )
        except Exception as ex:
            logger.error(f"Error adding collaborator: {ex}")
            return self.response_500(message="Failed to add collaborator.")

    @expose("/_info", methods=["GET"])
    @protect()  # 确保用户已认证
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
            # 获取用户对所有图表的权限
            all_permissions = ChartPermissions.get_all_chart_permissions(user)
        except Exception as e:
            logger.error(f"获取权限信息时出错: {e}")
            return self.response_500(message="内部服务器错误。")

        # 过滤并格式化权限信息
        filtered_permissions = {}
        for chart_id, perm in all_permissions.items():
            # 仅包含用户拥有至少一种权限的图表
            if perm["can_write"] or perm["can_add"] or perm["can_delete"] or perm[
                "can_read"]:
                filtered_permissions[chart_id] = {
                    "can_write": perm["can_write"],  # 替换 can_edit 为 can_write
                    "can_add": perm["can_add"],
                    "can_delete": perm["can_delete"],
                    "can_read": perm["can_read"],
                    "can_export": perm["can_export"],  # 基于 can_read 推导
                    "role": perm["role"]
                }

        # 获取全局权限
        global_permissions = {
            "can_write": security_manager.can_access('can_write', 'Chart')
        }

        logger.debug(f"获取到的权限信息: {filtered_permissions}")

        res = {"permissions": filtered_permissions,
               "global_permissions": global_permissions}
        # 返回 JSON 响应
        return self.response(200, **res)

    ModelKeyType = Union[str, int]

    @expose("/<int:pk>", methods=["GET"])
    @protect()
    @safe
    @rison(get_item_schema)
    def get(self, pk: ModelKeyType, **kwargs: Any) -> Response:
        """
        获取指定 ID 的图表，并返回其权限信息。
        ---
        get:
          description: >-
            获取一个图表模型及其权限信息
          parameters:
          - in: path
            schema:
              type: integer
            name: pk
          - in: query
            name: q
            content:
              application/json:
                schema:
                  $ref: '#/components/schemas/get_item_schema'
          responses:
            200:
              description: 成功获取图表及其权限信息
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      label_columns:
                        type: object
                        properties:
                          column_name:
                            description: >-
                              列名称的标签。
                              会被 babel 翻译
                            example: A Nice label for the column
                            type: string
                      show_columns:
                        description: >-
                          列的列表
                        type: array
                        items:
                          type: string
                      description_columns:
                        type: object
                        properties:
                          column_name:
                            description: >-
                              列名称的描述。
                              会被 babel 翻译
                            example: A Nice description for the column
                            type: string
                      show_title:
                        description: >-
                          显示的标题。
                          会被 babel 翻译
                        example: Show Item Details
                        type: string
                      id:
                        description: 图表的 ID
                        type: string
                      result:
                        $ref: '#/components/schemas/{{self.__class__.__name__}}.get'
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
        return self.get_headless(pk, **kwargs)

    @expose('/<int:chart_id>/permissions', methods=['GET'])
    @safe
    def get_permissions(self, chart_id):
        user_id = get_current_user_object().id  # 假设你有用户认证机制，可以获取当前登录用户的 ID
        # 获取当前登录用户的角色 ID
        role_id = get_current_user_role_id()  # 假设你有角色相关的字段

        return ChartPermissions.get_chart_permissions(
            chart_id,
            user_id=user_id,
            role_id=role_id
        )

    def get_headless(self, pk: int, **kwargs: Any) -> Response:
        """
        获取图表的详细信息，并进行权限检查。

        :param pk: 图表的主键
        :param kwargs: 查询参数
        :return: HTTP 响应
        """
        try:
            # 获取图表对象
            chart = self.datamodel.get(pk)
            if not chart:
                logger.warning(f"图表 ID {pk} 未找到。")
                return self.response_404()

            # 获取当前用户对象
            user = get_current_user_object()
            if not user:
                logger.error("没有用户登录。")
                return self.response_403(message="权限拒绝。")

            user_id = user.id
            role_ids = [role.id for role in user.roles] if user.roles else []

            # 使用 ChartPermissions 类进行权限检查
            has_permission = ChartPermissions.has_can_edit_permission(user_id, role_ids,
                                                                      pk)

            # 权限检查：如果没有 can_edit 权限，则返回 403
            if not has_permission:
                logger.warning(
                    f"用户 ID {user_id} 对图表 ID {pk} 不拥有 can_edit 权限，拒绝访问。")
                # 使用 make_response 返回 403 错误
                response = jsonify({"message": "你没有该图表的编辑权限。"})
                return make_response(response, 403)

            # 构建响应数据
            response = {}
            args = kwargs.get("q", {})
            select_cols = args.get("show_columns", [])
            pruned_select_cols = [col for col in select_cols if
                                  col in self.show_columns]

            # 设置响应的键映射
            self.set_response_key_mappings(response, self.get, args,
                                           **{"show_columns": pruned_select_cols})

            if pruned_select_cols:
                show_model_schema = self.model2schemaconverter.convert(
                    pruned_select_cols)
            else:
                show_model_schema = self.show_model_schema

            response["id"] = pk
            response["result"] = show_model_schema.dump(chart, many=False)
            self.pre_get(response)

            return self.response(200, **response)

        except SupersetException as e:
            logger.error(f"获取图表时出错: {e}")
            return self.response_500(message="服务器内部错误。")
        except Exception as e:
            logger.exception(f"未知错误: {e}")
            return self.response_500(message="服务器内部错误。")
