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
import io
from typing import Any

import pandas as pd
from xlsxwriter.workbook import Workbook


def get_excel_column_name(n):
    name = ''
    while n >= 0:
        n, remainder = divmod(n, 26)
        n -= 1  
        name = chr(65 + remainder) + name
    return name

def df_to_excel(df: pd.DataFrame, **kwargs: Any) -> Any:
    output = io.BytesIO()

    # timezones are not supported
    for column in df.select_dtypes(include=["datetimetz"]).columns:
        df[column] = df[column].astype(str)

    # pylint: disable=abstract-class-instantiated
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        df.to_excel(writer, index=False, **kwargs)

        workbook: Workbook = writer.book
        worksheet = writer.sheets[kwargs.get('sheet_name', 'Sheet1')]
        for idx, dtype in enumerate(df.dtypes):
            column_name = get_excel_column_name(idx)
            column_range = f'{column_name}:{column_name}'
            format = None

            if pd.api.types.is_integer_dtype(dtype):
                format = workbook.add_format({'num_format': '#,##0'})
            elif pd.api.types.is_float_dtype(dtype):
                format = workbook.add_format({'num_format': '#,##0.00'})
            if format:
                worksheet.set_column(column_range, None, format)

    return output.getvalue()
