/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
import { SupersetClient } from '@superset-ui/core';
import React, { useEffect, useState } from 'react';
import getBootstrapData from 'src/utils/getBootstrapData';

const bootstrapData = getBootstrapData();

function Copilot() {
  const [token, setToken] = useState();

  useEffect(() => {
    SupersetClient.get({
      url: '/api/v1/me/token/',
    }).then(res => {
      setToken(res.json.token);
    });
  }, []);

  return (
    <>
      {token && (
        <iframe
          title="Copilot"
          allow="microphone"
          src={`${bootstrapData.common.copilot_url}/chat?cid=1&model=chatgpt&token=${token}`}
          style={{
            width: '100%',
            height: 'calc(100vh - 53px)',
          }}
        />
      )}
    </>
  );
}

export default Copilot;
