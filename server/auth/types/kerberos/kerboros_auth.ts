/*
 *   Copyright OpenSearch Contributors
 *
 *   Licensed under the Apache License, Version 2.0 (the "License").
 *   You may not use this file except in compliance with the License.
 *   A copy of the License is located at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   or in the "license" file accompanying this file. This file is distributed
 *   on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *   express or implied. See the License for the specific language governing
 *   permissions and limitations under the License.
 */

import {
	CoreSetup,
	SessionStorageFactory,
	IRouter,
	ILegacyClusterClient,
	OpenSearchDashboardsRequest,
	Logger,
	LifecycleResponseFactory,
	AuthToolkit,
  } from 'opensearch-dashboards/server';
import { OpenSearchDashboardsResponse } from 'src/core/server/http/router';
import { BasicAuthentication } from '..';
import { SecurityPluginConfigType } from '../../..';
import { SecuritySessionCookie } from '../../../session/security_cookie';
import { AuthenticationType } from '../authentication_type';

export class KerberosAuthentication extends AuthenticationType {
	private static readonly AUTH_HEADER_NAME: string = 'authorization';
	private static readonly CHALLENGE: string = 'WWW-Authenticate';
	public readonly type: string = 'kerberos';

	constructor(
	  config: SecurityPluginConfigType,
	  sessionStorageFactory: SessionStorageFactory<SecuritySessionCookie>,
	  router: IRouter,
	  esClient: ILegacyClusterClient,
	  coreSetup: CoreSetup,
	  logger: Logger
	) {
	  super(config, sessionStorageFactory, router, esClient, coreSetup, logger);

	}

	// override functions inherited from AuthenticationType
	requestIncludesAuthInfo(
	  request: OpenSearchDashboardsRequest<unknown, unknown, unknown, any>
	): boolean {
	   return request.headers[ KerberosAuthentication.AUTH_HEADER_NAME ] ? true : false;
	//    return false;
	}

	getAdditionalAuthHeader(request: OpenSearchDashboardsRequest<unknown, unknown, unknown, any>) {
	  const authHeaders: any = {};
	  return authHeaders;
	}

	getCookie(request: OpenSearchDashboardsRequest, authInfo: any): SecuritySessionCookie {
	return {
		username: authInfo.user_name,
		authType: this.type,
		expiryTime: Date.now() + this.config.session.ttl,
		credentials: {
			authHeaderValue: 'a',
		},
		
	  };
	}

	async isValidCookie(cookie: SecuritySessionCookie): Promise<boolean> {
	  return ( cookie.authType === this.type && 
			cookie.username && 
			cookie.expiryTime &&
			cookie.credentials?.authHeaderValue );
	}

	handleUnauthedRequest(
	  request: OpenSearchDashboardsRequest,
	  response: LifecycleResponseFactory,
	  toolkit: AuthToolkit
	): OpenSearchDashboardsResponse {

		console.log( '********************** Unauthorized **********************' )
		console.log( request.headers )
		console.log( '********************** Unauthorized **********************' )
		return response.unauthorized({
		  body: `Authentication required`,
		  headers: {
			'WWW-Authenticate': 'Negotiate',
		  }
		});
		
		// return response.unauthorized({
		// 	body: `Authentication required`,
		//   });
	}

	buildAuthHeaderFromCookie(cookie: SecuritySessionCookie): any {
	  const headers: any = {};
	  return headers
	}
  }