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
import { SecurityPluginConfigType } from '../../..';
import { SecuritySessionCookie } from '../../../session/security_cookie';
import { AuthenticationType } from '../authentication_type';
import { KerberosRoutes } from './routes';
import { composeNextUrlQeuryParam } from '../../../utils/next_url';


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
	  
	  this.init();
	}

	private async init() {
		const routes = new KerberosRoutes(
			this.router,
			this.config,
			this.sessionStorageFactory,
			this.securityClient,
		  );
		routes.setupRoutes();
	  }

	// override functions inherited from AuthenticationType
	requestIncludesAuthInfo(
	  request: OpenSearchDashboardsRequest<unknown, unknown, unknown, any>
	): boolean {
	//    return request.headers[ KerberosAuthentication.AUTH_HEADER_NAME ] ? true : false;
	   return false;
	}

	getAdditionalAuthHeader(request: OpenSearchDashboardsRequest<unknown, unknown, unknown, any>) {
	  const authHeaders: any = {};
	  return authHeaders;
	}

	getCookie(request: OpenSearchDashboardsRequest, authInfo: any): SecuritySessionCookie {
	return {};
	}

	async isValidCookie(cookie: SecuritySessionCookie): Promise<boolean> {
	  return ( cookie.authType === 'jwt' && 
			cookie.username && 
			cookie.expiryTime &&
			cookie.credentials?.authHeaderValue );
	}

	handleUnauthedRequest(
	  request: OpenSearchDashboardsRequest,
	  response: LifecycleResponseFactory,
	  toolkit: AuthToolkit
	): OpenSearchDashboardsResponse {

		const nextUrlParam = composeNextUrlQeuryParam(
			request,
			this.coreSetup.http.basePath.serverBasePath
		  );
		const redirectLocation = `${this.coreSetup.http.basePath.serverBasePath}/auth/krb?${nextUrlParam}`;
		return response.redirected({
			headers: {
				location: `${redirectLocation}`,
			},
		});
	}

	buildAuthHeaderFromCookie(cookie: SecuritySessionCookie): any {
		const headers: any = {};
		Object.assign(headers, { authorization: cookie.credentials?.authHeaderValue });
		return headers;
	}
  }
