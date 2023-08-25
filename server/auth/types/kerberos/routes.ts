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

import { schema } from '@osd/config-schema';
import { sign } from 'jsonwebtoken';
import { IRouter, SessionStorageFactory, CoreSetup } from 'opensearch-dashboards/server';
import {
  SecuritySessionCookie,
  clearOldVersionCookieValue,
} from '../../../session/security_cookie';
import { SecurityPluginConfigType } from '../../..';
import { User } from '../../user';
import { SecurityClient } from '../../../backend/opensearch_security_client';
import { resolveTenant } from '../../../multitenancy/tenant_resolver';

import { KERBEROS_AUTH_LOGIN } from '../../../../common';

import { ParsedUrlQueryParams } from '../../../utils/next_url';
import { RequestStatus } from 'src/plugins/inspector';


export class KerberosRoutes {
  constructor(
    private readonly router: IRouter,
    private readonly config: SecurityPluginConfigType,
    private readonly sessionStorageFactory: SessionStorageFactory<SecuritySessionCookie>,
    private readonly securityClient: SecurityClient,
	private readonly coreSetup: CoreSetup
  ) {}

  public setupRoutes() {

    // login using username and password
    this.router.get(
      {
        path: KERBEROS_AUTH_LOGIN,
        validate: false,
        options: {
          authRequired: false,
        },
      },
      async (context, request, response) => {

    //   let user: any;

    //   if (request.headers.authorization) {

    //     user = await this.securityClient.authinfo( request )

    //     if( this.config.jwt?.signing_key ) {
    //       let signingKey = this.config.jwt.signing_key;
    //       const signingKey_text = Buffer.from( signingKey, 'base64' ).toString( 'binary' );

    //       let payload = {
    //         user: user.user_name,
    //         roles: user.roles 
    //       }

    //       let jwtToken = sign( payload, signingKey_text );
        
    //       this.sessionStorageFactory.asScoped(request).clear();
    //       const sessionStorage: SecuritySessionCookie = {
    //         username: user.user_name,
    //         credentials: {
    //           authHeaderValue: `Bearer ${jwtToken}`,
    //         },
    //         authType: 'jwt',
    //         isAnonymousAuth: false,
    //         expiryTime: Date.now() + this.config.session.ttl,
    //       };

    //       if (this.config.multitenancy?.enabled) {
	// 		const selectTenant = resolveTenant({
	// 			request,
	// 			username: user.username,
	// 			roles: user.roles,
	// 			availabeTenants: user.tenants,
	// 			config: this.config,
	// 			cookie: sessionStorage,
	// 			multitenancyEnabled: user.multitenancy_enabled,
	// 			privateTenantEnabled: user.private_tenant_enabled,
	// 			defaultTenant: user.default_tenant,
	// 		  });
    //         sessionStorage.tenant = selectTenant;
    //       }
    //       this.sessionStorageFactory.asScoped(request).set(sessionStorage);

    //       return response.redirected({
    //         headers: {
    //           location: '/',
    //         },
    //       });;

    //     }
    //   }

      return response.unauthorized({
          body: `Authentication required`,
          headers: {
        	'WWW-Authenticate': 'Negotiate',
          }
        });
      }
    );
  }
}
