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
import { IRouter, SessionStorageFactory, CoreSetup } from 'opensearch-dashboards/server';
import {
  SecuritySessionCookie,
  clearOldVersionCookieValue,
} from '../../../session/security_cookie';
import { SecurityPluginConfigType } from '../../..';
import { User } from '../../user';
import { SecurityClient } from '../../../backend/opensearch_security_client';
import { API_AUTH_LOGIN, API_AUTH_LOGOUT, LOGIN_PAGE_URI } from '../../../../common';
import { resolveTenant } from '../../../multitenancy/tenant_resolver';
import { ParsedUrlQueryParams } from '../../../utils/next_url';
import { RequestStatus } from 'src/plugins/inspector';


export class KerberosRoutes {
  constructor(
    private readonly router: IRouter,
    private readonly config: SecurityPluginConfigType,
    private readonly sessionStorageFactory: SessionStorageFactory<SecuritySessionCookie>,
    private readonly securityClient: SecurityClient,
  ) {}

  public setupRoutes() {
    // bootstrap an empty page so that browser app can render the login page
    // using client side routing.

    // login using username and password
    this.router.get(
      {
        path: '/auth/krb',
        validate: false,
        options: {
          authRequired: false,
        },
      },
      async (context, request, response) => {

        

        // const authinfo = this.securityClient.authinfo( request )
        console.log( '############### At /auth/krb ###############' );
        // console.log( negotiateStr );
        // await this.securityClient.authenticateWithHeader( request, 'authorization', String( negotiateStr ) );
      
      let user: any;

      if (request.headers.authorization) {

        // const negotiateStr = `${request.headers.authorization}`

        user = await this.securityClient.authinfo( request )
        console.log( user )
        console.log( user.user_name )
        
        console.log( '================================' )

        // user2 = await this.securityClient.authenticate(request, {
        //   username: user.username,
        //   password: 'test',
        // });
        // console.log( user2 );
        
        this.sessionStorageFactory.asScoped(request).clear();
        const encodedCredentials = Buffer.from(
          `${user.user_name}:test`
        ).toString('base64');
        const sessionStorage: SecuritySessionCookie = {
          username: user.user_name,
          credentials: {
            authHeaderValue: `Basic ${encodedCredentials}`,
          },
          authType: 'basicauth',
          isAnonymousAuth: false,
          expiryTime: Date.now() + this.config.session.ttl,
        };

        if (this.config.multitenancy?.enabled) {
          const selectTenant = resolveTenant(
            request,
            user.user_name,
            user.tenants,
            this.config,
            sessionStorage
          );
          sessionStorage.tenant = selectTenant;
        }
        this.sessionStorageFactory.asScoped(request).set(sessionStorage);

        console.log( sessionStorage )

        return response.redirected({
          headers: {
            location: '/',
          },
        });;
      }

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
