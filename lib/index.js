//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//

'use strict';

const adalNode = require('adal-node');
const async = require('async');
const azureKeyVault = require('azure-keyvault');
const objectPath = require('object-path');
const url = require('url');

// Key Vault Configuration Assumptions:
// In URL syntax, we define a custom scheme of "keyvault://" which resolves
// a KeyVault secret ID, replacing the original. To use a tag (a custom
// attribute on a secret - could be a username for example), use the tag
// name as the auth parameter of the URL.
//
// For example:
//   keyvault://myCustomTag@keyvaultname.vault.azure.net/secrets/secret-value-name/secretVersion",
//
// Would resolve the "myCustomTag" value instead of the secret value.
//
// You can also chose to leave the version off, so that the most recent version
// of the secret will be resolved during the resolution process.
//
// In the case that a KeyVault secret ID is needed inside the app, and not
// handled at startup, then the secret ID (a URI) can be included without
// the custom keyvault:// scheme.
//
// Note that this use of a custom scheme called "keyvault" is not an officially
// recommended or supported approach for KeyVault use in applications, and may
// not be endorsed by the engineering team responsible for KeyVault, but for our
// group and our Node apps, it has been very helpful.

const keyVaultProtocol = 'keyvault:';
const httpsProtocol = 'https:';

function resolveKeyVaultValue(config, keyVaultClient, keyVaultUrl, path, callback) {
  keyVaultUrl.protocol = httpsProtocol;
  const tag = keyVaultUrl.auth;
  if (tag !== null) {
    keyVaultUrl.auth = null;
  }
  const secretId = url.format(keyVaultUrl);
  keyVaultClient.getSecret(secretId, (getSecretError, secretResponse) => {
    if (getSecretError) {
      return callback(getSecretError);
    }
    let value = undefined;
    if (tag === null) {
      value = secretResponse.value;
    } else if (secretResponse.tags) {
      value = secretResponse.tags[tag];
    }
    objectPath.set(config, path, value);
    return callback();
  });
}

function getUrlIfVault(value) {
  try {
    const keyVaultUrl = url.parse(value);
    if (keyVaultUrl.protocol === keyVaultProtocol) {
      return keyVaultUrl;
    }
  }
  catch (typeError) {
    /* ignore */
  }
  return undefined;
}

function identifyKeyVaultValuePaths(node, prefix) {
  prefix = prefix !== undefined ? prefix + '.' : '';
  const paths = {};
  for (const property in node) {
    const value = node[property];
    if (typeof value === 'object') {
      Object.assign(paths, identifyKeyVaultValuePaths(value, prefix + property));
      continue;
    }
    if (typeof value !== 'string') {
      continue;
    }
    const keyVaultUrl = getUrlIfVault(value);
    if (keyVaultUrl === undefined) {
      continue;
    }
    paths[prefix + property] = keyVaultUrl;
  }
  return paths;
}

function wrapClient(keyVaultClient) {
  keyVaultClient.getObjectSecrets = function resolveSecrets(object, callback) {
    let paths = null;
    try {
      paths = identifyKeyVaultValuePaths(object);
    } catch(parseError) {
      return callback(parseError);
    }
    async.forEachOf(paths, resolveKeyVaultValue.bind(undefined, object, keyVaultClient), callback);
  };
  return keyVaultClient;
}

function createAndWrapKeyVaultClient(options) {
  if (!options) {
    throw new Error('No options provided for the key vault resolver.');
  }
  let client = typeof(options) === 'function' && options.getSecret ? options : options.client;
  if (options.credentials && !client) {
    client = new azureKeyVault.KeyVaultClient(options.credentials);
  }
  if (!client) {
    if (!options.clientId) {
      throw new Error('Must provide an Azure Active Directory "clientId" value to the key vault resolver.');
    }
    if (!options.clientSecret) {
      throw new Error('Must provide an Azure Active Directory "clientSecret" value to the key vault resolver.');
    }
    const clientId = options.clientId;
    const clientSecret = options.clientSecret;
    const authenticator = (challenge, authCallback) => {
      const context = new adalNode.AuthenticationContext(challenge.authorization);
      return context.acquireTokenWithClientCredentials(challenge.resource, clientId, clientSecret, (tokenAcquisitionError, tokenResponse) => {
        if (tokenAcquisitionError) {
          return authCallback(tokenAcquisitionError);
        }
        const authorizationValue = `${tokenResponse.tokenType} ${tokenResponse.accessToken}`;
        return authCallback(null, authorizationValue);
      });
    };
    const credentials = new azureKeyVault.KeyVaultCredentials(authenticator);
    client = new azureKeyVault.KeyVaultClient(credentials);
  }
  return wrapClient(client);
}

module.exports = createAndWrapKeyVaultClient;
