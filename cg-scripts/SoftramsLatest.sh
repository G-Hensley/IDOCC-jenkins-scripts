#!/bin/bash

# We need to access a cookie jar file that will be used for this Login sequence
# This cookie jar file needs to be reset every time we start a new Login sequence
rm -f cookie_jar_$user

user=${1:-fNCMS501202175604}
pass=$2
env=${3:-dev}

case $env in
  dev)
    OKTA_AUTH_ENDPOINT='aus2iklu9k1HyChDa297'
    OKTA_AUTH_CLIENT_ID="0oa2h629523PUDbhI297"
    OKTA_HOSTNAME="test.idp.idm.cms.gov"
    ;;
  test)
    OKTA_AUTH_ENDPOINT='aus2iklu9k1HyChDa297'
    OKTA_AUTH_CLIENT_ID="0oa2h629523PUDbhI297"
    OKTA_HOSTNAME="test.idp.idm.cms.gov"
    ;;
  impl)
    OKTA_AUTH_ENDPOINT='aus2mth3kjvm3Y4BK297'
    OKTA_AUTH_CLIENT_ID="0oa2mtg1rsJdE6utv297"
    OKTA_HOSTNAME="impl.idp.idm.cms.gov"
    ;;
esac

sessionTokenData="$(curl -s -X POST https://${OKTA_HOSTNAME}/api/v1/authn \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -d '{ "username": "'${user}'", "password": "'${pass}'", "options": { "warnBeforePasswordExpired": true, "multiOptionalFactorEnroll": false} }')"

if echo "$sessionTokenData" | jq -e 'has("errorCode")' > /dev/null; then
  echo "Failed to authenticate"
  exit 1
fi

sessionToken=$(echo ${sessionTokenData} | jq -r ".sessionToken" )
#echo "Session Token: "$sessionToken

# Second Step: We need to call the session cookie redirect endpoint with the session token received in Step 1
url="$(curl -i -c cookie_jar_$user -s -X GET "https://${OKTA_HOSTNAME}/login/sessionCookieRedirect?checkAccountSetupComplete=true&token=$sessionToken&redirectUrl=https%3A%2F%2F$OKTA_HOSTNAME%2Foauth2%2F${OKTA_AUTH_ENDPOINT}%2Fv1%2Fauthorize%3Fclient_id%3D${OKTA_AUTH_CLIENT_ID}%26response_type%3Dcode%26scope%3Dopenid%20offline_access%26redirect_uri%3Dhttps%3A%2F%2F4innovation-${env}.cms.gov%2Fsecure%26sessionToken%3D$sessionToken%26state%3Dcomplete%26nonce%3D%7B%7B%24guid%7D%7D" | grep location | cut -d ' ' -f2 )"
#echo "URL1 : "$url

# Third Step: We need to call oauth2 authorize endpoint with the session token received in Step 1
url="$(curl -i -b cookie_jar_$user -c cookie_jar_$user -s -X GET "https://${OKTA_HOSTNAME}/oauth2/${OKTA_AUTH_ENDPOINT}/v1/authorize?client_id=${OKTA_AUTH_CLIENT_ID}&response_type=code&scope=openid%20offline_access&redirect_uri=https://4innovation-${env}.cms.gov/secure&sessionToken=$sessionToken&state=complete&nonce=%7B%7B%24guid%7D%7D" | grep location)"
#echo "URL2: "$url
#echo "code: "$url | cut -d '=' -f2 | cut -d '&' -f1

code=$(echo $url | cut -d '=' -f2 | cut -d '&' -f1)
# echo "code: ${code}"

# Fourth Step: Finally we need to call the auth login endpoint to retrieve the JWT Token
jwt="$(curl -s -b cookie_jar_$user  -X POST https://4innovation-${env}-api.cms.gov/idm/auth/login -H 'Content-Type: application/json' -H 'Accept: application/json' -H 'Authorization: public_endpoints_only' -d "{\"authInput\":{\"access_token\":\"\",\"idToken\":\"\",\"authCode\":\"$code\",\"invitationCode\":\"\"},\"oktaRedirectUrl\":\"https://4innovation-$env.cms.gov/secure\"}" | jq -r ".jwt")"

echo "$jwt"
