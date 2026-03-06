#!/bin/bash

# We need to access a cookie jar file that will be used for this Login sequence
# This cookie jar file needs to be reset every time we start a new Login sequence
rm -f /opt/cookie_jar

username=$1
password=$2

# First Step: We need to generate a Session Token 
sessionToken="$(curl -s -X POST 'https://impl.idp.idm.cms.gov/api/v1/authn' -H 'Content-Type: application/json' -H 'Accept: application/json' -d "{ \"username\": \"$username\", \"password\": \"$password\", \"options\": { \"warnBeforePasswordExpired\": true, \"multiOptionalFactorEnroll\": false} }" | jq -r ".sessionToken")"



#sessionToken="$(curl -s -X POST 'https://impl.idp.idm.cms.gov/api/v1/authn' -H 'Content-Type: application/json' -H 'Accept: application/json' -d '{ "username": "<username>", "password": "<password>", "options": { "warnBeforePasswordExpired": true, "multiOptionalFactorEnroll": false} }' | jq -r ".sessionToken")"

# Second Step: We need to call the session cookie redirect endpoint with the session token received in Step 1 
url="$(curl -i -c /opt/cookie_jar -s -X GET "https://impl.idp.idm.cms.gov/login/sessionCookieRedirect?checkAccountSetupComplete=true&token=$sessionToken&redirectUrl=https%3A%2F%2Fimpl.idp.idm.cms.gov%2Foauth2%2Faus2mth3kjvm3Y4BK297%2Fv1%2Fauthorize%3Fclient_id%3D0oa2mtg1rsJdE6utv297%26response_type%3Dcode%26scope%3Dopenid%20offline_access%26redirect_uri%3Dhttps%3A%2F%2F4innovation-impl.cms.gov%2Fsecure%26sessionToken%3D$sessionToken%26state%3Dcomplete%26nonce%3D%7B%7B%24guid%7D%7D" | grep location | cut -d ' ' -f2 )"

#echo "Session Token: "$sessionToken
#echo "URL1 : "$url
# Third Step: We need to call oauth2 authorize endpoint with the session token received in Step 1
url="$(curl -i -b /opt/cookie_jar -c /opt/cookie_jar -s -X GET "https://impl.idp.idm.cms.gov/oauth2/aus2mth3kjvm3Y4BK297/v1/authorize?client_id=0oa2mtg1rsJdE6utv297&response_type=code&scope=openid%20offline_access&redirect_uri=https://4innovation-impl.cms.gov/secure&sessionToken=$sessionToken&state=complete&nonce=%7B%7B%24guid%7D%7D" | grep location)"

#echo "URL2: "$url
#echo "code: "$url | cut -d '=' -f2 | cut -d '&' -f1

code=$(echo $url | cut -d '=' -f2 | cut -d '&' -f1)
#echo "code: "$code

# Fourth Step: Finally we need to call the auth login endpoint to retrieve the JWT Token
jwt="$(curl -s -X POST 'https://4innovation-impl-api.cms.gov/idm/auth/login' -H 'Content-Type: application/json' -H 'Accept: application/json' -H 'Authorization: public_endpoints_only' -d "{\"authInput\":{\"access_token\":\"\",\"idToken\":\"\",\"authCode\":\"$code\",\"invitationCode\":\"\"},\"oktaRedirectUrl\":\"https://4innovation-impl.cms.gov/secure\"}" | jq -r ".jwt")"

echo $jwt
