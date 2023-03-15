public class BoxAuthProvider extends Auth.AuthProviderPluginClass {
    public static final String CUSTOM_METADATA_TYPE = 'unbox__BoxClientCredentialsGrant__mdt';
    public static final String BOX_AUTH_PROVIDER_NAME = 'unbox__BoxAuthProviderName__c';
    public static final String BOX_CLIENT_ID = 'unbox__BoxClientId__c';
    public static final String BOX_CLIENT_SECRET = 'unbox__BoxClientSecret__c';
    public static final String BOX_SUBJECT_TYPE = 'unbox__BoxSubjectType__c';
    public static final String BOX_SUBJECT_ID = 'unbox__BoxSubjectId__c';
    public static final String BOX_API_BASE_URL = 'unbox__BoxApiBaseUrl__c';
    public static final String BOX_TOKEN_ENDPOINT = 'unbox__BoxTokenEndpoint__c';
    public static final String BOX_USERS_ENDPOINT = 'unbox__BoxUsersEndpoint__c';
    public static final String SF_CALLBACK_URL = '/services/authcallback/';


    public static final String HTTP_POST_METHOD = 'POST';
    public static final String HTTP_GET_METHOD = 'GET';
    public static final String HEADER_AUTHORIZATION = 'Authorization';
    public static final String HEADER_CONTENT_TYPE = 'Content-Type';
    public static final String HEADER_APPLICATION_ENCODED = 'application/x-www-form-urlencoded';
    public static final String HEADER_APPLICATION_JSON = 'application/json';
   
    public String getCustomMetadataType() {
        return CUSTOM_METADATA_TYPE;
    } 

    public PageReference initiate(Map<String, String> authProviderConfiguration, String stateToPropagate) {
        String baseUrl = URL.getSalesforceBaseUrl().toExternalForm();
        String url = baseUrl + SF_CALLBACK_URL + authProviderConfiguration.get(BOX_AUTH_PROVIDER_NAME) + '?state=' + stateToPropagate;
        return new PageReference(url);
    }

    public Auth.AuthProviderTokenResponse handleCallback(Map<String, String> authProviderConfiguration, Auth.AuthProviderCallbackState state ) {
        Map<String, String> clientCredentialsGrantMap = new Map<String, String>();
        BoxClientCredentialsGrant__mdt boxClientCredentialsGrant = [
            SELECT Id, Label, unbox__BoxClientId__c, unbox__BoxClientSecret__c, unbox__BoxSubjectType__c, unbox__BoxSubjectId__c 
                FROM unbox__BoxClientCredentialsGrant__mdt 
                WHERE unbox__BoxClientId__c = :authProviderConfiguration.get(BOX_CLIENT_ID) 
                LIMIT 1
            ];

        clientCredentialsGrantMap.put('client_id', authProviderConfiguration.get(BOX_CLIENT_ID));
        clientCredentialsGrantMap.put('client_secret', authProviderConfiguration.get(BOX_CLIENT_SECRET));
        clientCredentialsGrantMap.put('grant_type', 'client_credentials');
        clientCredentialsGrantMap.put('box_subject_type', boxClientCredentialsGrant.BoxSubjectType__c);
        clientCredentialsGrantMap.put('box_subject_id', authProviderConfiguration.get(BOX_SUBJECT_ID));
        
        String tokenEndpoint = authProviderConfiguration.get(BOX_API_BASE_URL) + authProviderConfiguration.get(BOX_TOKEN_ENDPOINT);
        BoxAuthResponse boxAuthResponse = getAccessToken(tokenEndpoint, clientCredentialsGrantMap);
        
        return new Auth.AuthProviderTokenResponse(
            authProviderConfiguration.get(BOX_AUTH_PROVIDER_NAME), 
            boxAuthResponse.access_token, 
            boxAuthResponse.refresh_token, 
            state.queryParameters.get('state'));
    } 

    public override Auth.OAuthRefreshResult refresh(Map<String,String> authProviderConfiguration, String refreshToken) {
        Map<String, String> refreshTokenMap = new Map<String, String>();
        refreshTokenMap.put('client_id', authProviderConfiguration.get(BOX_CLIENT_ID));
        refreshTokenMap.put('client_secret', authProviderConfiguration.get(BOX_CLIENT_SECRET));
        refreshTokenMap.put('grant_type', 'refresh_token');
        refreshTokenMap.put('refresh_token', refreshToken);

        String tokenEndpoint = authProviderConfiguration.get(BOX_API_BASE_URL) + authProviderConfiguration.get(BOX_TOKEN_ENDPOINT);
        BoxAuthResponse boxAuthResponse = getAccessToken(tokenEndpoint, refreshTokenMap);

        return new Auth.OAuthRefreshResult(boxAuthResponse.access_token, boxAuthResponse.refresh_token);
    }

    public Auth.UserData getUserInfo(Map<String, String> authProviderConfiguration, Auth.AuthProviderTokenResponse response) {
        String usersEndpoint = authProviderConfiguration.get(BOX_API_BASE_URL) + authProviderConfiguration.get(BOX_USERS_ENDPOINT);
        
        String accessToken;
        if(response == null) {
            return new Auth.UserData(
                null, 
                null, 
                null, 
                null, 
                null, 
                null, 
                'Box User', 
                null, 
                authProviderConfiguration.get(BOX_AUTH_PROVIDER_NAME), 
                'https://account.box.com',
                new Map<String,String>());
        }
        else {
            HttpRequest httpRequest = new HttpRequest();
            httpRequest.setMethod(HTTP_GET_METHOD);
            httpRequest.setEndpoint(usersEndpoint);
            httpRequest.setHeader(HEADER_AUTHORIZATION, 'Bearer ' + response.oauthToken);
            httpRequest.setHeader(HEADER_CONTENT_TYPE, HEADER_APPLICATION_JSON);

            Http http = new Http();
            HttpResponse httpResponse = http.send(httpRequest);
            String body = httpResponse.getBody();
            BoxUserResponse boxUserResponse = BoxUserResponse.parse(body);

            return new Auth.UserData(
                boxUserResponse.id, 
                null, 
                null, 
                boxUserResponse.name, 
                boxUserResponse.login, 
                null, 
                boxUserResponse.login, 
                null, 
                authProviderConfiguration.get(BOX_AUTH_PROVIDER_NAME), 
                'https://account.box.com',
                new Map<String,String>());
        }

        
	}

    private static BoxAuthResponse getAccessToken(String tokenEndpoint, Map<String, String> urlParameterMap) {
        String encodedUrl = urlEncode(urlParameterMap);

        HttpRequest httpRequest = new HttpRequest();
        httpRequest.setMethod(HTTP_POST_METHOD);
        httpRequest.setEndpoint(tokenEndpoint);
        httpRequest.setHeader(HEADER_CONTENT_TYPE, HEADER_APPLICATION_ENCODED);
        httpRequest.setBody(encodedUrl);

        Http http = new Http();
        HttpResponse response = http.send(httpRequest);
        String body = response.getBody();
        BoxAuthResponse boxAuthResponse = BoxAuthResponse.parse(body);
        
        return boxAuthResponse;
    }

    private static String urlEncode(Map<String, String> urlParameterMap) {
      String result = '';
      for(String key : urlParameterMap.keySet()) {
          result += EncodingUtil.urlEncode(key, 'UTF-8') + '=' + EncodingUtil.urlEncode(urlParameterMap.get(key), 'UTF-8') + '&';
      }
      return result.removeEnd('&');    
    }

    public class BoxAuthProviderException extends Exception {
        public Integer status;
        public String code;
        public String message;
        public String requestId;

        public BoxAuthProviderException setDetails(Integer status, String code, String message, String requestId) {
            this.status = status;
            this.code = code;
            this.message = message;
            this.requestId = requestId;
            return this;
        }
    }
}