@isTest
public with sharing class BoxAuthProviderTest {
    public static final String CUSTOM_METADATA_TYPE = 'unbox__BoxClientCredentialsGrant__mdt';
    public static final String BOX_AUTH_PROVIDER_NAME = 'BoxCCG';
    public static final String BOX_CLIENT_ID = '141uw2duh1es7upm46n0e44sku5qerpn';
    public static final String BOX_CLIENT_SECRET = 'gZ4L21GRMHOptnU2R2R4zvlvJ9TK4hZz';
    public static final String BOX_SUBJECT_TYPE = 'enterprise';
    public static final String BOX_SUBJECT_ID = '5105484';
    public static final String BOX_API_BASE_URL = 'http://api.box.com/2.0';
    public static final String BOX_TOKEN_ENDPOINT = '/oauth2/token';
    public static final String BOX_USERS_ENDPOINT = '/users/me?fields=id,name,login';
    public static final String SF_CALLBACK_URL = '/services/authcallback/';

    public static final String HTTP_POST_METHOD = 'POST';
    public static final String HTTP_GET_METHOD = 'GET';
    public static final String HEADER_AUTHORIZATION = 'Authorization';
    public static final String HEADER_CONTENT_TYPE = 'Content-Type';
    public static final String HEADER_APPLICATION_ENCODED = 'application/x-www-form-urlencoded';
    public static final String HEADER_APPLICATION_JSON = 'application/json';
    public static final String BOX_ACCESS_TOKEN = 'abc123';
    public static final String BOX_REFRESH_TOKEN = 'zyx321';
    public static final String BOX_FULLNAME = 'box-ccd-developer-app';
    public static final String BOX_LOGIN = 'AutomationUser_123456_abc123@boxdevedition.com';
    public static final String BOX_USER_ID = '123456';


    private static Map<String,String> setupAuthProviderConfig () { 
        Map<String,String> authProviderConfiguration = new Map<String,String>(); 
        authProviderConfiguration.put('unbox__BoxClientId__c', BOX_CLIENT_ID);
        authProviderConfiguration.put('unbox__BoxClientSecret__c', BOX_CLIENT_SECRET);
        authProviderConfiguration.put('unbox__BoxSubjectType__c', BOX_SUBJECT_TYPE);
        authProviderConfiguration.put('unbox__BoxSubjectId__c', BOX_SUBJECT_ID);
        authProviderConfiguration.put('unbox__BoxApiBaseUrl__c', BOX_API_BASE_URL);
        authProviderConfiguration.put('unbox__BoxTokenEndpoint__c', BOX_TOKEN_ENDPOINT);
        authProviderConfiguration.put('unbox__BoxUsersEndpoint__c', BOX_USERS_ENDPOINT);
        authProviderConfiguration.put('unbox__BoxAuthProviderName__c', BOX_AUTH_PROVIDER_NAME);
        
        return authProviderConfiguration; 
    } 

    public static testMethod void testGetMetadataType() {
        BoxAuthProvider instance = new BoxAuthProvider();
        System.assertEquals(
            BoxAuthProvider.CUSTOM_METADATA_TYPE,
            instance.getCustomMetadataType()
        );
    }

    public static testMethod void testInitiate() {
        Map<String,String> authProviderConfiguration = setupAuthProviderConfig(); 
        BoxAuthProvider instance = new BoxAuthProvider();        
        String stateToPropagate = 'someState';
        String url = URL.getSalesforceBaseUrl().toExternalForm() + SF_CALLBACK_URL + BOX_AUTH_PROVIDER_NAME + '?state=' + stateToPropagate;
        PageReference expectedUrl = new PageReference(url);
        PageReference actualUrl = instance.initiate(authProviderConfiguration, stateToPropagate);
        System.assertEquals(expectedUrl.getUrl(), actualUrl.getUrl());
    }

    public static testMethod void testHandleCallback_Success() {
        Map<String,String> authProviderConfiguration = setupAuthProviderConfig(); 
        final BoxCalloutMock httpMock = new BoxCalloutMock(BOX_API_BASE_URL + BOX_TOKEN_ENDPOINT, true);
        Test.setMock(HttpCalloutMock.class, httpMock);
        BoxAuthProvider instance = new BoxAuthProvider();

        final Map<String, String> queryArgs = new Map<String, String>();
        queryArgs.put('state', 'someState');
        Auth.AuthProviderCallbackState callbackState = new Auth.AuthProviderCallbackState(
            new Map<String, String>(),
            '',
            queryArgs
        );

        Auth.AuthProviderTokenResponse response = instance.handleCallback(authProviderConfiguration, callbackState);

     
        String body = String.format('client_id={0}&client_secret={1}&grant_type=client_credentials&box_subject_type={2}&box_subject_id={3}', 
        new List<String> {BOX_CLIENT_ID, BOX_CLIENT_SECRET, BOX_SUBJECT_TYPE, BOX_SUBJECT_ID});
        Assert.isNotNull(response.provider);
        System.assertEquals('random_access_token', response.oauthToken);
        System.assertEquals('random_refresh_token', response.oauthSecretOrRefreshToken);
        System.assertEquals('someState', response.state);
    }

    public static testMethod void testHandleCallback_Error() {
        Map<String,String> authProviderConfiguration = setupAuthProviderConfig(); 
        final BoxCalloutMock httpMock = new BoxCalloutMock(BOX_API_BASE_URL + BOX_TOKEN_ENDPOINT, false);
        Test.setMock(HttpCalloutMock.class, httpMock);

        final Map<String, String> queryArgs = new Map<String, String>();
        Auth.AuthProviderCallbackState callbackState = new Auth.AuthProviderCallbackState(
            new Map<String, String>(),
            '',
            queryArgs
        );

        BoxAuthProvider instance = new BoxAuthProvider();
        Auth.AuthProviderTokenResponse response = instance.handleCallback(authProviderConfiguration, callbackState);
        Assert.isNull(response.oauthToken);
        Assert.isNull(response.oauthSecretOrRefreshToken);
        Assert.isNull(response.state);
        Assert.isNotNull(response.provider);
    }

    static testMethod void testGetUserInfo() { 
        Map<String,String> authProviderConfiguration = setupAuthProviderConfig(); 
        BoxAuthProvider instance = new BoxAuthProvider();          
        
        Auth.UserData actualUserData = instance.getUserInfo(authProviderConfiguration, null) ; 
        Assert.isNotNull(actualUserData.provider);
    } 

    public static testMethod void testRefresh() {
        Map<String,String> authProviderConfiguration = setupAuthProviderConfig(); 
        BoxCalloutMock httpMock = new BoxCalloutMock(BOX_API_BASE_URL + BOX_TOKEN_ENDPOINT, true);
        Test.setMock(HttpCalloutMock.class, httpMock);

        BoxAuthProvider instance = new BoxAuthProvider();   
        String refreshToken = EncodingUtil.base64Encode(Crypto.generateAesKey(128)); 
        Auth.OAuthRefreshResult response = instance.refresh(authProviderConfiguration, refreshToken);

        System.assertEquals('random_access_token', response.accessToken);
        System.assertEquals('random_refresh_token', response.refreshToken);
        System.assert(null == response.error);
    }

    private class BoxCalloutMock implements HttpCalloutMock {
        private String boxEndpoint;
        private Boolean isSuccessful;
        private Integer statusCode;
        private String responseBody;

        public BoxCalloutMock(String boxEndpoint, Boolean isSuccessful) {
            this.boxEndpoint = boxEndpoint;
            this.isSuccessful = isSuccessful;
        }

   
        public HTTPResponse respond(HTTPRequest httpRequest) {
            HttpResponse httpResponse = new HttpResponse();
            httpResponse.setHeader('Content-Type', HEADER_APPLICATION_JSON);        

            String endpoint = HttpRequest.getEndpoint();
            if(endpoint.equalsIgnoreCase(BOX_API_BASE_URL + BOX_TOKEN_ENDPOINT)) {
                if(this.isSuccessful) {
                    this.responseBody = '{"access_token": "random_access_token", "refresh_token": "random_refresh_token"}';
                    this.statusCode = 200;
                }else {
                    this.responseBody = '{"type": "error", "status": 401, "code": "Unauthorized", "message": "Authorization token is not authorized, check extended error message in body for more details","request_id": "abcdef123456"}';
                    this.statusCode = 401;
                }
            }
            else {
                if(this.isSuccessful) {
                    this.responseBody = String.format('{"id": "{0}", "name": "{1}", "login": "{2}"}', new List<String> {
                        BOX_USER_ID, BOX_FULLNAME, BOX_FULLNAME
                    });    
                    this.statusCode = 200;
                }else {
                    this.responseBody = '{"type": "error", "status": 404, "code": "not_found", "message": "The resource could not be found. Check the extended error message in the response body for more details.","request_id": "abcdef123456"}';
                    this.statusCode = 404;
                }
            }   
            httpResponse.setBody(this.responseBody);
            httpResponse.setStatusCode(this.statusCode);
            return httpResponse;
        }
    }

    private static String urlEncode(Map<String, String> urlParameterMap) {
        String result = '';
        for(String key : urlParameterMap.keySet()) {
            result += EncodingUtil.urlEncode(key, 'UTF-8') + '=' + EncodingUtil.urlEncode(urlParameterMap.get(key), 'UTF-8') + '&';
        }
        return result.removeEnd('&');    
      }
}