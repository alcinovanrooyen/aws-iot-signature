'use strict';

const   _conf = require('./conf'),
		AWS = require("aws-sdk");
		
		AWS.config.update( { region: _conf.cred.aws.region } );

const getSignatureKey = (key, date, region, service) =>{
	var kDate = AWS.util.crypto.hmac('AWS4' + key, date, 'buffer');
    var kRegion = AWS.util.crypto.hmac(kDate, region, 'buffer');
    var kService = AWS.util.crypto.hmac(kRegion, service, 'buffer');
    var kCredentials = AWS.util.crypto.hmac(kService, 'aws4_request', 'buffer');    
    return kCredentials;
};

module.exports = {
	iotSignedV4Url: (host = _conf.cred.aws.iot.endPoint, region = _conf.cred.aws.region, credentials = { accessKeyId: _conf.cred.aws.iot.key, secretAccessKey: _conf.cred.aws.iot.secret }) => {
		var datetime = AWS.util.date.iso8601(new Date()).replace(/[:\-]|\.\d{3}/g, '');
	    var date = datetime.substr(0, 8);
	
	    var method = 'GET';
	    var protocol = 'wss';
	    var uri = '/mqtt';
	    var service = 'iotdevicegateway';
	    var algorithm = 'AWS4-HMAC-SHA256';
	
	    var credentialScope = date + '/' + region + '/' + service + '/' + 'aws4_request';
	    var canonicalQuerystring = 'X-Amz-Algorithm=' + algorithm;
	    canonicalQuerystring += '&X-Amz-Credential=' + encodeURIComponent(credentials.accessKeyId + '/' + credentialScope);
	    canonicalQuerystring += '&X-Amz-Date=' + datetime;
	    canonicalQuerystring += '&X-Amz-SignedHeaders=host';
	
	    var canonicalHeaders = 'host:' + host + '\n';
	    var payloadHash = AWS.util.crypto.sha256('', 'hex')
	    var canonicalRequest = method + '\n' + uri + '\n' + canonicalQuerystring + '\n' + canonicalHeaders + '\nhost\n' + payloadHash;
	
	    var stringToSign = algorithm + '\n' + datetime + '\n' + credentialScope + '\n' + AWS.util.crypto.sha256(canonicalRequest, 'hex');
	    var signingKey = getSignatureKey(credentials.secretAccessKey, date, region, service);
	    var signature = AWS.util.crypto.hmac(signingKey, stringToSign, 'hex');
	
	    canonicalQuerystring += '&X-Amz-Signature=' + signature;
	    if (credentials.sessionToken) {
	        canonicalQuerystring += '&X-Amz-Security-Token=' + encodeURIComponent(credentials.sessionToken);
	    }
	
	    var requestUrl = protocol + '://' + host + uri + '?' + canonicalQuerystring;
	    return requestUrl;
	}
};
