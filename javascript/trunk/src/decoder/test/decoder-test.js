org.webpki.keygen2 = org.webpki.keygen2 || {};

//////////////////////////////////////////////
// InvocationRequest Decoder
//////////////////////////////////////////////

org.webpki.keygen2.InvocationRequest = function ()
{
};

org.webpki.keygen2.InvocationRequest.prototype.readJSONData = function (json_object_reader)
{
    this.submit_url = json_object_reader.getString ("SubmitURL");
    this.server_session_id = json_object_reader.getString ("ServerSessionID");
    this.action = json_object_reader.getString ("Action");
};

org.webpki.keygen2.InvocationRequest.prototype.getContext = function ()
{
    return "http://xmlns.webpki.org/keygen2/beta/20131201";
};

org.webpki.keygen2.InvocationRequest.prototype.getQualifier = function ()
{
    return "InvocationRequest";
};

//////////////////////////////////////////////
// InvocationResponse Decoder
//////////////////////////////////////////////

org.webpki.keygen2.InvocationResponse = function ()
{
};

org.webpki.keygen2.InvocationResponse.prototype.readJSONData = function (json_object_reader)
{
    this.server_session_id = json_object_reader.getString ("ServerSessionID");
    this.image_preferences = [];
    if (json_object_reader.hasProperty ("ImagePreferences"))
    {
        var json_array_reader = json_object_reader.getArray ("ImagePreferences");
        while (json_array_reader.hasMore ())
        {
            var pref_reader = json_array_reader.getObject ();
            var pref_object = new Object ();
            pref_object.type = pref_reader.getString ("Type");
            pref_object.mime_type = pref_reader.getString ("MimeType");
            pref_object.width = pref_reader.getInt ("Width");
            pref_object.height = pref_reader.getInt ("Height");
            this.image_preferences[this.image_preferences.length] = pref_object;
        }
    }
};

org.webpki.keygen2.InvocationResponse.prototype.getContext = function ()
{
    return "http://xmlns.webpki.org/keygen2/beta/20131201";
};

org.webpki.keygen2.InvocationResponse.prototype.getQualifier = function ()
{
    return "InvocationResponse";
};

//////////////////////////////////////////////
// Setting up the cache (class factory)
//////////////////////////////////////////////

var cache = new org.webpki.json.JSONDecoderCache ();
cache.addToCache (org.webpki.keygen2.InvocationResponse);
cache.addToCache (org.webpki.keygen2.InvocationRequest);

//////////////////////////////////////////////
// Sample Messages
//////////////////////////////////////////////

var invocation_request =
'{\
 "@context": "http://xmlns.webpki.org/keygen2/beta/20131201",\
 "@qualifier": "InvocationRequest",\
 "ServerSessionID": "142f1bdb286XVQnqmIRc1bSzm-QN-ZJk",\
 "SubmitURL": "http://issuer.example.com/platform",\
 "Action": "manage"\
}';

var invocation_response =
'{\
 "@context": "http://xmlns.webpki.org/keygen2/beta/20131201",\
 "@qualifier": "InvocationResponse",\
 "ServerSessionID": "142f1bdb286XVQnqmIRc1bSzm-QN-ZJk",\
 "ImagePreferences": \
   [{\
      "Type": "http://xmlns.webpki.org/keygen2/logotype#list",\
      "MimeType": "image/png",\
      "Width": 94,\
      "Height": 74\
    }]\
}';

// Note: ImagePreferences is (in this definition NB...) an optional item

var invocation_response_2 =
'{\
 "@context": "http://xmlns.webpki.org/keygen2/beta/20131201",\
 "@qualifier": "InvocationResponse",\
 "ServerSessionID": "142f1bdb286XVQnqmIRc1bSzm-QN-ZJk"\
}';

//////////////////////////////////////////////
// Run!
//////////////////////////////////////////////

// Remove any of the property read statements above and you can see what the following method does...
// cache.setCheckForUnreadProperties (false);

var doc1 = cache.parse (invocation_request);
if (!(doc1 instanceof org.webpki.keygen2.InvocationRequest)) throw "Object error1";    
console.debug ("SubmitURL=" + doc1.submit_url + " @context=" + doc1.getContext ());

var doc2 = cache.parse (invocation_response);
if (!(doc2 instanceof org.webpki.keygen2.InvocationResponse)) throw "Object error2";    
console.debug ("Number of ImagePreferences=" + doc2.image_preferences.length);

console.debug ("Number of ImagePreferences=" + cache.parse (invocation_response_2).image_preferences.length);

console.debug ("Successful decoding/instantiation of two different JSON document types");
