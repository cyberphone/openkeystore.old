org.example = org.example || {};
org.example.json = org.example.json || {};

//////////////////////////////////////////////
// InvocationRequest Decoder
//////////////////////////////////////////////

org.example.json.InvocationRequest = function ()
{
};

org.example.json.InvocationRequest.prototype.readJSONData = function (json_object_reader)
{
    this.submit_url = json_object_reader.getString ("SubmitURL");
    this.server_session_id = json_object_reader.getString ("ServerSessionID");
    this.action = json_object_reader.getString ("Action");
};

org.example.json.InvocationRequest.prototype.getContext = function ()
{
    return "http://org.example.json/protocol";
};

org.example.json.InvocationRequest.prototype.getQualifier = function ()
{
    return "InvocationRequest";
};

//////////////////////////////////////////////
// InvocationResponse Decoder
//////////////////////////////////////////////

org.example.json.InvocationResponse = function ()
{
};

org.example.json.InvocationResponse.prototype.readJSONData = function (json_object_reader)
{
    this.server_session_id = json_object_reader.getString ("ServerSessionID");
    this.image_preferences = [];
    if (json_object_reader.hasProperty ("ImagePreferences"))
    {
        // If present it must contain at least one item, hence the do {} while
        var json_array_reader = json_object_reader.getArray ("ImagePreferences");
        do
        {
            var pref_reader = json_array_reader.getObject ();
            var pref_object = new Object ();
            pref_object.type = pref_reader.getString ("Type");
            pref_object.mime_type = pref_reader.getString ("MimeType");
            pref_object.width = pref_reader.getInt ("Width");
            pref_object.height = pref_reader.getInt ("Height");
            this.image_preferences[this.image_preferences.length] = pref_object;
        }
        while (json_array_reader.hasMore ());
    }
};

org.example.json.InvocationResponse.prototype.getContext = function ()
{
    return "http://org.example.json/protocol";
};

org.example.json.InvocationResponse.prototype.getQualifier = function ()
{
    return "InvocationResponse";
};

//////////////////////////////////////////////
// Setting up the cache (class factory)
//////////////////////////////////////////////

var cache = new org.webpki.json.JSONDecoderCache ();
 cache.addToCache (org.example.json.InvocationResponse);
 cache.addToCache (org.example.json.InvocationRequest);

//////////////////////////////////////////////
// Sample Messages
//////////////////////////////////////////////

var invocation_request =
'{\
 "@context": "http://org.example.json/protocol",\
 "@qualifier": "InvocationRequest",\
 "ServerSessionID": "142f1bdb286XVQnqmIRc1bSzm-QN-ZJk",\
 "SubmitURL": "http://issuer.example.com/platform",\
 "Action": "manage"\
}';

var invocation_response =
'{\
 "@context": "http://org.example.json/protocol",\
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

// Note: ImagePreferences is an optional item

var invocation_response_2 =
'{\
 "@context": "http://org.example.json/protocol",\
 "@qualifier": "InvocationResponse",\
 "ServerSessionID": "142f1bdb286XVQnqmIRc1bSzm-QN-ZJk"\
}';

//////////////////////////////////////////////
// Run!
//////////////////////////////////////////////

// Remove any of the property read statements above and you can see what the following method does...
// cache.setCheckForUnreadProperties (false);
var doc1 = cache.parse (invocation_request);
if (!(doc1 instanceof org.example.json.InvocationRequest)) throw "Object error1";    
if (doc1.submit_url != "http://issuer.example.com/platform" || doc1.getContext () != "http://org.example.json/protocol")
{
    throw "Reading";
}

var doc2 = cache.parse (invocation_response);
if (!(doc2 instanceof org.example.json.InvocationResponse)) throw "Object error2";
if (doc2.image_preferences.length != 1)
{
    throw "Image 1 length";
}

if (cache.parse (invocation_response_2).image_preferences.length != 0)
{
    throw "Image 0 length";
}

console.debug ("Successful decoding/instantiation of two different JSON document types");
