import json
import collections

jcs_signed_data = (
'{ '
'  "now": "2014-12-08T10:25:17Z", '
'  "escapeMe": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/", '
'  "numbers": [1e0, 4.50, 6], '
'  "signature": '
'    { '
'      "algorithm": "ES256", '
'      "publicKey": '
'        { '
'          "type": "EC", '
'          "curve": "P-256", '
'          "x": "lNxNvAUEE8t7DSQBft93LVSXxKCiVjhbWWfyg023FCk", '
'          "y": "LmTlQxXB3LgZrNLmhOfMaCnDizczC_RfQ6Kx8iNwfFA" '
'        }, '
'      "value": "MEYCIQDGP3HL5aCGaMlgNlqqnPbq-Dhkli4SkfV_ZoGlhGroowIhAPlPhXOsjpPHgQ8E8M-jUQo8lfgO_GRZUJKsg_-u-aJO" '
'    } '
'}'
)

jsonObject = json.loads(jcs_signed_data, object_pairs_hook=collections.OrderedDict)
parsed_signature = json.dumps(jsonObject,separators=(',',':'),ensure_ascii=False)
print parsed_signature
#get all but the signature value
savedSignatureObject = collections.OrderedDict(jsonObject['signature'])
jsonObject['signature'].pop('value')
normalized_result = json.dumps(jsonObject,separators=(',',':'),ensure_ascii=False)
print normalized_result
jsonObject['signature'] = savedSignatureObject
print json.dumps(jsonObject,separators=(',',':'),ensure_ascii=False)

expected_result_adjusted_for_FP = (
u'{"now":"2014-12-08T10:25:17Z","escapeMe":"\u20ac$\\u000f\\nA\'B\\"\\\\\\\\\\"/","numbers":[1.0,4.5,6],"signature":'
u'{"algorithm":"ES256","publicKey":{"type":"EC","curve":"P-256","x":"lNxNvAUEE8t7DSQBft93LVSXxKCiVjhbWW'
u'fyg023FCk","y":"LmTlQxXB3LgZrNLmhOfMaCnDizczC_RfQ6Kx8iNwfFA"}}}'
)


print expected_result_adjusted_for_FP == normalized_result


