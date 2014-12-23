import json
import collections

jsonObject = collections.OrderedDict()
jsonObject['l'] = 7
jsonObject['k'] = 6
jsonObject['4'] = 6
mm = jsonObject['m'] = collections.OrderedDict()
mm['l'] = 'juk'
mm['j'] = 'puk'
jo2 = collections.OrderedDict(jsonObject['m'])
jsonObject['m'].pop('l')
normalized_result = json.dumps(jsonObject,separators=(',',':'),ensure_ascii=False)
print normalized_result
jsonObject['m'] = jo2

normalized_result = json.dumps(jsonObject,separators=(',',':'),ensure_ascii=False)
print normalized_result

