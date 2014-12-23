import json
import collections
json_str= '{"a":6, "b":7,"c":[7,5]}'
my_ordered_dict = json.loads(json_str, object_pairs_hook=collections.OrderedDict)
print my_ordered_dict
my_ordered_dict.pop('b')
print json.dumps(my_ordered_dict)

