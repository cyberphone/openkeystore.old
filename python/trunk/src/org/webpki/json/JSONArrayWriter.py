##############################################################################
#                                                                            #
#  Copyright 2006-2015 WebPKI.org (http://webpki.org).                       #
#                                                                            #
#  Licensed under the Apache License, Version 2.0 (the "License");           #
#  you may not use this file except in compliance with the License.          #
#  You may obtain a copy of the License at                                   #
#                                                                            #
#      http://www.apache.org/licenses/LICENSE-2.0                            #
#                                                                            #
#  Unless required by applicable law or agreed to in writing, software       #
#  distributed under the License is distributed on an "AS IS" BASIS,         #
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  #
#  See the License for the specific language governing permissions and       #
#  limitations under the License.                                            #
#                                                                            #
##############################################################################

from collections import OrderedDict

from org.webpki.json.Utils import base64UrlEncode
from org.webpki.json.Utils import serializeJson

class new:
    def __init__(self):
        self.array = list()

    def setInt(self,value):
        if not isinstance(value,int):
            raise TypeError('Integer expected')
        return self._put(value)

    def setString(self,value):
        if not isinstance(value,str):
            raise TypeError('String expected')
        return self._put(value)

    def setFloat(self,value):
        if isinstance(value, int):
            value = float(value)
        elif not isinstance(value,float):
            raise TypeError('Float expected')
        return self._put(value)

    def setObject(self):
        newObject = new()
        self._put(newObject.root)
        return newObject

    def setBinary(self,value):
        if not isinstance(value, str):
            raise TypeError('String or bytearray expected')
        return self._put(base64UrlEncode(value))

    def _put(self,value):
        self.array.append(value)
        return self

    def serialize(self):
        return serializeJson(self.array)
