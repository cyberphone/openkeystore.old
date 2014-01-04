/*
 *  Copyright 2006-2014 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

/*================================================================*/
/*                            JSONTypes                           */
/*================================================================*/

var JSONTypes = 
  {
    NULL:
      {
        "enumvalue" : function () { return 0;},
        "compatible" : function (o) { return o == JSONTypes.NULL;}
      },
    BOOLEAN:
      {
        "enumvalue" : function () { return 1;},
        "compatible" : function (o) { return o == JSONTypes.BOOLEAN;}
      },
    INTEGER:
      {
        "enumvalue" : function () { return 2;},
        "compatible" : function (o) { return o == JSONTypes.INTEGER;}
      },
    DECIMAL:
      {
        "enumvalue" : function () { return 3;},
        "compatible" : function (o) { return o == JSONTypes.DECIMAL || o == JSONTypes.INTEGER;}
      },
    DOUBLE:
      {
        "enumvalue" : function () { return 4;},
        "compatible" : function (o) { return o == JSONTypes.DOUBLE || o == JSONTypes.DECIMAL || o == JSONTypes.INTEGER;}
      },
    STRING:
      {
        "enumvalue" : function () { return 5;},
        "compatible" : function (o) { return o == JSONTypes.STRING;}
      },
    ARRAY:
      {
        "enumvalue" : function () { return 10;},
        "compatible" : function (o) { return o == JSONTypes.ARRAY;}
      },
    OBJECT:
      {
        "enumvalue" : function () { return 11;},
        "compatible" : function (o) { return o == JSONTypes.OBJECT;}
      }
  };
