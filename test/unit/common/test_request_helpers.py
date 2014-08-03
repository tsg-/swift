# Copyright (c) 2010-2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for swift.common.request_helpers"""

import unittest
import hashlib
from swift.common.swob import Request
from swift.common.request_helpers import is_sys_meta, is_user_meta, \
    is_sys_or_user_meta, strip_sys_meta_prefix, strip_user_meta_prefix, \
    remove_items, copy_header_subset, ObjectPayloadTrailer
from swift.common.swob import HTTPException

server_types = ['account', 'container', 'object']


class TestRequestHelpers(unittest.TestCase):
    def test_is_user_meta(self):
        m_type = 'meta'
        for st in server_types:
            self.assertTrue(is_user_meta(st, 'x-%s-%s-foo' % (st, m_type)))
            self.assertFalse(is_user_meta(st, 'x-%s-%s-' % (st, m_type)))
            self.assertFalse(is_user_meta(st, 'x-%s-%sfoo' % (st, m_type)))

    def test_is_sys_meta(self):
        m_type = 'sysmeta'
        for st in server_types:
            self.assertTrue(is_sys_meta(st, 'x-%s-%s-foo' % (st, m_type)))
            self.assertFalse(is_sys_meta(st, 'x-%s-%s-' % (st, m_type)))
            self.assertFalse(is_sys_meta(st, 'x-%s-%sfoo' % (st, m_type)))

    def test_is_sys_or_user_meta(self):
        m_types = ['sysmeta', 'meta']
        for mt in m_types:
            for st in server_types:
                self.assertTrue(is_sys_or_user_meta(st, 'x-%s-%s-foo'
                                                    % (st, mt)))
                self.assertFalse(is_sys_or_user_meta(st, 'x-%s-%s-'
                                                     % (st, mt)))
                self.assertFalse(is_sys_or_user_meta(st, 'x-%s-%sfoo'
                                                     % (st, mt)))

    def test_strip_sys_meta_prefix(self):
        mt = 'sysmeta'
        for st in server_types:
            self.assertEquals(strip_sys_meta_prefix(st, 'x-%s-%s-a'
                                                    % (st, mt)), 'a')

    def test_strip_user_meta_prefix(self):
        mt = 'meta'
        for st in server_types:
            self.assertEquals(strip_user_meta_prefix(st, 'x-%s-%s-a'
                                                     % (st, mt)), 'a')

    def test_remove_items(self):
        src = {'a': 'b',
               'c': 'd'}
        test = lambda x: x == 'a'
        rem = remove_items(src, test)
        self.assertEquals(src, {'c': 'd'})
        self.assertEquals(rem, {'a': 'b'})

    def test_copy_header_subset(self):
        src = {'a': 'b',
               'c': 'd'}
        from_req = Request.blank('/path', environ={}, headers=src)
        to_req = Request.blank('/path', {})
        test = lambda x: x.lower() == 'a'
        copy_header_subset(from_req, to_req, test)
        self.assertTrue('A' in to_req.headers)
        self.assertEqual(to_req.headers['A'], 'b')
        self.assertFalse('c' in to_req.headers)
        self.assertFalse('C' in to_req.headers)

    def assertRaisesWithMessage(self, exc_class, message, f, *args, **kwargs):
        try:
            f(*args, **kwargs)
        except exc_class as err:
            err_msg = str(err)
            self.assert_(message in err_msg, 'Error message %r did not '
                         'have expected substring %r' % (err_msg, message))
        else:
            self.fail('%r did not raise %s' % (message, exc_class.__name__))

    def test_object_payload_trailer_get_size(self):
        trailer_size = ObjectPayloadTrailer.get_trailer_size()
        for i in xrange(0, 20):
            self.assertEquals(ObjectPayloadTrailer.get_trailer_size(),
                              trailer_size)

    def test_object_payload_trailer_good_serialize_deserialize(self):
        obj_bytes = b'qwertyuiop'
        obj_md5 = hashlib.md5()
        obj_md5.update(obj_bytes)

        trailer = ObjectPayloadTrailer(obj_md5, len(obj_bytes), obj_md5)
        trailer_bytes = trailer.serialize()
        self.assertEquals(len(trailer_bytes),
                          ObjectPayloadTrailer.get_trailer_size())

        trailer_dict = ObjectPayloadTrailer.deserialize(trailer_bytes)
        self.assertTrue('ETag' in trailer_dict)
        self.assertTrue('X-Object-Content-Length' in trailer_dict)
        self.assertTrue('X-Object-ETag' in trailer_dict)

        self.assertEquals(trailer_dict['ETag'],
                          obj_md5.hexdigest())
        self.assertEquals(trailer_dict['X-Object-ETag'],
                          obj_md5.hexdigest())
        self.assertEquals((int)(trailer_dict['X-Object-Content-Length']),
                          len(obj_bytes))

    def test_object_payload_trailer_json_decode_error(self):
        obj_bytes = b'qwertyuiop'
        obj_md5 = hashlib.md5()
        obj_md5.update(obj_bytes)

        trailer = ObjectPayloadTrailer(obj_md5, len(obj_bytes), obj_md5)
        trailer_bytes = trailer.serialize()

        # Polute trailer magic, expect invalid trailer error
        trailer_bytes_x = '1' + trailer_bytes[1:]
        # TBD use assertRaisesMessage - cannot figure out how to do that with
        # generic HTTP exceptions yet
        self.assertRaises(HTTPException,
                          ObjectPayloadTrailer.deserialize, trailer_bytes_x)

        # Polute md5sum, expect checksum error
        trailer_bytes_y1 = trailer_bytes[:4] + 'f' + trailer_bytes[5:]
        # TBD use assertRaisesMessage - cannot figure out how to do that with
        # generic HTTP exceptions yet
        self.assertRaises(HTTPException,
                          ObjectPayloadTrailer.deserialize, trailer_bytes_y1)

        # Truncated stream, expect checksum error
        trailer_bytes_y2 = trailer_bytes[:50]
        # TBD use assertRaisesMessage - cannot figure out how to do that with
        # generic HTTP exceptions yet
        self.assertRaises(HTTPException,
                          ObjectPayloadTrailer.deserialize, trailer_bytes_y2)

        # Polute trailer JSON data, expect decode error
        trailer_bytes_z = trailer_bytes[:43] + '\xfd' + trailer_bytes[44:]
        poluted_json_bytes = trailer_bytes_z[36:]
        poluted_json_bytes_md5 = hashlib.md5()
        poluted_json_bytes_md5.update(poluted_json_bytes)
        trailer_bytes_z = trailer_bytes_z[:4] + \
            poluted_json_bytes_md5.hexdigest() + poluted_json_bytes
        # TBD use assertRaisesMessage - cannot figure out how to do that with
        # generic HTTP exceptions yet
        self.assertRaises(HTTPException,
                          ObjectPayloadTrailer.deserialize, trailer_bytes_z)

    def assertRaisesMessage(self, exc, msg, func, *args, **kwargs):
        try:
            func(*args, **kwargs)
        except Exception as e:
            self.assertTrue(msg in str(e),
                            "Expected %r in %r" % (msg, str(e)))
            self.assertTrue(isinstance(e, exc),
                            "Expected %s, got %s" % (exc, type(e)))
