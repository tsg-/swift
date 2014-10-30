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

# NOTE: swift_conn
# You'll see swift_conn passed around a few places in this file. This is the
# source bufferedhttp connection of whatever it is attached to.
#   It is used when early termination of reading from the connection should
# happen, such as when a range request is satisfied but there's still more the
# source connection would like to send. To prevent having to read all the data
# that could be left, the source connection can be .close() and then reads
# commence to empty out any buffers.
#   These shenanigans are to ensure all related objects can be garbage
# collected. We've seen objects hang around forever otherwise.

import itertools
import mimetypes
import time
import math
import random
from hashlib import md5
from pyeclib.ec_iface import ECDriverError
from swift import gettext_ as _
from urllib import unquote, quote

from eventlet import GreenPile
from eventlet.queue import Queue
from eventlet.timeout import Timeout

from swift.common.utils import (
    clean_content_type, config_true_value, ContextPool, csv_append,
    GreenAsyncPile, GreenthreadSafeIterator, json, Timestamp,
    normalize_delete_at_timestamp, public, get_expirer_container)
from swift.common.bufferedhttp import http_connect
from swift.common.constraints import check_metadata, check_object_creation, \
    check_copy_from_header, check_destination_header, \
    check_account_format
from swift.common import constraints
from swift.common.exceptions import ChunkReadTimeout, \
    ChunkWriteTimeout, ConnectionTimeout, ListingIterNotFound, \
    ListingIterNotAuthorized, ListingIterError, ResponseTimeout, \
    InsufficientStorage, FooterNotSupported
from swift.common.http import is_success, is_client_error, \
    HTTP_CREATED, HTTP_MULTIPLE_CHOICES, HTTP_NOT_FOUND, \
    HTTP_INTERNAL_SERVER_ERROR, HTTP_SERVICE_UNAVAILABLE, \
    HTTP_INSUFFICIENT_STORAGE, HTTP_PRECONDITION_FAILED
from swift.common.storage_policy import POLICIES
from swift.proxy.controllers.base import Controller, delay_denial, \
    cors_validation
from swift.common.swob import HTTPAccepted, HTTPBadRequest, HTTPNotFound, \
    HTTPPreconditionFailed, HTTPRequestEntityTooLarge, HTTPRequestTimeout, \
    HTTPServerError, HTTPServiceUnavailable, Request, HeaderKeyDict, \
    HTTPClientDisconnect
from swift.common.request_helpers import is_sys_or_user_meta, is_sys_meta, \
    remove_items, copy_header_subset


def copy_headers_into(from_r, to_r):
    """
    Will copy desired headers from from_r to to_r
    :params from_r: a swob Request or Response
    :params to_r: a swob Request or Response
    """
    pass_headers = ['x-delete-at']
    for k, v in from_r.headers.items():
        if is_sys_or_user_meta('object', k) or k.lower() in pass_headers:
            to_r.headers[k] = v


def check_content_type(req):
    if not req.environ.get('swift.content_type_overridden') and \
            ';' in req.headers.get('content-type', ''):
        for param in req.headers['content-type'].split(';')[1:]:
            if param.lstrip().startswith('swift_'):
                return HTTPBadRequest("Invalid Content-Type, "
                                      "swift_* is not a valid parameter name.")
    return None


NO_DATA_SENT = 1
SENDING_DATA = 2
DONE_SENDING = 3


class Putter(object):
    """
    An HTTP PUT request that supports streaming.

    Probably deserves more docs than this, but meh.
    """
    def __init__(self, conn, node, resp, path, connect_duration, chunked,
                 mime_boundary):
        # Note: you probably want to call Putter.connect() instead of
        # instantiating one of these directly.
        self.conn = conn
        self.node = node
        self.resp = resp
        self.path = path
        self.connect_duration = connect_duration
        self.chunked = chunked
        self.mime_boundary = mime_boundary

        self.failed = False
        self.queue = None
        self.state = NO_DATA_SENT

    def current_status(self):
        """
        Returns the current status of the response.

        A response starts off with no current status, then may or may not have
        a status of 100 for some time, and then ultimately has a final status
        like 200, 404, et cetera.
        """
        return self.resp.status

    def await_final_response(self, timeout):
        """
        Get the final response, i.e. the one with status >= 200.

        Might or might not actually wait for anything. If we said Expect:
        100-continue but got back a non-100 response, that'll be the thing
        returned, and we won't do any network IO to get it. OTOH, if we got
        a 100 Continue response and sent up the PUT request's body, then
        we'll actually read the 2xx-5xx response off the network here.

        :returns: HTTPResponse
        :raises: Timeout if the response took too long
        """
        conn = self.conn
        with Timeout(timeout):
            if not conn.resp:
                conn.resp = conn.getresponse()
            return conn.resp

    def spawn_sender_greenthread(self, pool, queue_depth, write_timeout,
                                 exception_handler):
        """Call before sending the first chunk of request body"""
        self.queue = Queue(queue_depth)
        pool.spawn(self._send_file, write_timeout, exception_handler)

    def wait(self):
        if self.queue.unfinished_tasks:
            self.queue.join()

    def _start_mime_doc(self):
        self.queue.put("--%s\r\nX-Document: object body\r\n\r\n" %
                       (self.mime_boundary,))

    def send_chunk(self, chunk):
        if not chunk:
            # If we're not using chunked transfer-encoding, sending a 0-byte
            # chunk is just wasteful. If we *are* using chunked
            # transfer-encoding, sending a 0-byte chunk terminates the
            # request body. Neither one of these is good.
            return
        elif self.state == DONE_SENDING:
            raise ValueError("called send_chunk after end_of_object_data")

        if self.state == NO_DATA_SENT and self.mime_boundary:
            # We're sending the object plus other stuff in the same request
            # body, all wrapped up in multipart MIME, so we'd better start
            # off the MIME document before sending any object data.
            self._start_mime_doc()
            self.state = SENDING_DATA

        self.queue.put(chunk)

    def end_of_object_data(self, footer_metadata=None):
        """
        Call when there is no more data to send.
        """
        if self.state == DONE_SENDING:
            raise ValueError("called end_of_object_data twice")
        elif self.state == NO_DATA_SENT and self.mime_boundary:
            self._start_mime_doc()

        if footer_metadata is None:
            footer_metadata = {}

        if self.mime_boundary:
            footer_body = json.dumps(footer_metadata)
            footer_md5 = md5(footer_body).hexdigest()

            message_parts = [
                ("\r\n--%s\r\n" % self.mime_boundary),
                "X-Document: object metadata\r\n",
                "Content-MD5: %s\r\n" % footer_md5,
                "\r\n",
                footer_body, "\r\n",
                "--%s--" % (self.mime_boundary,),
            ]
            self.queue.put("".join(message_parts))

        self.queue.put('')
        self.state = DONE_SENDING

    def _send_file(self, write_timeout, exception_handler):
        """
        Method for a file PUT coro. Takes chunks from a queue and sends them
        down a socket.

        If something goes wrong, the "failed" attribute will be set to true
        and the exception handler will be called.
        """
        while True:
            chunk = self.queue.get()
            if not self.failed:
                if self.chunked:
                    to_send = "%x\r\n%s\r\n" % (len(chunk), chunk)
                else:
                    to_send = chunk
                try:
                    with ChunkWriteTimeout(write_timeout):
                        self.conn.send(to_send)
                except (Exception, ChunkWriteTimeout):
                    self.failed = True
                    exception_handler(self.conn.node, _('Object'),
                                      _('Trying to write to %s') % self.path)
            self.queue.task_done()

    @classmethod
    def connect(cls, node, part, path, headers, conn_timeout, node_timeout,
                chunked=False, want_metadata_footer=False,
                need_metadata_footer=False):
        """
        Connect to a backend node and send the headers.

        :returns: Putter instance

        :raises: ConnectionTimeout if initial connection timed out
        :raises: ResponseTimeout if header retrieval timed out
        :raises: InsufficientStorage on 507 response from node
        :raises: FooterNotSupported if need_metadata_footer is set but
            backend node can't accept footers
        """
        mime_boundary = None

        if want_metadata_footer or need_metadata_footer:
            mime_boundary = "%.64x" % random.randint(0, 16 ** 64)
            headers = HeaderKeyDict(headers)
            # We're going to be adding some unknown amount of data to the
            # request, so we can't use an explicit content length, and thus
            # we must use chunked encoding.
            headers['Transfer-Encoding'] = 'chunked'
            headers['Expect'] = '100-continue'
            if 'Content-Length' in headers:
                headers['X-Backend-Obj-Content-Length'] = \
                    headers.pop('Content-Length')
            chunked = True

            headers['X-Backend-Obj-Metadata-Footer'] = 'yes'
            headers['X-Backend-Obj-Multipart-Mime-Boundary'] = mime_boundary

        start_time = time.time()
        with ConnectionTimeout(conn_timeout):
            conn = http_connect(node['ip'], node['port'], node['device'],
                                part, 'PUT', path, headers)
        connect_duration = time.time() - start_time

        with ResponseTimeout(node_timeout):
            resp = conn.getexpect()

        if resp.status == HTTP_INSUFFICIENT_STORAGE:
            raise InsufficientStorage

        continue_headers = HeaderKeyDict(resp.getheaders())
        can_send_metadata_footer = config_true_value(
            continue_headers.get('X-Obj-Metadata-Footer', 'no'))

        if need_metadata_footer and not can_send_metadata_footer:
            raise FooterNotSupported()

        conn.node = node
        conn.resp = None
        if is_success(resp.status):
            conn.resp = resp
        elif (headers.get('If-None-Match', None) is not None and
              resp.status == HTTP_PRECONDITION_FAILED):
            conn.resp = resp

        send_metadata_footer = ((want_metadata_footer or need_metadata_footer)
                                and can_send_metadata_footer)

        return cls(conn, node, resp, path, connect_duration, chunked,
                   mime_boundary if send_metadata_footer else None)


class ObjectController(Controller):
    """WSGI controller for object requests."""
    server_type = 'Object'

    def __init__(self, app, account_name, container_name, object_name,
                 **kwargs):
        Controller.__init__(self, app)
        self.account_name = unquote(account_name)
        self.container_name = unquote(container_name)
        self.object_name = unquote(object_name)

    def _listing_iter(self, lcontainer, lprefix, env):
        for page in self._listing_pages_iter(lcontainer, lprefix, env):
            for item in page:
                yield item

    def _listing_pages_iter(self, lcontainer, lprefix, env):
        lpartition = self.app.container_ring.get_part(
            self.account_name, lcontainer)
        marker = ''
        while True:
            lreq = Request.blank('i will be overridden by env', environ=env)
            # Don't quote PATH_INFO, by WSGI spec
            lreq.environ['PATH_INFO'] = \
                '/v1/%s/%s' % (self.account_name, lcontainer)
            lreq.environ['REQUEST_METHOD'] = 'GET'
            lreq.environ['QUERY_STRING'] = \
                'format=json&prefix=%s&marker=%s' % (quote(lprefix),
                                                     quote(marker))
            lresp = self.GETorHEAD_base(
                lreq, _('Container'), self.app.container_ring, lpartition,
                lreq.swift_entity_path)
            if 'swift.authorize' in env:
                lreq.acl = lresp.headers.get('x-container-read')
                aresp = env['swift.authorize'](lreq)
                if aresp:
                    raise ListingIterNotAuthorized(aresp)
            if lresp.status_int == HTTP_NOT_FOUND:
                raise ListingIterNotFound()
            elif not is_success(lresp.status_int):
                raise ListingIterError()
            if not lresp.body:
                break
            sublisting = json.loads(lresp.body)
            if not sublisting:
                break
            marker = sublisting[-1]['name'].encode('utf-8')
            yield sublisting

    def _remaining_items(self, listing_iter):
        """
        Returns an item-by-item iterator for a page-by-page iterator
        of item listings.

        Swallows listing-related errors; this iterator is only used
        after we've already started streaming a response to the
        client, and so if we start getting errors from the container
        servers now, it's too late to send an error to the client, so
        we just quit looking for segments.
        """
        try:
            for page in listing_iter:
                for item in page:
                    yield item
        except ListingIterNotFound:
            pass
        except ListingIterError:
            pass
        except ListingIterNotAuthorized:
            pass

    def iter_nodes_local_first(self, ring, partition):
        """
        Yields nodes for a ring partition.

        If the 'write_affinity' setting is non-empty, then this will yield N
        local nodes (as defined by the write_affinity setting) first, then the
        rest of the nodes as normal. It is a re-ordering of the nodes such
        that the local ones come first; no node is omitted. The effect is
        that the request will be serviced by local object servers first, but
        nonlocal ones will be employed if not enough local ones are available.

        :param ring: ring to get nodes from
        :param partition: ring partition to yield nodes for
        """

        is_local = self.app.write_affinity_is_local_fn
        if is_local is None:
            return self.app.iter_nodes(ring, partition)

        primary_nodes = ring.get_part_nodes(partition)
        num_locals = self.app.write_affinity_node_count(len(primary_nodes))

        all_nodes = itertools.chain(primary_nodes,
                                    ring.get_more_nodes(partition))
        first_n_local_nodes = list(itertools.islice(
            itertools.ifilter(is_local, all_nodes), num_locals))

        # refresh it; it moved when we computed first_n_local_nodes
        all_nodes = itertools.chain(primary_nodes,
                                    ring.get_more_nodes(partition))
        local_first_node_iter = itertools.chain(
            first_n_local_nodes,
            itertools.ifilter(lambda node: node not in first_n_local_nodes,
                              all_nodes))

        return self.app.iter_nodes(
            ring, partition, node_iter=local_first_node_iter)

    def GETorHEAD(self, req):
        """Handle HTTP GET or HEAD requests."""
        container_info = self.container_info(
            self.account_name, self.container_name, req)
        req.acl = container_info['read_acl']
        # pass the policy index to storage nodes via req header
        policy_index = req.headers.get('X-Backend-Storage-Policy-Index',
                                       container_info['storage_policy'])
        obj_ring = self.app.get_object_ring(policy_index)
        req.headers['X-Backend-Storage-Policy-Index'] = policy_index
        if 'swift.authorize' in req.environ:
            aresp = req.environ['swift.authorize'](req)
            if aresp:
                return aresp
        partition = obj_ring.get_part(
            self.account_name, self.container_name, self.object_name)
        resp = self.GETorHEAD_base(
            req, _('Object'), obj_ring, partition,
            req.swift_entity_path)

        if ';' in resp.headers.get('content-type', ''):
            resp.content_type = clean_content_type(
                resp.headers['content-type'])
        return resp

    @public
    @cors_validation
    @delay_denial
    def GET(self, req):
        """Handler for HTTP GET requests."""
        return self.GETorHEAD(req)

    @public
    @cors_validation
    @delay_denial
    def HEAD(self, req):
        """Handler for HTTP HEAD requests."""
        return self.GETorHEAD(req)

    @public
    @cors_validation
    @delay_denial
    def POST(self, req):
        """HTTP POST request handler."""
        if self.app.object_post_as_copy:
            req.method = 'PUT'
            req.path_info = '/v1/%s/%s/%s' % (
                self.account_name, self.container_name, self.object_name)
            req.headers['Content-Length'] = 0
            req.headers['X-Copy-From'] = quote('/%s/%s' % (self.container_name,
                                               self.object_name))
            req.headers['X-Fresh-Metadata'] = 'true'
            req.environ['swift_versioned_copy'] = True
            if req.environ.get('QUERY_STRING'):
                req.environ['QUERY_STRING'] += '&multipart-manifest=get'
            else:
                req.environ['QUERY_STRING'] = 'multipart-manifest=get'
            resp = self.PUT(req)
            # Older editions returned 202 Accepted on object POSTs, so we'll
            # convert any 201 Created responses to that for compatibility with
            # picky clients.
            if resp.status_int != HTTP_CREATED:
                return resp
            return HTTPAccepted(request=req)
        else:
            error_response = check_metadata(req, 'object')
            if error_response:
                return error_response
            container_info = self.container_info(
                self.account_name, self.container_name, req)
            container_partition = container_info['partition']
            containers = container_info['nodes']
            req.acl = container_info['write_acl']
            if 'swift.authorize' in req.environ:
                aresp = req.environ['swift.authorize'](req)
                if aresp:
                    return aresp
            if not containers:
                return HTTPNotFound(request=req)

            req, delete_at_container, delete_at_part, \
                delete_at_nodes = self._config_obj_expiration(req)

            # pass the policy index to storage nodes via req header
            policy_index = req.headers.get('X-Backend-Storage-Policy-Index',
                                           container_info['storage_policy'])
            obj_ring = self.app.get_object_ring(policy_index)
            req.headers['X-Backend-Storage-Policy-Index'] = policy_index
            partition, nodes = obj_ring.get_nodes(
                self.account_name, self.container_name, self.object_name)

            req.headers['X-Timestamp'] = Timestamp(time.time()).internal

            headers = self._backend_requests(
                req, len(nodes), container_partition, containers,
                delete_at_container, delete_at_part, delete_at_nodes)

            resp = self.make_requests(req, obj_ring, partition,
                                      'POST', req.swift_entity_path, headers)
            return resp

    def _backend_requests(self, req, n_outgoing,
                          container_partition, containers,
                          delete_at_container=None, delete_at_partition=None,
                          delete_at_nodes=None):
        headers = [self.generate_request_headers(req, additional=req.headers)
                   for _junk in range(n_outgoing)]

        for header in headers:
            header['Connection'] = 'close'

        for i, container in enumerate(containers):
            i = i % len(headers)

            headers[i]['X-Container-Partition'] = container_partition
            headers[i]['X-Container-Host'] = csv_append(
                headers[i].get('X-Container-Host'),
                '%(ip)s:%(port)s' % container)
            headers[i]['X-Container-Device'] = csv_append(
                headers[i].get('X-Container-Device'),
                container['device'])

        for i, node in enumerate(delete_at_nodes or []):
            i = i % len(headers)

            headers[i]['X-Delete-At-Container'] = delete_at_container
            headers[i]['X-Delete-At-Partition'] = delete_at_partition
            headers[i]['X-Delete-At-Host'] = csv_append(
                headers[i].get('X-Delete-At-Host'),
                '%(ip)s:%(port)s' % node)
            headers[i]['X-Delete-At-Device'] = csv_append(
                headers[i].get('X-Delete-At-Device'),
                node['device'])

        return headers

    def _send_file(self, conn, path):
        """Method for a file PUT coro"""
        while True:
            chunk = conn.queue.get()
            if not conn.failed:
                try:
                    with ChunkWriteTimeout(self.app.node_timeout):
                        conn.send(chunk)
                except (Exception, ChunkWriteTimeout):
                    conn.failed = True
                    self.app.exception_occurred(
                        conn.node, _('Object'),
                        _('Trying to write to %s') % path)
            conn.queue.task_done()

    def _connect_put_node(self, node_iter, part, path, headers,
                          logger_thread_locals, chunked,
                          want_metadata_footer=False):
        """
        Connects to the first working node that it finds in node_iter and sends
        over the request headers. Returns a Putter to handle the rest of the
        streaming, or None if no working nodes were found.
        """
        self.app.logger.thread_locals = logger_thread_locals
        for node in node_iter:
            try:
                putter = Putter.connect(
                    node, part, path, headers,
                    conn_timeout=self.app.conn_timeout,
                    node_timeout=self.app.node_timeout,
                    chunked=chunked, want_metadata_footer=want_metadata_footer)
                self.app.set_node_timing(node, putter.connect_duration)
                return putter
            except InsufficientStorage:
                self.app.error_limit(node, _('ERROR Insufficient Storage'))
            except (Exception, Timeout):
                self.app.exception_occurred(
                    node, _('Object'),
                    _('Expect: 100-continue on %s') % path)

    def _quorum_size(self, n, req):
        """
        Number of successful backend requests needed for the proxy to consider
        the client request successful.
        """
        policy_index = req.headers.get('X-Backend-Storage-Policy-Index')
        return POLICIES.get_by_index(policy_index).quorum_size(n)

    def _get_put_responses(self, req, putters, nodes):
        statuses = []
        reasons = []
        bodies = []
        etags = dict()

        def get_put_response(putter):
            try:
                resp = putter.await_final_response(self.app.node_timeout)
                return (putter, resp)
            except (Exception, Timeout):
                self.app.exception_occurred(
                    putter.node, _('Object'),
                    _('Trying to get final status of PUT to %s') % req.path)
            return (None, None)

        pile = GreenAsyncPile(len(putters))
        for putter in putters:
            pile.spawn(get_put_response, putter)

        def _handle_response(putter, response):
            statuses.append(response.status)
            reasons.append(response.reason)
            bodies.append(response.read())
            if response.status >= HTTP_INTERNAL_SERVER_ERROR:
                self.app.error_occurred(
                    putter.node,
                    _('ERROR %(status)d %(body)s From Object Server '
                      're: %(path)s') %
                    {'status': response.status,
                     'body': bodies[-1][:1024], 'path': req.path})
            elif is_success(response.status):
                etags[putter] = response.getheader('etag').strip('"')

        for (putter, response) in pile:
            if response:
                _handle_response(putter, response)
                if self.have_quorum(statuses, len(nodes), req):
                    break

        # give any pending requests *some* chance to finish
        finished_quickly = pile.waitall(self.app.post_quorum_timeout)
        for (putter, response) in finished_quickly:
            if response:
                _handle_response(putter, response)

        while len(statuses) < len(nodes):
            statuses.append(HTTP_SERVICE_UNAVAILABLE)
            reasons.append('')
            bodies.append('')
        return statuses, reasons, bodies, etags

    def _config_obj_expiration(self, req):
        delete_at_container = None
        delete_at_part = None
        delete_at_nodes = None

        req = constraints.check_delete_headers(req)

        if 'x-delete-at' in req.headers:
            x_delete_at = int(normalize_delete_at_timestamp(
                int(req.headers['x-delete-at'])))

            req.environ.setdefault('swift.log_info', []).append(
                'x-delete-at:%s' % x_delete_at)

            delete_at_container = get_expirer_container(
                x_delete_at, self.app.expiring_objects_container_divisor,
                self.account_name, self.container_name, self.object_name)

            delete_at_part, delete_at_nodes = \
                self.app.container_ring.get_nodes(
                    self.app.expiring_objects_account, delete_at_container)

        return req, delete_at_container, delete_at_part, delete_at_nodes

    @public
    @cors_validation
    @delay_denial
    def PUT(self, req):
        """HTTP PUT request handler."""
        if req.if_none_match is not None and '*' not in req.if_none_match:
            # Sending an etag with if-none-match isn't currently supported
            return HTTPBadRequest(request=req, content_type='text/plain',
                                  body='If-None-Match only supports *')
        container_info = self.container_info(
            self.account_name, self.container_name, req)
        policy_index = req.headers.get('X-Backend-Storage-Policy-Index',
                                       container_info['storage_policy'])
        policy = POLICIES.get_by_index(policy_index)
        ec_policy = True if policy.policy_type == 'erasure_coding' else False
        obj_ring = self.app.get_object_ring(policy_index)

        # pass the policy index to storage nodes via req header
        req.headers['X-Backend-Storage-Policy-Index'] = policy_index
        container_partition = container_info['partition']
        containers = container_info['nodes']
        req.acl = container_info['write_acl']
        req.environ['swift_sync_key'] = container_info['sync_key']
        object_versions = container_info['versions']
        if 'swift.authorize' in req.environ:
            aresp = req.environ['swift.authorize'](req)
            if aresp:
                return aresp

        if not containers:
            return HTTPNotFound(request=req)

        # Sometimes the 'content-type' header exists, but is set to None.
        content_type_manually_set = True
        detect_content_type = \
            config_true_value(req.headers.get('x-detect-content-type'))
        if detect_content_type or not req.headers.get('content-type'):
            guessed_type, _junk = mimetypes.guess_type(req.path_info)
            req.headers['Content-Type'] = guessed_type or \
                'application/octet-stream'
            if detect_content_type:
                req.headers.pop('x-detect-content-type')
            else:
                content_type_manually_set = False

        error_response = check_object_creation(req, self.object_name) or \
            check_content_type(req)
        if error_response:
            return error_response

        partition, nodes = obj_ring.get_nodes(
            self.account_name, self.container_name, self.object_name)

        # do a HEAD request for container sync and checking object versions
        if 'x-timestamp' in req.headers or \
                (object_versions and not
                 req.environ.get('swift_versioned_copy')):
            # make sure proxy-server uses the right policy index
            _headers = {'X-Backend-Storage-Policy-Index': policy_index,
                        'X-Newest': 'True'}
            hreq = Request.blank(req.path_info, headers=_headers,
                                 environ={'REQUEST_METHOD': 'HEAD'})
            hresp = self.GETorHEAD_base(
                hreq, _('Object'), obj_ring, partition,
                hreq.swift_entity_path)

        # Used by container sync feature
        if 'x-timestamp' in req.headers:
            try:
                req_timestamp = Timestamp(req.headers['X-Timestamp'])
                if hresp.environ and 'swift_x_timestamp' in hresp.environ and \
                        hresp.environ['swift_x_timestamp'] >= req_timestamp:
                    return HTTPAccepted(request=req)
            except ValueError:
                return HTTPBadRequest(
                    request=req, content_type='text/plain',
                    body='X-Timestamp should be a UNIX timestamp float value; '
                         'was %r' % req.headers['x-timestamp'])
            req.headers['X-Timestamp'] = req_timestamp.internal
        else:
            req.headers['X-Timestamp'] = Timestamp(time.time()).internal

        if object_versions and not req.environ.get('swift_versioned_copy'):
            if hresp.status_int != HTTP_NOT_FOUND:
                # This is a version manifest and needs to be handled
                # differently. First copy the existing data to a new object,
                # then write the data from this request to the version manifest
                # object.
                lcontainer = object_versions.split('/')[0]
                prefix_len = '%03x' % len(self.object_name)
                lprefix = prefix_len + self.object_name + '/'
                ts_source = hresp.environ.get('swift_x_timestamp')
                if ts_source is None:
                    ts_source = time.mktime(time.strptime(
                                            hresp.headers['last-modified'],
                                            '%a, %d %b %Y %H:%M:%S GMT'))
                new_ts = Timestamp(ts_source).internal
                vers_obj_name = lprefix + new_ts
                copy_headers = {
                    'Destination': '%s/%s' % (lcontainer, vers_obj_name)}
                copy_environ = {'REQUEST_METHOD': 'COPY',
                                'swift_versioned_copy': True
                                }
                copy_req = Request.blank(req.path_info, headers=copy_headers,
                                         environ=copy_environ)
                copy_resp = self.COPY(copy_req)
                if is_client_error(copy_resp.status_int):
                    # missing container or bad permissions
                    return HTTPPreconditionFailed(request=req)
                elif not is_success(copy_resp.status_int):
                    # could not copy the data, bail
                    return HTTPServiceUnavailable(request=req)

        reader = req.environ['wsgi.input'].read
        data_source = iter(lambda: reader(self.app.client_chunk_size), '')
        source_header = req.headers.get('X-Copy-From')
        source_resp = None
        if source_header:
            if req.environ.get('swift.orig_req_method', req.method) != 'POST':
                req.environ.setdefault('swift.log_info', []).append(
                    'x-copy-from:%s' % source_header)
            ver, acct, _rest = req.split_path(2, 3, True)
            src_account_name = req.headers.get('X-Copy-From-Account', None)
            if src_account_name:
                src_account_name = check_account_format(req, src_account_name)
            else:
                src_account_name = acct
            src_container_name, src_obj_name = check_copy_from_header(req)
            source_header = '/%s/%s/%s/%s' % (ver, src_account_name,
                            src_container_name, src_obj_name)
            source_req = req.copy_get()

            # make sure the source request uses it's container_info
            source_req.headers.pop('X-Backend-Storage-Policy-Index', None)
            source_req.path_info = source_header
            source_req.headers['X-Newest'] = 'true'
            orig_obj_name = self.object_name
            orig_container_name = self.container_name
            orig_account_name = self.account_name
            self.object_name = src_obj_name
            self.container_name = src_container_name
            self.account_name = src_account_name
            sink_req = Request.blank(req.path_info,
                                     environ=req.environ, headers=req.headers)
            source_resp = self.GET(source_req)
            sink_req.headers['etag'] = source_resp.etag

            # This gives middlewares a way to change the source; for example,
            # this lets you COPY a SLO manifest and have the new object be the
            # concatenation of the segments (like what a GET request gives
            # the client), not a copy of the manifest file.
            hook = req.environ.get(
                'swift.copy_hook',
                (lambda source_req, source_resp, sink_req: source_resp))
            source_resp = hook(source_req, source_resp, sink_req)

            if source_resp.status_int >= HTTP_MULTIPLE_CHOICES:
                return source_resp
            self.object_name = orig_obj_name
            self.container_name = orig_container_name
            self.account_name = orig_account_name
            data_source = iter(source_resp.app_iter)
            sink_req.content_length = source_resp.content_length
            if sink_req.content_length is None:
                # This indicates a transfer-encoding: chunked source object,
                # which currently only happens because there are more than
                # CONTAINER_LISTING_LIMIT segments in a segmented object. In
                # this case, we're going to refuse to do the server-side copy.
                return HTTPRequestEntityTooLarge(request=req)
            if sink_req.content_length > constraints.MAX_FILE_SIZE:
                return HTTPRequestEntityTooLarge(request=req)
            sink_req.etag = source_resp.etag

            # we no longer need the X-Copy-From header
            del sink_req.headers['X-Copy-From']
            if 'X-Copy-From-Account' in sink_req.headers:
                del sink_req.headers['X-Copy-From-Account']
            if not content_type_manually_set:
                sink_req.headers['Content-Type'] = \
                    source_resp.headers['Content-Type']
            if config_true_value(
                    sink_req.headers.get('x-fresh-metadata', 'false')):
                # post-as-copy: ignore new sysmeta, copy existing sysmeta
                condition = lambda k: is_sys_meta('object', k)
                remove_items(sink_req.headers, condition)
                copy_header_subset(source_resp, sink_req, condition)
            else:
                # copy/update existing sysmeta and user meta
                copy_headers_into(source_resp, sink_req)
                copy_headers_into(req, sink_req)

            # copy over x-static-large-object for POSTs and manifest copies
            if 'X-Static-Large-Object' in source_resp.headers and \
                    req.params.get('multipart-manifest') == 'get':
                sink_req.headers['X-Static-Large-Object'] = \
                    source_resp.headers['X-Static-Large-Object']

            req = sink_req

        req, delete_at_container, delete_at_part, \
            delete_at_nodes = self._config_obj_expiration(req)

        node_iter = GreenthreadSafeIterator(
            self.iter_nodes_local_first(obj_ring, partition))
        pile = GreenPile(len(nodes))
        te = req.headers.get('transfer-encoding', '')
        chunked = ('chunked' in te)

        outgoing_headers = self._backend_requests(
            req, len(nodes), container_partition, containers,
            delete_at_container, delete_at_part, delete_at_nodes)

        for nheaders in outgoing_headers:
            # RFC2616:8.2.3 disallows 100-continue without a body
            if (req.content_length > 0) or chunked:
                nheaders['Expect'] = '100-continue'
            # We indicate that we always need a metadata footer
            # for erasure coded objects, in which case the proxy->object
            # encoding is always chunked, thus we shouldn't retain the
            # Content-Length header.  We also remove the Etag header
            # as the etag of the data being written to the object server
            # is not the same as the original object etag as sent by client
            if ec_policy:
                nheaders.pop('Content-Length', None)
                nheaders.pop('Etag', None)
                req.content_length = None
            pile.spawn(self._connect_put_node, node_iter, partition,
                       req.swift_entity_path, nheaders,
                       self.app.logger.thread_locals, chunked,
                       want_metadata_footer=ec_policy)

        putters = [p for p in pile if p]
        min_puts = self._quorum_size(len(nodes), req)

        if req.if_none_match is not None and '*' in req.if_none_match:
            statuses = [p.current_status() for p in putters]
            if HTTP_PRECONDITION_FAILED in statuses:
                # If we find any copy of the file, it shouldn't be uploaded
                self.app.logger.debug(
                    _('Object PUT returning 412, %(statuses)r'),
                    {'statuses': statuses})
                return HTTPPreconditionFailed(request=req)

        if len(putters) < min_puts:
            self.app.logger.error(
                _('Object PUT returning 503, %(conns)s/%(nodes)s '
                  'required connections'),
                {'conns': len(putters), 'nodes': min_puts})
            return HTTPServiceUnavailable(request=req)

        # Running etag for segments as they are streamed in (gives us the
        # object etag in the end)
        object_etag = md5()

        # Create a connection:etag association for object stream being sent
        # down each connection
        putter_tx_etags = []
        for i in range(len(nodes)):
            putter_tx_etags.extend([md5()])
        ondisk_object_etags = dict(zip(putters, putter_tx_etags))
        bytes_transferred = object_bytes_transferred = 0
        try:
            with ContextPool(len(putters)) as pool:
                for putter in putters:
                    putter.spawn_sender_greenthread(
                        pool, self.app.put_queue_depth, self.app.node_timeout,
                        self.app.exception_occurred)

                def _buffer_chunks(source, size, leftover):
                    if size == 0:
                        return next(source), None
                    buf = []
                    bytes_sofar = 0
                    segment = leftover = b""
                    while bytes_sofar < size:
                        bytes = next(source)
                        buf.append(bytes)
                        bytes_sofar += len(bytes)
                        # Buffer exactly 'size' bytes
                        if bytes_sofar >= size:
                            segment = b"".join(buf)
                            leftover = segment[size:]
                            segment = segment[:size]
                    return segment, leftover

                next_chunk = b""
                object_segment_size = policy.ec_objsegsz if ec_policy else 0
                while True:
                    with ChunkReadTimeout(self.app.client_timeout):
                        try:
                            chunk, next_chunk = _buffer_chunks(
                                data_source, object_segment_size, next_chunk)
                        except StopIteration:
                            for putter in putters:
                                # Write original object length and etag to the
                                # metadata footer by default
                                custom_putter_meta = {
                                    'X-Object-Sysmeta-Content-Length':
                                    object_bytes_transferred,
                                    'X-Object-Sysmeta-Etag':
                                    object_etag.hexdigest(),
                                }
                                # Add policy specific metadata
                                custom_putter_meta.update(
                                    policy.custom_meta(putters.index(putter)))
                                putter.end_of_object_data(custom_putter_meta)
                            break
                    # If policy is erasure_coding, encode object segment into
                    # ec_ndata and ec_nparity fragments, before streaming
                    # those to the object servers.
                    if ec_policy:
                        # Running md5sum for object data
                        object_etag.update(chunk)
                        # Encode and stream
                        try:
                            ec_fragments = policy.pyeclib_driver.encode(chunk)
                        except ECDriverError:
                            self.app.logger.error(_(
                                'Object PUT exception during'
                                ' ec_driver.encode()'))
                            return HTTPServerError(request=req)

                        ec_fragment = iter(ec_fragments)
                        bytes_transferred += len(ec_fragments[0])
                        object_bytes_transferred += len(chunk)
                    else:
                        bytes_transferred += len(chunk)

                    if bytes_transferred > constraints.MAX_FILE_SIZE:
                        return HTTPRequestEntityTooLarge(request=req)
                    for putter in list(putters):
                        if not putter.failed:
                            if ec_policy:
                                chunk = next(ec_fragment)
                                ondisk_object_etags[putter].update(chunk)
                            putter.send_chunk(chunk)
                        else:
                            putters.remove(putter)
                    if len(putters) < min_puts:
                        self.app.logger.error(_(
                            'Object PUT exceptions during'
                            ' send, %(conns)s/%(nodes)s required connections'),
                            {'conns': len(putters), 'nodes': min_puts})
                        return HTTPServiceUnavailable(request=req)
                for putter in putters:
                    putter.wait()
            putters = [p for p in putters if not p.failed]
        except ChunkReadTimeout as err:
            self.app.logger.warn(
                _('ERROR Client read timeout (%ss)'), err.seconds)
            self.app.logger.increment('client_timeouts')
            return HTTPRequestTimeout(request=req)
        except (Exception, Timeout):
            self.app.logger.exception(
                _('ERROR Exception causing client disconnect'))
            return HTTPClientDisconnect(request=req)
        if req.content_length and bytes_transferred < req.content_length:
            req.client_disconnect = True
            self.app.logger.warn(
                _('Client disconnected without sending enough data'))
            self.app.logger.increment('client_disconnects')
            return HTTPClientDisconnect(request=req)

        statuses, reasons, bodies, etags = self._get_put_responses(
            req, putters, nodes)

        if ec_policy:
            # Validate etags received in response against EC fragment etags
            mismatched_etags = 0
            for putter in putters:
                putter_tx_etag = ondisk_object_etags[putter].hexdigest()
                if putter in etags and \
                        putter_tx_etag != etags[putter]:
                    mismatched_etags += 1
            if mismatched_etags > 0:
                self.app.logger.error(
                    _('Object servers returned %s mismatched etags'),
                    len(etags))
            # Respond to the client with object etag
            etag = object_etag.hexdigest()
        else:
            etags = set(etags.values())
            if len(etags) > 1:
                self.app.logger.error(
                    _('Object servers returned %s mismatched etags'),
                    len(etags))
                return HTTPServerError(request=req)
            etag = etags.pop() if len(etags) else None
        resp = self.best_response(req, statuses, reasons, bodies,
                                  _('Object PUT'), etag=etag)
        if source_header:
            acct, path = source_header.split('/', 3)[2:4]
            resp.headers['X-Copied-From-Account'] = quote(acct)
            resp.headers['X-Copied-From'] = quote(path)
            if 'last-modified' in source_resp.headers:
                resp.headers['X-Copied-From-Last-Modified'] = \
                    source_resp.headers['last-modified']
            copy_headers_into(req, resp)
        resp.last_modified = math.ceil(
            float(Timestamp(req.headers['X-Timestamp'])))
        return resp

    @public
    @cors_validation
    @delay_denial
    def DELETE(self, req):
        """HTTP DELETE request handler."""
        container_info = self.container_info(
            self.account_name, self.container_name, req)
        # pass the policy index to storage nodes via req header
        policy_index = req.headers.get('X-Backend-Storage-Policy-Index',
                                       container_info['storage_policy'])
        obj_ring = self.app.get_object_ring(policy_index)
        # pass the policy index to storage nodes via req header
        req.headers['X-Backend-Storage-Policy-Index'] = policy_index
        container_partition = container_info['partition']
        containers = container_info['nodes']
        req.acl = container_info['write_acl']
        req.environ['swift_sync_key'] = container_info['sync_key']
        object_versions = container_info['versions']
        if object_versions:
            # this is a version manifest and needs to be handled differently
            object_versions = unquote(object_versions)
            lcontainer = object_versions.split('/')[0]
            prefix_len = '%03x' % len(self.object_name)
            lprefix = prefix_len + self.object_name + '/'
            item_list = []
            try:
                for _item in self._listing_iter(lcontainer, lprefix,
                                                req.environ):
                    item_list.append(_item)
            except ListingIterNotFound:
                # no worries, last_item is None
                pass
            except ListingIterNotAuthorized as err:
                return err.aresp
            except ListingIterError:
                return HTTPServerError(request=req)

            while len(item_list) > 0:
                previous_version = item_list.pop()
                # there are older versions so copy the previous version to the
                # current object and delete the previous version
                orig_container = self.container_name
                orig_obj = self.object_name
                self.container_name = lcontainer
                self.object_name = previous_version['name'].encode('utf-8')

                copy_path = '/v1/' + self.account_name + '/' + \
                            self.container_name + '/' + self.object_name

                copy_headers = {'X-Newest': 'True',
                                'Destination': orig_container + '/' + orig_obj
                                }
                copy_environ = {'REQUEST_METHOD': 'COPY',
                                'swift_versioned_copy': True
                                }
                creq = Request.blank(copy_path, headers=copy_headers,
                                     environ=copy_environ)
                copy_resp = self.COPY(creq)
                if copy_resp.status_int == HTTP_NOT_FOUND:
                    # the version isn't there so we'll try with previous
                    self.container_name = orig_container
                    self.object_name = orig_obj
                    continue
                if is_client_error(copy_resp.status_int):
                    # some user error, maybe permissions
                    return HTTPPreconditionFailed(request=req)
                elif not is_success(copy_resp.status_int):
                    # could not copy the data, bail
                    return HTTPServiceUnavailable(request=req)
                # reset these because the COPY changed them
                self.container_name = lcontainer
                self.object_name = previous_version['name'].encode('utf-8')
                new_del_req = Request.blank(copy_path, environ=req.environ)
                container_info = self.container_info(
                    self.account_name, self.container_name, req)
                policy_idx = container_info['storage_policy']
                obj_ring = self.app.get_object_ring(policy_idx)
                # pass the policy index to storage nodes via req header
                new_del_req.headers['X-Backend-Storage-Policy-Index'] = \
                    policy_idx
                container_partition = container_info['partition']
                containers = container_info['nodes']
                new_del_req.acl = container_info['write_acl']
                new_del_req.path_info = copy_path
                req = new_del_req
                # remove 'X-If-Delete-At', since it is not for the older copy
                if 'X-If-Delete-At' in req.headers:
                    del req.headers['X-If-Delete-At']
                break
        if 'swift.authorize' in req.environ:
            aresp = req.environ['swift.authorize'](req)
            if aresp:
                return aresp
        if not containers:
            return HTTPNotFound(request=req)
        partition, nodes = obj_ring.get_nodes(
            self.account_name, self.container_name, self.object_name)
        # Used by container sync feature
        if 'x-timestamp' in req.headers:
            try:
                req_timestamp = Timestamp(req.headers['X-Timestamp'])
            except ValueError:
                return HTTPBadRequest(
                    request=req, content_type='text/plain',
                    body='X-Timestamp should be a UNIX timestamp float value; '
                         'was %r' % req.headers['x-timestamp'])
            req.headers['X-Timestamp'] = req_timestamp.internal
        else:
            req.headers['X-Timestamp'] = Timestamp(time.time()).internal

        headers = self._backend_requests(
            req, len(nodes), container_partition, containers)
        # When deleting objects treat a 404 status as 204.
        status_overrides = {404: 204}
        resp = self.make_requests(req, obj_ring,
                                  partition, 'DELETE', req.swift_entity_path,
                                  headers, overrides=status_overrides)
        return resp

    @public
    @cors_validation
    @delay_denial
    def COPY(self, req):
        """HTTP COPY request handler."""
        if not req.headers.get('Destination'):
            return HTTPPreconditionFailed(request=req,
                                          body='Destination header required')
        dest_account = self.account_name
        if 'Destination-Account' in req.headers:
            dest_account = req.headers.get('Destination-Account')
            dest_account = check_account_format(req, dest_account)
            req.headers['X-Copy-From-Account'] = self.account_name
            self.account_name = dest_account
            del req.headers['Destination-Account']
        dest_container, dest_object = check_destination_header(req)
        source = '/%s/%s' % (self.container_name, self.object_name)
        self.container_name = dest_container
        self.object_name = dest_object
        # re-write the existing request as a PUT instead of creating a new one
        # since this one is already attached to the posthooklogger
        req.method = 'PUT'
        req.path_info = '/v1/%s/%s/%s' % \
                        (dest_account, dest_container, dest_object)
        req.headers['Content-Length'] = 0
        req.headers['X-Copy-From'] = quote(source)
        del req.headers['Destination']
        return self.PUT(req)
