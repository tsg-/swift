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
import operator
import time
import math
import random
from hashlib import md5
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
    InsufficientStorage, FooterNotSupported, MultiphasePUTNotSupported, \
    PutterConnectError
from swift.common.http import (
    is_success, is_client_error, is_server_error, HTTP_CONTINUE,
    HTTP_CREATED, HTTP_MULTIPLE_CHOICES, HTTP_NOT_FOUND,
    HTTP_INTERNAL_SERVER_ERROR, HTTP_SERVICE_UNAVAILABLE,
    HTTP_INSUFFICIENT_STORAGE, HTTP_PRECONDITION_FAILED, HTTP_CONFLICT)
from swift.common.storage_policy import POLICIES
from swift.proxy.controllers.base import Controller, delay_denial, \
    cors_validation
from swift.common.swob import HTTPAccepted, HTTPBadRequest, HTTPNotFound, \
    HTTPPreconditionFailed, HTTPRequestEntityTooLarge, HTTPRequestTimeout, \
    HTTPServerError, HTTPServiceUnavailable, Request, HeaderKeyDict, \
    HTTPClientDisconnect, HTTPUnprocessableEntity
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
DATA_SENT = 3
DATA_ACKED = 4
COMMIT_SENT = 5


class Putter(object):
    """
    An HTTP PUT request that supports streaming.

    Probably deserves more docs than this, but meh.
    """
    def __init__(self, conn, node, resp, path, connect_duration, chunked,
                 mime_boundary, need_multiphase_put):
        # Note: you probably want to call Putter.connect() instead of
        # instantiating one of these directly.
        self.conn = conn
        self.node = node
        self.resp = resp
        self.path = path
        self.connect_duration = connect_duration
        self.chunked = chunked
        self.node_index = node['index']
        self.mime_boundary = mime_boundary
        self.need_multiphase_put = need_multiphase_put

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

    def await_response(self, timeout, informational=False):
        """
        Get 100-continue response indicating the end of 1st phase of a 2-phase
        commit or the final response, i.e. the one with status >= 200.

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
                if informational:
                    conn.resp = conn.getexpect()
                else:
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

    def _start_mime_doc_object_body(self):
        self.queue.put("--%s\r\nX-Document: object body\r\n\r\n" %
                       (self.mime_boundary,))

    def send_chunk(self, chunk):
        if not chunk:
            # If we're not using chunked transfer-encoding, sending a 0-byte
            # chunk is just wasteful. If we *are* using chunked
            # transfer-encoding, sending a 0-byte chunk terminates the
            # request body. Neither one of these is good.
            return
        elif self.state == DATA_SENT:
            raise ValueError("called send_chunk after end_of_object_data")

        if self.state == NO_DATA_SENT and self.mime_boundary:
            # We're sending the object plus other stuff in the same request
            # body, all wrapped up in multipart MIME, so we'd better start
            # off the MIME document before sending any object data.
            self._start_mime_doc_object_body()
            self.state = SENDING_DATA

        self.queue.put(chunk)

    def end_of_object_data(self, need_commit_confirmation,
                           footer_metadata=None):
        """
        Call when there is no more data to send.

        If this Putter was created without need_metadata_footer=True, then
        any footer metadata passed in will be silently ignored.

        :param footer_metadata: dictionary of metadata items
        """
        if self.state == DATA_SENT:
            raise ValueError("called end_of_object_data twice")
        elif self.state == NO_DATA_SENT and self.mime_boundary:
            self._start_mime_doc_object_body()

        if footer_metadata is None:
            footer_metadata = {}

        if self.mime_boundary:
            footer_body = json.dumps(footer_metadata)
            footer_md5 = md5(footer_body).hexdigest()

            if need_commit_confirmation:
                tail_boundary = ("--%s" % (self.mime_boundary,))
            else:
                tail_boundary = ("--%s--" % (self.mime_boundary,))

            message_parts = [
                ("\r\n--%s\r\n" % self.mime_boundary),
                "X-Document: object metadata\r\n",
                "Content-MD5: %s\r\n" % footer_md5,
                "\r\n",
                footer_body, "\r\n",
                tail_boundary,
            ]
            self.queue.put("".join(message_parts))

        self.queue.put('')
        self.state = DATA_SENT

    def send_commit_confirmation(self):
        """
        Call when there are > quorum 2XX responses received.  Send commit
        confirmations to all object nodes to finalize the PUT.
        """
        if self.state == COMMIT_SENT:
            raise ValueError("called send_commit_confirmation twice")

        self.state = DATA_ACKED

        if self.mime_boundary:
            body = "commit_confirmation"
            tail_boundary = ("--%s--" % (self.mime_boundary,))
            message_parts = [
                "X-Document: PUT commit\r\n",
                "\r\n",
                body, "\r\n",
                tail_boundary,
            ]
            self.queue.put("".join(message_parts))

        self.queue.put('')
        self.state = COMMIT_SENT

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
                chunked=False, need_metadata_footer=False,
                need_multiphase_put=False):
        """
        Connect to a backend node and send the headers.

        :returns: Putter instance

        :raises: ConnectionTimeout if initial connection timed out
        :raises: ResponseTimeout if header retrieval timed out
        :raises: InsufficientStorage on 507 response from node
        :raises: FooterNotSupported if need_metadata_footer is set but
        :raises: MultiphasePUTNotSupported if need_multiphase_support is
                 set but backend node can't handle multiphase PUT
        """
        mime_boundary = None

        if need_metadata_footer:
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

        if need_multiphase_put:
            headers['X-Backend-Obj-Multiphase-Commit'] = 'yes'

        start_time = time.time()
        with ConnectionTimeout(conn_timeout):
            conn = http_connect(node['ip'], node['port'], node['device'],
                                part, 'PUT', path, headers)
        connect_duration = time.time() - start_time

        with ResponseTimeout(node_timeout):
            resp = conn.getexpect()

        if resp.status == HTTP_INSUFFICIENT_STORAGE:
            raise InsufficientStorage

        if is_server_error(resp.status):
            raise PutterConnectError(resp.status)

        continue_headers = HeaderKeyDict(resp.getheaders())
        can_send_metadata_footer = config_true_value(
            continue_headers.get('X-Obj-Metadata-Footer', 'no'))
        can_handle_multiphase_put = config_true_value(
            continue_headers.get('X-Obj-Multiphase-Commit', 'no'))
        print continue_headers

        if need_metadata_footer and not can_send_metadata_footer:
            raise FooterNotSupported()

        if need_multiphase_put and not can_handle_multiphase_put:
            raise MultiphasePUTNotSupported()

        conn.node = node
        conn.resp = None
        if is_success(resp.status) or resp.status == HTTP_CONFLICT:
            conn.resp = resp
        elif (headers.get('If-None-Match', None) is not None and
              resp.status == HTTP_PRECONDITION_FAILED):
            conn.resp = resp

        return cls(conn, node, resp, path, connect_duration, chunked,
                   mime_boundary if need_metadata_footer else None,
                   need_multiphase_put)


class BaseObjectController(Controller):
    """Base WSGI controller for object requests."""
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
            container_node_iter = self.app.iter_nodes(self.app.container_ring,
                                                      lpartition)
            lresp = self.GETorHEAD_base(
                lreq, _('Container'), container_node_iter, lpartition,
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

        all_nodes = itertools.chain(
            primary_nodes, ring.get_more_nodes(partition))
        first_n_local_nodes = list(itertools.islice(
            itertools.ifilter(is_local, all_nodes), num_locals))

        # refresh it; it moved when we computed first_n_local_nodes
        all_nodes = itertools.chain(
            primary_nodes, ring.get_more_nodes(partition))
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
        policy = POLICIES.get_by_index(policy_index)
        obj_ring = self.app.get_object_ring(policy_index)
        req.headers['X-Backend-Storage-Policy-Index'] = policy_index
        if 'swift.authorize' in req.environ:
            aresp = req.environ['swift.authorize'](req)
            if aresp:
                return aresp
        partition = obj_ring.get_part(
            self.account_name, self.container_name, self.object_name)
        node_iter = self.app.iter_nodes(obj_ring, partition)

        resp = self._get_or_head_response(req, node_iter, partition, policy)

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
                          need_metadata_footer=False,
                          need_multiphase_put=False):
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
                    chunked=chunked, need_metadata_footer=need_metadata_footer,
                    need_multiphase_put=need_multiphase_put)
                self.app.set_node_timing(node, putter.connect_duration)
                return putter
            except InsufficientStorage:
                self.app.error_limit(node, _('ERROR Insufficient Storage'))
            except PutterConnectError as e:
                self.app.error_occurred(
                    node, _('ERROR %(status)d Expect: 100-continue '
                            'From Object Server') % {
                                'status': e.status})
            except (Exception, Timeout):
                self.app.exception_occurred(
                    node, _('Object'),
                    _('Expect: 100-continue on %s') % path)

    def _have_adequate_successes(self, statuses, min_responses):
        """
        Given a list of statuses from several requests, determine if a
        satisfactory number of nodes have responded with 2xx statuses to
        deem the transaction for a succssful response to the client.

        :param statuses: list of statuses returned so far
        :param min_responses: minimal pass criterion for number of successes
        :returns: True or False, depending on current number of successes
        """
        if sum(1 for s in statuses if is_success(s)) >= min_responses:
            return True
        return False

    def _get_put_responses(self, req, putters, nodes, final_phase,
                           min_responses, need_quorum=True):
        """
        Collect object responses to a PUT request and determine if
        satisfactory number of nodes have returned success.  Return
        statuses, quorum result if indicated by 'need_quorum' and
        etags if this is a final phase or a multiphase PUT transaction.
        """
        statuses = []
        reasons = []
        bodies = []
        etags = set()

        def get_put_response(putter):
            try:
                resp = putter.await_response(
                    self.app.node_timeout, not final_phase)
                return (putter, resp)
            except (Exception, Timeout):
                self.app.exception_occurred(
                    putter.node, _('Object'),
                    _('Trying to get status of PUT to %s') % req.path)
            return (None, None)

        pile = GreenAsyncPile(len(putters))
        for putter in putters:
            if putter.need_multiphase_put:
                # if this is a putter that uses more than one phase for
                # PUT, make sure conn.resp property is reset before
                # collecting the next-phase response
                putter.conn.resp = None
            pile.spawn(get_put_response, putter)

        def _handle_response(putter, response):
            statuses.append(response.status)
            reasons.append(response.reason)
            print "FINAL PHASE %r" % final_phase
            if final_phase:
                bodies.append(response.read())
            if response.status == HTTP_INSUFFICIENT_STORAGE:
                self.app.error_limit(putter.node,
                                     _('ERROR Insufficient Storage'))
            elif response.status >= HTTP_INTERNAL_SERVER_ERROR:
                self.app.error_occurred(
                    putter.node,
                    _('ERROR %(status)d %(body)s From Object Server '
                      're: %(path)s') %
                    {'status': response.status,
                     'body': bodies[-1][:1024], 'path': req.path})
            elif is_success(response.status):
                etags.add(response.getheader('etag').strip('"'))

        quorum = False
        for (putter, response) in pile:
            if response:
                _handle_response(putter, response)
                if need_quorum and final_phase:
                    # do not declare quorum for 100-continue acks just yet.
                    # Wait to collect as many as possible.  Other statuses:
                    # go ahead and declare quorum as soon as we can
                    if self.have_quorum(statuses, len(nodes), req):
                        quorum = True
                        break
                else:
                    # if quorum is not required (final phase of an erasure
                    # coded PUT, for example), respond to the client after
                    # receiving 'min_responses'-lower bound supplied by caller
                    if self._have_adequate_successes(statuses, min_responses):
                        break

        # give any pending requests *some* chance to finish
        finished_quickly = pile.waitall(self.app.post_quorum_timeout)
        for (putter, response) in finished_quickly:
            if response:
                _handle_response(putter, response)

        if need_quorum:
            if final_phase:
                while len(statuses) < len(nodes):
                    statuses.append(HTTP_SERVICE_UNAVAILABLE)
                    reasons.append('')
                    bodies.append('')
            else:
                # intermediate response phase - make sure there is quorum
                # w/ 100-continue acknowledgements
                if self.have_quorum(statuses, len(nodes), req):
                    quorum = True

        return statuses, reasons, bodies, etags, quorum

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

    def _determine_chunk_destinations(self, putters):
        """
        Given a list of putters, return a dict where they key is the putter
        and the value is the node index to use.

        This is done so that we line up handoffs using the same node index
        (in the primary part list) as the primary that the handoff is standing
        in for.  This lets erasure-code fragment archives wind up on the
        preferred local primary nodes when possible.
        """
        # Give each putter a "chunk index": the index of the
        # transformed chunk that we'll send to it.
        #
        # For primary nodes, that's just its index (primary 0 gets
        # chunk 0, primary 1 gets chunk 1, and so on). For handoffs,
        # we assign the chunk index of a missing primary.
        handoff_conns = []
        chunk_index = {}
        for p in putters:
            if p.node_index < len(putters):
                chunk_index[p] = p.node_index
            else:
                handoff_conns.append(p)

        # Note: we may have more holes than handoffs. This is okay; it
        # just means that we failed to connect to one or more storage
        # nodes. Holes occur when a storage node is down, in which
        # case the connection is not replaced, and when a storage node
        # returns 507, in which case a handoff is used to replace it.
        holes = [x for x in range(len(putters))
                 if x not in chunk_index.values()]

        handoff_conns.sort(key=operator.attrgetter('node_index'))
        for hole, p in zip(holes, handoff_conns):
            chunk_index[p] = hole
        return chunk_index

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
        policy_index = int(req.headers.get('X-Backend-Storage-Policy-Index',
                                           container_info['storage_policy']))
        policy = POLICIES.get_by_index(policy_index)
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

        # do a HEAD request for checking object versions
        if object_versions and not req.environ.get('swift_versioned_copy'):
            # make sure proxy-server uses the right policy index
            _headers = {'X-Backend-Storage-Policy-Index': policy_index,
                        'X-Newest': 'True'}
            hreq = Request.blank(req.path_info, headers=_headers,
                                 environ={'REQUEST_METHOD': 'HEAD'})
            hnode_iter = self.app.iter_nodes(obj_ring, partition)
            hresp = self.GETorHEAD_base(
                hreq, _('Object'), hnode_iter, partition,
                hreq.swift_entity_path)

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

        if object_versions and not req.environ.get('swift_versioned_copy'):
            is_manifest = 'X-Object-Manifest' in req.headers or \
                          'X-Object-Manifest' in hresp.headers
            if hresp.status_int != HTTP_NOT_FOUND and not is_manifest:
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
            source_header = '/%s/%s/%s/%s' % (
                ver, src_account_name, src_container_name, src_obj_name)
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

        # If the request body sent from client -> proxy is the same as the
        # request body sent proxy -> object, then we can rely on the object
        # server to handle any Etag checking. If not, we have to do it here.
        etag_hasher = None if policy.stores_objects_verbatim else md5()

        outgoing_headers = self._backend_requests(
            req, len(nodes), container_partition, containers,
            delete_at_container, delete_at_part, delete_at_nodes)

        for nheaders in outgoing_headers:
            if not policy.stores_objects_verbatim:
                # the object server will get different bytes, so these
                # values do not apply (Content-Length might, in general, but
                # in the specific case of replication vs. EC, it doesn't).
                nheaders.pop('Content-Length', None)
                nheaders.pop('Etag', None)
            # RFC2616:8.2.3 disallows 100-continue without a body
            if (int(nheaders.get('content-length', 0)) > 0) or chunked:
                nheaders['Expect'] = '100-continue'
            pile.spawn(
                self._connect_put_node, node_iter, partition,
                req.swift_entity_path, nheaders,
                self.app.logger.thread_locals, chunked,
                need_metadata_footer=policy.needs_trailing_object_metadata,
                need_multiphase_put=policy.needs_multiphase_put)

        min_puts = policy.quorum_size(len(nodes))
        putters = []
        chunk_hashers = [None] * len(nodes)
        for i, p in enumerate(pile):
            if p:
                putters.append(p)
                p.hshr_index = i
                chunk_hashers[p.hshr_index] = (
                    None if policy.stores_objects_verbatim else md5())

        statuses = [p.current_status() for p in putters]
        if (req.if_none_match is not None
                and '*' in req.if_none_match
                and HTTP_PRECONDITION_FAILED in statuses):
            # If we find any copy of the file, it shouldn't be uploaded
            self.app.logger.debug(
                _('Object PUT returning 412, %(statuses)r'),
                {'statuses': statuses})
            return HTTPPreconditionFailed(request=req)

        if HTTP_CONFLICT in statuses:
            timestamps = [HeaderKeyDict(p.resp.getheaders()).get(
                'X-Backend-Timestamp') for p in putters if p.resp]
            self.app.logger.debug(
                _('Object PUT returning 202 for 409: '
                  '%(req_timestamp)s <= %(timestamps)r'),
                {'req_timestamp': req.timestamp.internal,
                 'timestamps': ', '.join(timestamps)})
            return HTTPAccepted(request=req)

        if len(putters) < min_puts:
            self.app.logger.error(
                _('Object PUT returning 503, %(conns)s/%(nodes)s '
                  'required connections'),
                {'conns': len(putters), 'nodes': min_puts})
            return HTTPServiceUnavailable(request=req)

        bytes_transferred = 0
        chunk_transform = policy.chunk_transformer(len(nodes))
        chunk_transform.send(None)

        def send_chunk(chunk):
            if etag_hasher:
                etag_hasher.update(chunk)
            backend_chunks = chunk_transform.send(chunk)
            if backend_chunks is None:
                # If there's not enough bytes buffered for erasure-encoding
                # or whatever we're doing, the transform will give us None.
                return

            for putter in list(putters):
                backend_chunk = backend_chunks[chunk_index[putter]]
                if not putter.failed:
                    if chunk_hashers[putter.hshr_index]:
                        chunk_hashers[putter.hshr_index].update(backend_chunk)
                    putter.send_chunk(backend_chunk)
                else:
                    putters.remove(putter)
            if len(putters) < min_puts:
                self.app.logger.error(_(
                    'Object PUT exceptions during'
                    ' send, %(conns)s/%(nodes)s required connections'),
                    {'conns': len(putters), 'nodes': min_puts})
                raise HTTPServiceUnavailable(request=req)

        final_phase = True
        need_quorum = True
        min_responses = min_puts
        needs_multiphase_put = policy.needs_multiphase_put
        try:
            with ContextPool(len(putters)) as pool:

                # build our chunk index dict to place handoffs in the
                # same part nodes index as the primaries they are covering
                chunk_index = self._determine_chunk_destinations(putters)

                for putter in putters:
                    putter.spawn_sender_greenthread(
                        pool, self.app.put_queue_depth, self.app.node_timeout,
                        self.app.exception_occurred)
                while True:
                    with ChunkReadTimeout(self.app.client_timeout):
                        try:
                            chunk = next(data_source)
                        except StopIteration:
                            computed_etag = (etag_hasher.hexdigest()
                                             if etag_hasher else None)
                            received_etag = req.headers.get(
                                'etag', '').strip('"')
                            if (computed_etag and received_etag and
                               computed_etag != received_etag):
                                return HTTPUnprocessableEntity(request=req)

                            send_chunk('')  # flush out any buffered data

                            for putter in putters:
                                trail_md = policy.trailing_metadata(
                                    etag_hasher, bytes_transferred,
                                    chunk_index[putter])
                                if not policy.stores_objects_verbatim:
                                    trail_md['Etag'] = chunk_hashers[
                                        putter.hshr_index].hexdigest()
                                putter.end_of_object_data(
                                    needs_multiphase_put, trail_md)
                            break
                    bytes_transferred += len(chunk)
                    if bytes_transferred > constraints.MAX_FILE_SIZE:
                        return HTTPRequestEntityTooLarge(request=req)

                    send_chunk(chunk)

                for putter in putters:
                    putter.wait()

                if needs_multiphase_put:
                    # for storage policies requiring 2-phase commit (e.g.
                    # erasure coding), enforce >= 'quorum' number of
                    # 100-continue responses - this indicates successful
                    # object data and metadata commit and is a necessary
                    # condition to be met before starting 2nd PUT phase
                    final_phase = False
                    statuses, reasons, bodies, _junk, quorum = \
                        self._get_put_responses(
                            req, putters, nodes, final_phase, min_responses,
                            need_quorum=need_quorum)
                    if quorum:
                        # quorum achieved, start 2nd phase - send commit
                        # confirmation to participating object servers
                        # so they write a .durable state file indicating
                        # a successful PUT
                        for putter in putters:
                            putter.send_commit_confirmation()
                    else:
                        self.app.logger.error(
                            _('Not enough object servers ack\'ed (got %d)'),
                            statuses.count(HTTP_CONTINUE))
                        return HTTPServerError(request=req)
                    for putter in putters:
                        putter.wait()
                    final_phase = True
                    need_quorum = False
                    min_responses = 2

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

        statuses, reasons, bodies, etags, _junk = self._get_put_responses(
            req, putters, nodes, final_phase, min_responses,
            need_quorum=need_quorum)

        if len(etags) > 1 and policy.stores_objects_verbatim:
            self.app.logger.error(
                _('Object servers returned %s mismatched etags'), len(etags))
            return HTTPServerError(request=req)
        etag = etags.pop() if len(etags) else None
        resp = self.best_response(req, statuses, reasons, bodies,
                                  _('Object PUT'), etag=etag,
                                  quorum_size=min_puts)
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


class ReplicatedObjectController(BaseObjectController):
    def _get_or_head_response(self, req, node_iter, partition, policy):
        resp = self.GETorHEAD_base(
            req, _('Object'), node_iter, partition,
            req.swift_entity_path)
        return resp


class ECObjectController(BaseObjectController):
    def _get_or_head_response(self, req, node_iter, partition, policy):
        if req.method == 'HEAD':
            # no fancy EC decoding here, just one plain old HEAD request to
            # one object server
            resp = self.GETorHEAD_base(
                req, _('Object'), node_iter, partition,
                req.swift_entity_path)
        else:  # GET request
            node_iter = GreenthreadSafeIterator(node_iter)
            pile = GreenAsyncPile(policy.n_streams_for_decode)
            for _junk in range(policy.n_streams_for_decode):
                pile.spawn(self.GETorHEAD_base,
                           req, 'Object', node_iter, partition,
                           req.swift_entity_path,
                           client_chunk_size=policy.fragment_size)

            # TODO(sam): make this an object that responds to .close() and
            # passes that message to its sub-iterators
            def decoding_iterator(app_iters):
                queues = [Queue(1) for _junk in range(len(app_iters))]

                def put_fragments_in_queue(app_iter, queue):
                    # TODO(sam): timeout handling
                    for fragment in app_iter:
                        queue.put(fragment)
                    queue.put(None)

                with ContextPool(len(app_iters)) as pool:
                    for app_iter, queue in zip(app_iters, queues):
                        pool.spawn(put_fragments_in_queue, app_iter, queue)

                    while True:
                        fragments = []
                        for queue in queues:
                            fragment = queue.get()
                            queue.task_done()
                            fragments.append(fragment)

                        if not all(fragments):  # got a None; we're done
                            break
                        segment = policy.decode_fragments(fragments)
                        yield segment

            responses = list(pile)
            good_responses = []
            bad_responses = []
            for response in responses:
                if response.status_int == 200:
                    good_responses.append(response)
                else:
                    bad_responses.append(response)

            if len(good_responses) == policy.n_streams_for_decode:
                # we found enough pieces to decode the object, so now let's
                # decode the object
                resp = good_responses[0]
                resp.app_iter = decoding_iterator(
                    [r.app_iter for r in good_responses])
            else:
                resp = self.best_response(
                    req,
                    [r.status_int for r in bad_responses],
                    [r.status.split(' ', 1)[1] for r in bad_responses],
                    [r.body for r in bad_responses],
                    'Object')

        # EC fragment archives each have different bytes, hence different
        # etags. However, they all have the original object's etag stored in
        # sysmeta, so we copy that here so the client gets it.
        resp.headers['Etag'] = resp.headers.get(
            'X-Object-Sysmeta-Ec-Etag')
        resp.headers['Content-Length'] = resp.headers.get(
            'X-Object-Sysmeta-Ec-Content-Length')

        return resp
