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
from swift import gettext_ as _
from urllib import unquote, quote

from eventlet import GreenPile
from eventlet.queue import Queue
from eventlet.timeout import Timeout

from swift.common.utils import (
    clean_content_type, config_true_value, ContextPool, csv_append,
    GreenAsyncPile, GreenthreadSafeIterator, json, Timestamp,
    normalize_delete_at_timestamp, public)
from swift.common.bufferedhttp import http_connect
from swift.common.constraints import check_metadata, check_object_creation, \
    check_copy_from_header
from swift.common import constraints
from swift.common.exceptions import ChunkReadTimeout, \
    ChunkWriteTimeout, ConnectionTimeout, ListingIterNotFound, \
    ListingIterNotAuthorized, ListingIterError, RingValidationError
from swift.common.http import is_success, is_client_error, HTTP_CONTINUE, \
    HTTP_CREATED, HTTP_MULTIPLE_CHOICES, HTTP_NOT_FOUND, \
    HTTP_INTERNAL_SERVER_ERROR, HTTP_SERVICE_UNAVAILABLE, \
    HTTP_INSUFFICIENT_STORAGE, HTTP_PRECONDITION_FAILED, HTTP_OK, \
    HTTP_PARTIAL_CONTENT
from swift.proxy.controllers.base import Controller, delay_denial, \
    cors_validation, close_swift_conn, source_key, update_headers, \
    is_server_error
from swift.common.swob import HTTPAccepted, HTTPBadRequest, HTTPNotFound, \
    HTTPPreconditionFailed, HTTPRequestEntityTooLarge, HTTPRequestTimeout, \
    HTTPServerError, HTTPServiceUnavailable, Request, Response, \
    HTTPClientDisconnect, HTTPNotImplemented, HTTPException
from swift.common.request_helpers import is_sys_or_user_meta, is_sys_meta, \
    remove_items, copy_header_subset, ObjectPayloadTrailer
from swift.common.storage_policy import POLICIES, EC_POLICY
from hashlib import md5
from pyeclib.ec_iface import ECDriverError
from swift.common.http import is_redirection
from sys import exc_info


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


class ec_GetOrHeadHandler(object):

    def __init__(self, app, req, server_type, ring, partition, path,
                 backend_headers):
        self.app = app
        self.ring = ring
        self.server_type = server_type
        self.partition = partition
        self.path = path
        self.backend_headers = backend_headers
        ## self.used_nodes = []
        self.used_source_etag = ''

        # stuff from request
        self.req_method = req.method
        self.req_path = req.path
        self.req_query_string = req.query_string
        self.newest = config_true_value(req.headers.get('x-newest', 'f'))

        # populated when finding source
        self.statuses = []
        self.reasons = []
        self.bodies = []
        self.source_headers = []

        policy = POLICIES.get_by_index(
            (int)(req.headers['X-Backend-Storage-Policy-Index']))
        self.ec_ndata = policy.ec_ndata
        self.ec_nparity = policy.ec_nparity
        self.pyeclib_driver = policy.ec_driver

        # filled using headers rcvd from object server
        self.ec_type = None
        self.ec_fragment_size = None
        self.ec_segment_size = None

    def is_good_source(self, src):
        """
        Indicates whether or not the request made to the backend found
        what it was looking for.

        :param src: the response from the backend
        :returns: True if found, False if not
        """
        if self.server_type == 'Object' and src.status == 416:
            return True
        return is_success(src.status) or is_redirection(src.status)

    def _get_fragments_for_next_stripe(self, req, sources, node_timeout):

        fragments = []
        statuses = []
        reasons = []
        bodies = []

        def _get_fragment(source, timeout):
            try:
                with ChunkReadTimeout(timeout):
                    _fragment = source.read(self.ec_fragment_size)
                    print "got fragment %d bytes" % len(_fragment)
                    if source.resp:
                        return _fragment, source, source.resp
                    else:
                        return _fragment, source, source.getresponse()
            except ChunkReadTimeout:
                self.app.exception_occurred(
                    source.node, _('Object'),
                    _('Trying to get fragment from source %r') % source)

        pile = GreenAsyncPile(len(sources))
        for source in sources:
            pile.spawn(_get_fragment, source, node_timeout)

        for fragment, source, response in pile:
            if fragment:
                fragments.append(fragment)
                statuses.append(response.status)
                reasons.append(response.reason)
                bodies.append(response.read())
                if response.status >= HTTP_INTERNAL_SERVER_ERROR:
                    self.app.error_occurred(
                        source.node,
                        _('ERROR %(status)d %(body)s From Object Server '
                          're: %(path)s') %
                        {'status': response.status,
                         'body': bodies[-1][:1024], 'path': req.path})
                elif is_success(response.status):
                    if len(statuses) == self.ec_ndata:
                        break
        # give any pending requests *some* chance to finish
        pile.waitall(self.app.node_timeout)
        while len(statuses) < self.ec_ndata:
            statuses.append(HTTP_SERVICE_UNAVAILABLE)
            reasons.append('')
            bodies.append('')
        return statuses, reasons, bodies, fragments

    def _make_app_iter(self, req, sources):
        try:
            bytes_read_from_source = 0
            node_timeout = self.app.node_timeout
            if self.server_type == 'Object':
                node_timeout = self.app.recoverable_node_timeout
            while True:
                try:
                    statuses, reasons, bodies, \
                        fragments = self._get_fragments_for_next_stripe(
                            req, sources, node_timeout)
                    stripe = self.ec_driver.decode(fragments)
                    bytes_read_from_source += len(stripe)
                    if bytes_read_from_source >= self.object_length:
                        raise StopIteration
                except ChunkReadTimeout:
                    exc_type, exc_value, exc_traceback = exc_info()
                    if self.newest or self.server_type != 'Object':
                        raise exc_type, exc_value, exc_traceback
                    try:
                        self.fast_forward(bytes_read_from_source)
                    except (NotImplementedError, HTTPException, ValueError):
                        raise exc_type, exc_value, exc_traceback
                    ## FIXME handle failure case
                if not stripe:
                    break
                with ChunkWriteTimeout(self.app.client_timeout):
                    yield stripe
        except ChunkWriteTimeout:
            self.app.logger.warn(
                _('Client did not read from proxy within %ss') %
                self.app.client_timeout)
            self.app.logger.increment('client_timeouts')
        except GeneratorExit:
            if not req.environ.get('swift.non_client_disconnect'):
                self.app.logger.warn(_('Client disconnected on read'))
        except Exception:
            self.app.logger.exception(_('Trying to send to client'))
            raise
        finally:
            for source in sources:
                # Close-out the connection as best as possible.
                if getattr(source, 'swift_conn', None):
                    close_swift_conn(source)

    def _ec_unpack_fragment_metadata(self, src_headers):
            self.ec_type = src_headers.get(
                'X-EC-Type-Version', '').strip('"')
            self.ec_fragment_size = src_headers.get(
                'X-EC-Fragment-Size', '').strip('"')
            self.ec_segment_size = src_headers.get(
                'X-EC-Segment-Size', '').strip('"')
            self.used_source_etag = src_headers.get(
                'X-Object-ETag', '').strip('"')
            self.object_length = src_headers.get(
                'X-Object-Content-Length', '').strip('"')

    def _get_sources(self):
        self.statuses = []
        self.reasons = []
        self.bodies = []
        self.source_headers = []
        sources = []

        node_timeout = self.app.node_timeout
        if self.server_type == 'Object' and not self.newest:
            node_timeout = self.app.recoverable_node_timeout
        for node in self.app.iter_nodes(self.ring, self.partition):
            start_node_timing = time.time()
            try:
                with ConnectionTimeout(self.app.conn_timeout):
                    conn = http_connect(
                        node['ip'], node['port'], node['device'],
                        self.partition, self.req_method, self.path,
                        headers=self.backend_headers,
                        query_string=self.req_query_string)
                self.app.set_node_timing(node, time.time() - start_node_timing)

                with Timeout(node_timeout):
                    possible_source = conn.getresponse()
                    # See NOTE: swift_conn at top of file about this.
                    possible_source.swift_conn = conn
            except (Exception, Timeout):
                self.app.exception_occurred(
                    node, self.server_type,
                    _('Trying to %(method)s %(path)s') %
                    {'method': self.req_method, 'path': self.req_path})
                continue
            if self.is_good_source(possible_source):
                # 404 if we know we don't have a synced copy
                if not float(possible_source.getheader('X-PUT-Timestamp', 1)):
                    self.statuses.append(HTTP_NOT_FOUND)
                    self.reasons.append('')
                    self.bodies.append('')
                    self.source_headers.append('')
                    close_swift_conn(possible_source)
                else:
                    if self.used_source_etag:
                        src_headers = dict(
                            (k.lower(), v) for k, v in
                            possible_source.getheaders())
                        if src_headers.get('etag', '').strip('"') != \
                                self.used_source_etag:
                            self.statuses.append(HTTP_NOT_FOUND)
                            self.reasons.append('')
                            self.bodies.append('')
                            self.source_headers.append('')
                            continue

                    self.statuses.append(possible_source.status)
                    self.reasons.append(possible_source.reason)
                    self.bodies.append('')
                    self.source_headers.append('')
                    sources.append((possible_source, node))
            else:
                self.statuses.append(possible_source.status)
                self.reasons.append(possible_source.reason)
                self.bodies.append(possible_source.read())
                self.source_headers.append(possible_source.getheaders())
                if possible_source.status == HTTP_INSUFFICIENT_STORAGE:
                    self.app.error_limit(node, _('ERROR Insufficient Storage'))
                elif is_server_error(possible_source.status):
                    self.app.error_occurred(
                        node, _('ERROR %(status)d %(body)s '
                                'From %(type)s Server') %
                        {'status': possible_source.status,
                         'body': self.bodies[-1][:1024],
                         'type': self.server_type})

        if sources and len(sources) >= self.ec_ndata:
            sources.sort(key=lambda s: source_key(s[0]))
            src_headers = dict(
                (k.lower(), v) for k, v in
                possible_source.getheaders())
            self._ec_unpack_fragment_metadata(src_headers)
            return sources
        return None

    def get_working_response(self, req):
        sources = self._get_sources()
        res = None
        good_source = None
        if sources:
            res = Response(request=req)
            if req.method == 'GET':
                ngood_responses = 0
                for source in sources:
                    if source.status in (HTTP_OK, HTTP_PARTIAL_CONTENT):
                        ngood_responses += 1
                        if not good_source:
                            good_source = source
                if ngood_responses > self.ec_ndata:
                    res.app_iter = self._make_app_iter(req, sources)
                    res.swift_conn = source.swift_conn
                # See NOTE: swift_conn at top of file about this.
                # TBD res.swift_conn = source.swift_conn
######################### WIP #######################
                # FIXME - one source is enough?
                if good_source:
                    res.status = good_source.status
                update_headers(res, good_source.getheaders())
                if not res.environ:
                    res.environ = {}
                res.environ['swift_x_timestamp'] = \
                    source.getheader('x-timestamp')
                res.accept_ranges = 'bytes'
                res.content_length = source.getheader('Content-Length')
                if source.getheader('Content-Type'):
                    res.charset = None
                    res.content_type = source.getheader('Content-Type')
######################### WIP #######################
        return res


class ObjectController(Controller):
    """WSGI controller for object requests."""
    server_type = 'Object'

    def __init__(self, app, account_name, container_name, object_name,
                 **kwargs):
        Controller.__init__(self, app)
        self.account_name = unquote(account_name)
        self.container_name = unquote(container_name)
        self.object_name = unquote(object_name)
        self.ec_GetOrHeadHandler = ec_GetOrHeadHandler

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

            try:
                req, delete_at_container, delete_at_part, \
                    delete_at_nodes = self._config_obj_expiration(req)
            except ValueError as e:
                return HTTPBadRequest(request=req, content_type='text/plain',
                                      body=str(e))

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

    def _connect_put_node(self, nodes, part, path, headers,
                          logger_thread_locals):
        """Method for a file PUT connect"""
        self.app.logger.thread_locals = logger_thread_locals
        for node in nodes:
            try:
                start_time = time.time()
                with ConnectionTimeout(self.app.conn_timeout):
                    conn = http_connect(
                        node['ip'], node['port'], node['device'], part, 'PUT',
                        path, headers)
                self.app.set_node_timing(node, time.time() - start_time)
                with Timeout(self.app.node_timeout):
                    resp = conn.getexpect()
                if resp.status == HTTP_CONTINUE:
                    conn.resp = None
                    conn.node = node
                    return conn
                elif is_success(resp.status):
                    conn.resp = resp
                    conn.node = node
                    return conn
                elif headers['If-None-Match'] is not None and \
                        resp.status == HTTP_PRECONDITION_FAILED:
                    conn.resp = resp
                    conn.node = node
                    return conn
                elif resp.status == HTTP_INSUFFICIENT_STORAGE:
                    self.app.error_limit(node, _('ERROR Insufficient Storage'))
            except (Exception, Timeout):
                self.app.exception_occurred(
                    node, _('Object'),
                    _('Expect: 100-continue on %s') % path)

    def _quorum_size(self, n, policy_index):
        """
        Number of successful backend requests needed for the proxy to consider
        the client request successful.
        """
        policy = POLICIES.get_by_index(policy_index)
        return policy.quorum_size(n)

    def _get_put_responses(self, req, conns, nodes):
        statuses = []
        reasons = []
        bodies = []
        etags = dict()

        def get_conn_response(conn):
            try:
                with Timeout(self.app.node_timeout):
                    if conn.resp:
                        return conn, conn.resp
                    else:
                        return conn, conn.getresponse()
            except (Exception, Timeout):
                self.app.exception_occurred(
                    conn.node, _('Object'),
                    _('Trying to get final status of PUT to %s') % req.path)
        pile = GreenAsyncPile(len(conns))
        for conn in conns:
            pile.spawn(get_conn_response, conn)
        for conn, response in pile:
            if response:
                statuses.append(response.status)
                reasons.append(response.reason)
                bodies.append(response.read())
                if response.status >= HTTP_INTERNAL_SERVER_ERROR:
                    self.app.error_occurred(
                        conn.node,
                        _('ERROR %(status)d %(body)s From Object Server '
                          're: %(path)s') %
                        {'status': response.status,
                         'body': bodies[-1][:1024], 'path': req.path})
                elif is_success(response.status):
                    etags[conn] = response.getheader('etag').strip('"')
                container_info = self.container_info(
                    self.account_name, self.container_name, req)
                policy_index = \
                    req.headers.get('X-Backend-Storage-Policy-Index',
                                    container_info['storage_policy'])
                if self.have_quorum(statuses, len(nodes), policy_index):
                    break
        # give any pending requests *some* chance to finish
        pile.waitall(self.app.post_quorum_timeout)
        while len(statuses) < len(nodes):
            statuses.append(HTTP_SERVICE_UNAVAILABLE)
            reasons.append('')
            bodies.append('')
        return statuses, reasons, bodies, etags

    def _config_obj_expiration(self, req):
        delete_at_container = None
        delete_at_part = None
        delete_at_nodes = None

        if 'x-delete-after' in req.headers:
            try:
                x_delete_after = int(req.headers['x-delete-after'])
            except ValueError:
                raise ValueError('Non-integer X-Delete-After')

            req.headers['x-delete-at'] = normalize_delete_at_timestamp(
                time.time() + x_delete_after)

        if 'x-delete-at' in req.headers:
            try:
                x_delete_at = int(normalize_delete_at_timestamp(
                    int(req.headers['x-delete-at'])))
            except ValueError:
                raise ValueError('Non-integer X-Delete-At')

            if x_delete_at < time.time():
                raise ValueError('X-Delete-At in past')

            req.environ.setdefault('swift.log_info', []).append(
                'x-delete-at:%s' % x_delete_at)
            delete_at_container = normalize_delete_at_timestamp(
                x_delete_at /
                self.app.expiring_objects_container_divisor *
                self.app.expiring_objects_container_divisor)
            delete_at_part, delete_at_nodes = \
                self.app.container_ring.get_nodes(
                    self.app.expiring_objects_account, delete_at_container)

        return req, delete_at_container, delete_at_part, delete_at_nodes

    def _ec_pack_fragment_metadata(self, policy, req):
        # fixed min object segment size we apply EC encode on
        # It is chosen to be reasonably large so we don't end up with
        # too many small fragments, or end up calling into expensive
        # EC encode operations too many times.
        ec_object_segment_size = constraints.EC_OBJECT_SEGMENT_SIZE

        # For EC policies, we call PyECLib get_segment_info() routine to
        # get info necessary to calculate total transfer size to the object
        # server (PyECLib calculates data size taking into account any
        # header/padding overheads for data fragments generated after
        # EC encode operation
        if req.content_length > 0:
            data_length = req.content_length
        else:
            # Most likely chunked encoding.  We don't know the total
            # object length being transferred from the client.
            # Use ec_object_segment_size for ec_fragment_size calculation
            data_length = ec_object_segment_size
        ec_segment_info = \
            policy.ec_driver.get_segment_info(data_length,
                                              ec_object_segment_size)
        ec_num_segments = ec_segment_info['num_segments']
        ec_fragment_size = ec_segment_info['fragment_size']
        ec_last_fragment_size = ec_segment_info['last_fragment_size']
        # Add EC-specific headers to req.headers
        req.headers['X-EC-Type-Version'] = policy.ec_type
        req.headers['X-EC-Segment-Size'] = ec_object_segment_size
        req.headers['X-EC-Fragment-Size'] = ec_fragment_size
        # calculate total fragment archive transfer size to each object
        ec_transfer_size = \
            ((ec_num_segments - 1) * ec_fragment_size) + ec_last_fragment_size
        return ec_object_segment_size, ec_fragment_size, ec_transfer_size

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
        obj_ring = self.app.get_object_ring(policy_index)

        # pass the policy index to storage nodes via req header
        req.headers['X-Backend-Storage-Policy-Index'] = policy_index
        ec_policy = False
        policy = POLICIES.get_by_index(policy_index)
        if policy.policy_type == EC_POLICY:
            # Early check to validate if the replica count for the
            # policy is enough to hold (data + parity) nodes
            try:
                policy.validate_ring_replica_count(obj_ring.replica_count)
            except RingValidationError:
                return HTTPServerError(request=req)
            ec_policy = True
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

        try:
            ml = req.message_length()
        except ValueError as e:
            return HTTPBadRequest(request=req, content_type='text/plain',
                                  body=str(e))
        except AttributeError as e:
            return HTTPNotImplemented(request=req, content_type='text/plain',
                                      body=str(e))
        if ml is not None and ml > constraints.MAX_FILE_SIZE:
            return HTTPRequestEntityTooLarge(request=req)
        if 'x-delete-after' in req.headers:
            try:
                x_delete_after = int(req.headers['x-delete-after'])
            except ValueError:
                return HTTPBadRequest(request=req,
                                      content_type='text/plain',
                                      body='Non-integer X-Delete-After')
            req.headers['x-delete-at'] = normalize_delete_at_timestamp(
                time.time() + x_delete_after)
        # get_nodes returns (ndata + nparity) nodes for object rings
        # configured with erasure_coding policy type
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
            src_container_name, src_obj_name = check_copy_from_header(req)
            ver, acct, _rest = req.split_path(2, 3, True)
            if isinstance(acct, unicode):
                acct = acct.encode('utf-8')
            source_header = '/%s/%s/%s/%s' % (ver, acct,
                                              src_container_name, src_obj_name)
            source_req = req.copy_get()

            # make sure the source request uses it's container_info
            source_req.headers.pop('X-Backend-Storage-Policy-Index', None)
            source_req.path_info = source_header
            source_req.headers['X-Newest'] = 'true'
            orig_obj_name = self.object_name
            orig_container_name = self.container_name
            self.object_name = src_obj_name
            self.container_name = src_container_name
            sink_req = Request.blank(req.path_info,
                                     environ=req.environ, headers=req.headers)
            source_resp = self.GET(source_req)

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

        try:
            req, delete_at_container, delete_at_part, \
                delete_at_nodes = self._config_obj_expiration(req)
        except ValueError as e:
            return HTTPBadRequest(request=req, content_type='text/plain',
                                  body=str(e))

        node_iter = GreenthreadSafeIterator(
            self.iter_nodes_local_first(obj_ring, partition))
        pile = GreenPile(len(nodes))
        te = req.headers.get('transfer-encoding', '')
        chunked = ('chunked' in te)

        # Tell object servers about trailer magic
        req.headers['X-Backend-Payload-Trailer-Magic'] = \
            ObjectPayloadTrailer.trailer_magic
        trailer_size = ObjectPayloadTrailer.get_trailer_size()
        req.headers['X-Backend-Payload-Trailer-Length'] = trailer_size

        if req.content_length > 0 and not chunked:
            # if HTTP encoding is non-chunked, we need to prefill the
            # Content-Length header.  Content length (transfer size)
            # is not the same as original object length for EC policies
            if ec_policy:
                ec_object_segment_size, ec_fragment_size, transfer_size = \
                    self._ec_pack_fragment_metadata(policy, req)
                req.content_length = transfer_size
            else:
                transfer_size = req.content_length
            # Add trailer length to 'Content-Length'
            req.content_length += trailer_size
            req.headers['Content-Length'] = str(req.content_length)

        outgoing_headers = self._backend_requests(
            req, len(nodes), container_partition, containers,
            delete_at_container, delete_at_part, delete_at_nodes)

        for nheaders in outgoing_headers:
            # RFC2616:8.2.3 disallows 100-continue without a body
            if (req.content_length > 0) or chunked:
                nheaders['Expect'] = '100-continue'
            pile.spawn(self._connect_put_node, node_iter, partition,
                       req.swift_entity_path, nheaders,
                       self.app.logger.thread_locals)

        conns = [conn for conn in pile if conn]
        min_conns = self._quorum_size(len(nodes), policy_index)

        if req.if_none_match is not None and '*' in req.if_none_match:
            statuses = [conn.resp.status for conn in conns if conn.resp]
            if HTTP_PRECONDITION_FAILED in statuses:
                # If we find any copy of the file, it shouldn't be uploaded
                self.app.logger.debug(
                    _('Object PUT returning 412, %(statuses)r'),
                    {'statuses': statuses})
                return HTTPPreconditionFailed(request=req)

        if len(conns) < min_conns:
            self.app.logger.error(
                _('Object PUT returning 503, %(conns)s/%(nodes)s '
                  'required connections'),
                {'conns': len(conns), 'nodes': min_conns})
            return HTTPServiceUnavailable(request=req)
        # In the erasure_coding case, we stream individual fragments to
        # respective nodes/connections, which get accumulated into
        # 'fragment archives' on the object server
        ec_fragments = ec_fragment = None
        ec_segment_etag = md5()
        # Create a conn:etag association for the fragment archives
        ec_fragarchive_etags = []
        for i in range(len(conns)):
            ec_fragarchive_etags.extend([md5()])
        ec_fragarchive_etags_dict = dict(zip(conns, ec_fragarchive_etags))
        # Running etag for original object data (for trailer)
        orig_object_etag = md5()
        # Bytes transferred and object_bytes_transferred can be different
        # where the original object data is mangled and additional metadata
        # is added to record modifications to the original data
        bytes_transferred = 0
        object_bytes_transferred = 0
        try:
            with ContextPool(len(nodes)) as pool:
                for conn in conns:
                    conn.failed = False
                    conn.queue = Queue(self.app.put_queue_depth)
                    pool.spawn(self._send_file, conn, req.path)

                _buffer = []
                seg = next_seg = b''
                while True:
                    with ChunkReadTimeout(self.app.client_timeout):
                        try:
                            if ec_policy:
                                _buffer = []
                                leftover = seglen = 0
                                # We buffer HTTP chunks until we have enough to
                                # meet the ec_object_segment_size constraint.
                                while seglen < ec_object_segment_size:
                                    chunk = next(data_source)
                                    seglen += len(chunk)
                                    if seglen >= ec_object_segment_size:
                                        # Buffer any leftover bytes
                                        leftover = \
                                            seglen - ec_object_segment_size
                                        next_seg = chunk[:leftover]
                                        chunk = chunk[leftover:]
                                    _buffer.append(chunk)
                                seg = b''.join(_buffer)
                            else:
                                chunk = next(data_source)
                        except StopIteration:
                            if ec_policy:
                                # Flush _buffer
                                seg = b''.join(_buffer)
                                if len(seg) == 0:
                                    break
                            else:
                                break
                    # If policy is erasure_coding, encode obj data into
                    # ec_ndata + ec_nparity fragments. EC fragments are
                    # streamed to the object server similar to non-EC objs
                    if ec_policy:
                        # Running md5sum for object data
                        ec_segment_etag.update(seg)
                        # OK to Encode and stream now
                        try:
                            ec_fragments = policy.ec_driver.encode(seg)
                        except ECDriverError:
                            self.app.logger.error(_(
                                'Object PUT exception during'
                                ' ec_driver.encode()'))
                            return HTTPServerError(request=req)
                        ec_fragment = iter(ec_fragments)

                        bytes_transferred += len(ec_fragments[0])
                        object_bytes_transferred += len(seg)
                        seg = next_seg
                        next_seg = ""
                    else:
                        orig_object_etag.update(chunk)
                        bytes_transferred += len(chunk)

                    if bytes_transferred > constraints.MAX_FILE_SIZE:
                        return HTTPRequestEntityTooLarge(request=req)
                    for conn in list(conns):
                        if not conn.failed:
                            if ec_policy:
                                chunk = next(ec_fragment)
                                # Choose fragment archive etag corresponding
                                # to the connection object and update
                                ec_fragarchive_etags_dict[conn].update(chunk)
                            conn.queue.put(
                                '%x\r\n%s\r\n' % (len(chunk), chunk)
                                if chunked else chunk)
                            print(("conn %r, wrote %d bytes")
                                  % (conn, len(chunk)))
                        else:
                            conns.remove(conn)
                    if len(conns) < min_conns:
                        self.app.logger.error(_(
                            'Object PUT exceptions during'
                            ' send, %(conns)s/%(nodes)s required connections'),
                            {'conns': len(conns), 'nodes': min_conns})
                        return HTTPServiceUnavailable(request=req)

                orig_object_size = bytes_transferred
                payload_etag = orig_object_etag
                if ec_policy:
                    orig_object_size = object_bytes_transferred
                    orig_object_etag = ec_segment_etag
                # Send payload trailer
                for conn in conns:
                    # Erasure coding case: get etag for the fragment archive
                    # being sent down this connection
                    if ec_policy:
                        payload_etag = \
                            ec_fragarchive_etags_dict[conn]
                    trailer = ObjectPayloadTrailer(
                        payload_etag, orig_object_size, orig_object_etag)
                    trailer_bytes = trailer.serialize()
                    conn.queue.put(
                        '%x\r\n%s\r\n' %
                        (len(trailer_bytes), trailer_bytes)
                        if chunked else trailer_bytes)
                bytes_transferred += len(trailer_bytes)
                if chunked:
                    for conn in conns:
                        conn.queue.put('0\r\n\r\n')
                for conn in conns:
                    if conn.queue.unfinished_tasks:
                        conn.queue.join()
            conns = [conn for conn in conns if not conn.failed]
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

        statuses, reasons, bodies, etags = self._get_put_responses(req, conns,
                                                                   nodes)
        if ec_policy:
            # Validate etags received in response against EC fragment etags
            mismatched_etags = 0
            for conn in conns:
                fragarch_etag = ec_fragarchive_etags_dict[conn]
                if fragarch_etag.hexdigest() != etags[conn]:
                    mismatched_etags += 1
                print "EC conn index = %d, etag = %r, resp_etag = %r" % \
                    (conns.index(conn), fragarch_etag.hexdigest(),
                     etags[conn])
            if mismatched_etags > 0:
                self.app.logger.error(
                    _('Object servers returned %s mismatched etags'),
                    len(etags))
            # Respond with object etag
            etag = orig_object_etag.hexdigest()
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
            resp.headers['X-Copied-From'] = quote(
                source_header.split('/', 3)[3])
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
            last_item = None
            try:
                for last_item in self._listing_iter(lcontainer, lprefix,
                                                    req.environ):
                    pass
            except ListingIterNotFound:
                # no worries, last_item is None
                pass
            except ListingIterNotAuthorized as err:
                return err.aresp
            except ListingIterError:
                return HTTPServerError(request=req)
            if last_item:
                # there are older versions so copy the previous version to the
                # current object and delete the previous version
                orig_container = self.container_name
                orig_obj = self.object_name
                self.container_name = lcontainer
                self.object_name = last_item['name'].encode('utf-8')
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
                if is_client_error(copy_resp.status_int):
                    # some user error, maybe permissions
                    return HTTPPreconditionFailed(request=req)
                elif not is_success(copy_resp.status_int):
                    # could not copy the data, bail
                    return HTTPServiceUnavailable(request=req)
                # reset these because the COPY changed them
                self.container_name = lcontainer
                self.object_name = last_item['name'].encode('utf-8')
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
        resp = self.make_requests(req, obj_ring,
                                  partition, 'DELETE', req.swift_entity_path,
                                  headers)
        return resp

    @public
    @cors_validation
    @delay_denial
    def COPY(self, req):
        """HTTP COPY request handler."""
        dest = req.headers.get('Destination')
        if not dest:
            return HTTPPreconditionFailed(request=req,
                                          body='Destination header required')
        dest = unquote(dest)
        if not dest.startswith('/'):
            dest = '/' + dest
        try:
            _junk, dest_container, dest_object = dest.split('/', 2)
        except ValueError:
            return HTTPPreconditionFailed(
                request=req,
                body='Destination header must be of the form '
                     '<container name>/<object name>')
        source = '/' + self.container_name + '/' + self.object_name
        self.container_name = dest_container
        self.object_name = dest_object
        # re-write the existing request as a PUT instead of creating a new one
        # since this one is already attached to the posthooklogger
        req.method = 'PUT'
        req.path_info = '/v1/' + self.account_name + dest
        req.headers['Content-Length'] = 0
        req.headers['X-Copy-From'] = quote(source)
        del req.headers['Destination']
        return self.PUT(req)
