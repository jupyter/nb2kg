# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.

import os
import json

from tornado import gen
from tornado.escape import json_encode, json_decode, url_escape
from tornado.httpclient import HTTPClient, AsyncHTTPClient, HTTPError

from notebook.services.kernels.kernelmanager import MappingKernelManager
from notebook.services.sessions.sessionmanager import (
    SessionManager as BaseSessionManager
)
from jupyter_client.kernelspec import KernelSpecManager
from notebook.utils import url_path_join

from traitlets import Instance, Unicode, default

# TODO: Find a better way to specify global configuration options 
# for a server extension.
KG_URL = os.getenv('KG_URL', 'http://127.0.0.1:8888/')
KG_HEADERS = json.loads(os.getenv('KG_HEADERS', '{}'))
KG_HEADERS.update({
    'Authorization': 'token {}'.format(os.getenv('KG_AUTH_TOKEN', ''))
})
VALIDATE_KG_CERT = os.getenv('VALIDATE_KG_CERT') not in ['no', 'false']

KG_CLIENT_KEY = os.getenv('KG_CLIENT_KEY')
KG_CLIENT_CERT = os.getenv('KG_CLIENT_CERT')
KG_CLIENT_CA = os.getenv('KG_CLIENT_CA')

KG_HTTP_USER = os.getenv('KG_HTTP_USER')
KG_HTTP_PASS = os.getenv('KG_HTTP_PASS')

KG_CONNECT_TIMEOUT = float(os.getenv('KG_CONNECT_TIMEOUT', 20.0))
KG_REQUEST_TIMEOUT = float(os.getenv('KG_REQUEST_TIMEOUT', 20.0))


def load_connection_args(**kwargs):
    if KG_CLIENT_CERT:
        kwargs["client_key"] = kwargs.get("client_key", KG_CLIENT_KEY)
        kwargs["client_cert"] = kwargs.get("client_cert", KG_CLIENT_CERT)
        if KG_CLIENT_CA:
            kwargs["ca_certs"] = kwargs.get("ca_certs", KG_CLIENT_CA)
    kwargs['connect_timeout'] = kwargs.get('connect_timeout', KG_CONNECT_TIMEOUT)
    kwargs['request_timeout'] = kwargs.get('request_timeout', KG_REQUEST_TIMEOUT)
    kwargs['headers'] = kwargs.get('headers', KG_HEADERS)
    kwargs['validate_cert'] = kwargs.get('validate_cert', VALIDATE_KG_CERT)
    if KG_HTTP_USER:
        kwargs['auth_username'] = kwargs.get('auth_username', KG_HTTP_USER)
    if KG_HTTP_PASS:
        kwargs['auth_password'] = kwargs.get('auth_password', KG_HTTP_PASS)
    return kwargs

@gen.coroutine
def fetch_kg(endpoint, **kwargs):
    """Make an async request to kernel gateway endpoint."""
    client = AsyncHTTPClient()
    url = url_path_join(KG_URL, endpoint)

    kwargs = load_connection_args(**kwargs)

    response = yield client.fetch(url, **kwargs)
    raise gen.Return(response)

class RemoteKernelManager(MappingKernelManager):
    """Kernel manager that supports remote kernels hosted by Jupyter 
    kernel gateway."""

    kernels_endpoint_env = 'KG_KERNELS_ENDPOINT'
    kernels_endpoint = Unicode(config=True,
        help="""The kernel gateway API endpoint for accessing kernel resources 
        (KG_KERNELS_ENDPOINT env var)""")

    @default('kernels_endpoint')
    def kernels_endpoint_default(self):
        return os.getenv(self.kernels_endpoint_env, '/api/kernels')

    # TODO: The notebook code base assumes a sync operation to determine if
    # kernel manager has a kernel_id (existing kernel manager stores kernels
    # in dictionary).  Keeping such a dictionary in sync with remote KG is
    # NOT something we want to do, is it?
    #
    # options:
    #  - update internal dictionary on every /api/kernels request
    #  - replace `__contains__` with more formal async get_kernel() API
    #    (requires notebook code base changes)
    _kernels = {}
    
    def __contains__(self, kernel_id):
        self.log.debug('RemoteKernelManager.__contains__ {}'.format(kernel_id))
        return kernel_id in self._kernels

    def _remove_kernel(self, kernel_id):
        """Remove a kernel from our mapping, mainly so that a dead kernel can be 
        removed without having to call shutdown_kernel.

        The kernel object is returned.

        Parameters
        ----------
        kernel_id: kernel UUID
        """
        try:
            return self._kernels.pop(kernel_id)
        except KeyError:
            pass

    def _kernel_id_to_url(self, kernel_id):
        """Builds a url for the given kernel UUID.

        Parameters
        ----------
        kernel_id: kernel UUID
        """
        return url_path_join(self.kernels_endpoint, url_escape(str(kernel_id)))

    @gen.coroutine
    def start_kernel(self, kernel_id=None, path=None, **kwargs):
        """Start a kernel for a session and return its kernel_id.

        Parameters
        ----------
        kernel_id : uuid
            The uuid to associate the new kernel with. If this
            is not None, this kernel will be persistent whenever it is
            requested.
        path : API path
            The API path (unicode, '/' delimited) for the cwd.
            Will be transformed to an OS path relative to root_dir.
        """
        self.log.info(
            'Request start kernel: kernel_id=%s, path="%s"',
            kernel_id, path
        )

        if kernel_id is None:
            kernel_name = kwargs.get('kernel_name', 'python3')
            self.log.debug("Request new kernel at: %s" % self.kernels_endpoint)
            kernel_env = {k: v for (k, v) in dict(os.environ).items() if k.startswith('KERNEL_')
                        or k in os.environ.get('KG_ENV_WHITELIST', '').split(",")}
            # Convey the full path to where this notebook file is located.
            if path is not None and kernel_env.get('KERNEL_WORKING_DIR') is None:
                kernel_env['KERNEL_WORKING_DIR'] = self.cwd_for_path(path)

            json_body = json_encode({'name': kernel_name, 'env': kernel_env})

            response = yield fetch_kg(self.kernels_endpoint, method='POST', body=json_body)
            kernel = json_decode(response.body)
            kernel_id = kernel['id']
            self.log.info("Kernel started: %s" % kernel_id)
        else:
            kernel = yield self.get_kernel(kernel_id)
            kernel_id = kernel['id']
            self.log.info("Using existing kernel: %s" % kernel_id)
        self._kernels[kernel_id] = kernel
        raise gen.Return(kernel_id)

    @gen.coroutine
    def get_kernel(self, kernel_id=None, **kwargs):
        """Get kernel for kernel_id.

        Parameters
        ----------
        kernel_id : uuid
            The uuid of the kernel.
        """
        kernel_url = self._kernel_id_to_url(kernel_id)
        self.log.debug("Request kernel at: %s" % kernel_url)
        try:
            response = yield fetch_kg(kernel_url, method='GET')
        except HTTPError as error:
            if error.code == 404:
                self.log.debug("Kernel not found at: %s" % kernel_url)
                self._remove_kernel(kernel_id)
                kernel = None
            else:
                raise
        else:
            kernel = json_decode(response.body)
            self._kernels[kernel_id] = kernel
        self.log.debug("Kernel retrieved: %s" % kernel)
        raise gen.Return(kernel)

    @gen.coroutine
    def kernel_model(self, kernel_id):
        """Return a dictionary of kernel information described in the
        JSON standard model.

        Parameters
        ----------
        kernel_id : uuid
            The uuid of the kernel.
        """
        self.log.debug("RemoteKernelManager.kernel_model: %s", kernel_id)
        model = yield self.get_kernel(kernel_id)
        raise gen.Return(model)

    @gen.coroutine
    def list_kernels(self, **kwargs):
        """Get a list of kernels."""
        self.log.debug("Request list kernels: %s", kwargs)
        response = yield fetch_kg(self.kernels_endpoint, method='GET')
        kernels = json_decode(response.body)
        self._kernels = {x['id']:x for x in kernels}
        raise gen.Return(kernels)

    @gen.coroutine
    def shutdown_kernel(self, kernel_id):
        """Shutdown a kernel by its kernel uuid.

        Parameters
        ==========
        kernel_id : uuid
            The id of the kernel to shutdown.
        """
        self.log.debug("Request shutdown kernel: %s", kernel_id)
        kernel_url = self._kernel_id_to_url(kernel_id)
        self.log.debug("Request delete kernel at: %s", kernel_url)
        response = yield fetch_kg(kernel_url, method='DELETE')
        self.log.debug("Shutdown kernel response: %d %s", response.code, response.reason)
        self._remove_kernel(kernel_id)

    @gen.coroutine
    def restart_kernel(self, kernel_id, now=False, **kwargs):
        """Restart a kernel by its kernel uuid.

        Parameters
        ==========
        kernel_id : uuid
            The id of the kernel to restart.
        """
        self.log.debug("Request restart kernel: %s", kernel_id)
        kernel_url = self._kernel_id_to_url(kernel_id) + '/restart'
        self.log.debug("Request restart kernel at: %s", kernel_url)
        response = yield fetch_kg(kernel_url, method='POST', body=json_encode({}))
        self.log.debug("Restart kernel response: %d %s", response.code, response.reason)

    @gen.coroutine
    def interrupt_kernel(self, kernel_id, **kwargs):
        """Interrupt a kernel by its kernel uuid.

        Parameters
        ==========
        kernel_id : uuid
            The id of the kernel to interrupt.
        """
        self.log.debug("Request interrupt kernel: %s", kernel_id)
        kernel_url = self._kernel_id_to_url(kernel_id) + '/interrupt'
        self.log.debug("Request interrupt kernel at: %s", kernel_url)
        response = yield fetch_kg(kernel_url, method='POST', body=json_encode({}))
        self.log.debug("Interrupt kernel response: %d %s", response.code, response.reason)

    def shutdown_all(self):
        """Shutdown all kernels."""
        # Note: We have to make this sync because the NotebookApp does not wait for async.
        kwargs = {'method': 'DELETE'}
        kwargs = load_connection_args(**kwargs)
        client = HTTPClient()
        for kernel_id in self._kernels.keys():
            kernel_url = url_path_join(KG_URL, self._kernel_id_to_url(kernel_id))
            self.log.debug("Request delete kernel at: %s", kernel_url)
            try:
                response = client.fetch(kernel_url, **kwargs)
            except HTTPError:
                pass
            self.log.debug("Delete kernel response: %d %s",
                response.code, response.reason)
        client.close()


class RemoteKernelSpecManager(KernelSpecManager):
    kernelspecs_endpoint_env = 'KG_KERNELSPECS_ENDPOINT'
    kernelspecs_endpoint = Unicode(config=True,
        help="""The kernel gateway API endpoint for accessing kernelspecs 
        (KG_KERNELSPECS_ENDPOINT env var)""")

    @default('kernelspecs_endpoint')
    def kernelspecs_endpoint_default(self):
        return os.getenv(self.kernelspecs_endpoint_env, '/api/kernelspecs')

    kernelspecs_resource_endpoint_env = 'KG_KERNELSPECS_RESOURCE_ENDPOINT'
    kernelspecs_resource_endpoint = Unicode(config=True,
        help="""The kernel gateway API endpoint for accessing kernelspecs resources 
        (KG_KERNELSPECS_RESOURCE_ENDPOINT env var)""")

    @default('kernelspecs_resource_endpoint')
    def kernelspecs_resource_endpoint_default(self):
        return os.getenv(self.kernelspecs_resource_endpoint_env, '/kernelspecs')

    @gen.coroutine
    def list_kernel_specs(self):
        """Get a list of kernel specs."""
        self.log.debug("Request list kernel specs at: %s", self.kernelspecs_endpoint)
        response = yield fetch_kg(self.kernelspecs_endpoint, method='GET')
        kernel_specs = json_decode(response.body)
        raise gen.Return(kernel_specs)

    @gen.coroutine
    def get_kernel_spec(self, kernel_name, **kwargs):
        """Get kernel spec for kernel_name.

        Parameters
        ----------
        kernel_name : str
            The name of the kernel.
        """
        kernel_spec_url = url_path_join(self.kernelspecs_endpoint, str(kernel_name))
        self.log.debug("Request kernel spec at: %s" % kernel_spec_url)
        try:
            response = yield fetch_kg(kernel_spec_url, method='GET')
        except HTTPError as error:
            if error.code == 404:
                self.log.warning("Kernel spec not found at: %s" % kernel_spec_url)
                kernel_spec = None
            else:
                raise
        else:
            kernel_spec = json_decode(response.body)
        raise gen.Return(kernel_spec)

    @gen.coroutine
    def get_kernel_spec_resource(self, kernel_name, path):
        """Get kernel spec for kernel_name.

        Parameters
        ----------
        kernel_name : str
            The name of the kernel.
        path : str
            The name of the desired resource
        """
        kernel_spec_url = url_path_join(self.kernelspecs_resource_endpoint, str(kernel_name), str(path))
        self.log.debug("Request kernel spec resource '{}' at: {}".format(path,kernel_spec_url))
        try:
            response = yield fetch_kg(kernel_spec_url, method='GET')
        except HTTPError as error:
            if error.code == 404:
                kernel_spec_resource = None
            else:
                raise
        else:
            kernel_spec_resource = response.body
        raise gen.Return(kernel_spec_resource)


class SessionManager(BaseSessionManager):
    kernel_manager = Instance('nb2kg.managers.RemoteKernelManager')

    @gen.coroutine
    def create_session(self, path=None, name=None, type=None,
                       kernel_name=None, kernel_id=None):
        """Creates a session and returns its model.
        
        Overrides base class method to turn into an async operation.
        """
        session_id = self.new_session_id()

        kernel = None
        if kernel_id is not None:
            # This is now an async operation
            kernel = yield self.kernel_manager.get_kernel(kernel_id)
        
        if kernel is not None:
            pass
        else:
            kernel_id = yield self.start_kernel_for_session(
                session_id, path, name, type, kernel_name,
            )

        result = yield self.save_session(
            session_id, path=path, name=name, type=type, kernel_id=kernel_id,
        )
        raise gen.Return(result)

    @gen.coroutine
    def save_session(self, session_id, path=None, name=None, type=None,
                     kernel_id=None):
        """Saves the items for the session with the given session_id
        
        Given a session_id (and any other of the arguments), this method
        creates a row in the sqlite session database that holds the information
        for a session.
        
        Parameters
        ----------
        session_id : str
            uuid for the session; this method must be given a session_id
        path : str
            the path for the given notebook
        kernel_id : str
            a uuid for the kernel associated with this session
        
        Returns
        -------
        model : dict
            a dictionary of the session model
        """
        # This is now an async operation
        session = yield super(SessionManager, self).save_session(
            session_id, path=path, name=name, type=type, kernel_id=kernel_id
        )
        raise gen.Return(session)

    @gen.coroutine
    def get_session(self, **kwargs):
        """Returns the model for a particular session.
        
        Takes a keyword argument and searches for the value in the session
        database, then returns the rest of the session's info.

        Overrides base class method to turn into an async operation.

        Parameters
        ----------
        **kwargs : keyword argument
            must be given one of the keywords and values from the session database
            (i.e. session_id, path, kernel_id)

        Returns
        -------
        model : dict
            returns a dictionary that includes all the information from the 
            session described by the kwarg.
        """
        # This is now an async operation
        session = yield super(SessionManager, self).get_session(**kwargs)
        raise gen.Return(session)

    @gen.coroutine
    def update_session(self, session_id, **kwargs):
        """Updates the values in the session database.
        
        Changes the values of the session with the given session_id
        with the values from the keyword arguments. 

        Overrides base class method to turn into an async operation.
        
        Parameters
        ----------
        session_id : str
            a uuid that identifies a session in the sqlite3 database
        **kwargs : str
            the key must correspond to a column title in session database,
            and the value replaces the current value in the session 
            with session_id.
        """
        # This is now an async operation
        session = yield self.get_session(session_id=session_id)

        if not kwargs:
            # no changes
            return

        sets = []
        for column in kwargs.keys():
            if column not in self._columns:
                raise TypeError("No such column: %r" % column)
            sets.append("%s=?" % column)
        query = "UPDATE session SET %s WHERE session_id=?" % (', '.join(sets))
        self.cursor.execute(query, list(kwargs.values()) + [session_id])

    @gen.coroutine
    def row_to_model(self, row):
        """Takes sqlite database session row and turns it into a dictionary.
        
        Overrides base class method to turn into an async operation.
        """
        # Retrieve kernel for session, which is now an async operation
        kernel = yield self.kernel_manager.get_kernel(row['kernel_id'])
        if kernel is None:
            # The kernel was killed or died without deleting the session.
            # We can't use delete_session here because that tries to find
            # and shut down the kernel.
            self.cursor.execute("DELETE FROM session WHERE session_id=?", 
                                (row['session_id'],))
            raise KeyError

        model = {
            'id': row['session_id'],
            'path': row['path'],
            'name': row['name'],
            'type': row['type'],
            'kernel': kernel
        }
        if row['type'] == 'notebook':  # Provide the deprecated API.
            model['notebook'] = {'path': row['path'], 'name': row['name']}

        raise gen.Return(model)

    @gen.coroutine
    def list_sessions(self):
        """Returns a list of dictionaries containing all the information from
        the session database.
        
        Overrides base class method to turn into an async operation.
        """
        c = self.cursor.execute("SELECT * FROM session")
        result = []
        # We need to use fetchall() here, because row_to_model can delete rows,
        # which messes up the cursor if we're iterating over rows.
        for row in c.fetchall():
            try:
                # This is now an async operation
                model = yield self.row_to_model(row)
                result.append(model)
            except KeyError:
                pass
        raise gen.Return(result)

    @gen.coroutine
    def delete_session(self, session_id):
        """Deletes the row in the session database with given session_id.

        Overrides base class method to turn into an async operation.
        """
        # This is now an async operation
        session = yield self.get_session(session_id=session_id)
        yield gen.maybe_future(self.kernel_manager.shutdown_kernel(session['kernel']['id']))
        self.cursor.execute("DELETE FROM session WHERE session_id=?", (session_id,))
