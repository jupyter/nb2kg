# Jupyter Notebook Extension to Kernel Gateway (nb2kg)

## Overview

**nb2kg** is a [Jupyter Notebook](https://github.com/jupyter/notebook) [server extension](http://jupyter-notebook.readthedocs.io/en/latest/extending/handlers.html#writing-a-notebook-server-extension)
that enables the Notebook server to use remote kernels hosted by a Jupyter "Gateway" (i.e., [Kernel Gateway](https://github.com/jupyter/kernel_gateway) or [Enterprise Gateway](https://github.com/jupyter-incubator/enterprise_gateway)).

The extension may be useful in cases where you want a local Notebook server to connect to a kernel that executes code on a compute cluster in the cloud, perhaps near big data (e.g., the kernel is a driver program running on an [Apache Spark](http://spark.apache.org/) cluster).

The extension overrides the `/api/kernels/*` and `/api/kernelspecs` request handlers of the Notebook server, and proxies all requests for these resources to the Gateway.  When you enable the extension, **all** kernels run on the configured Gateway instead of on the Notebook server host (although kernels can also be remoted from Enterprise Gateway servers).

![Jupyter remote kernels](https://github.com/jupyter-incubator/nb2kg/blob/master/deploy.png)

The **nb2kg** extension communicates with the Gateway using standard HTTP and web socket protocols.  This differs from other remote kernel projects, such as [remote_ikernel](https://pypi.python.org/pypi/remote_ikernel) and [rk](https://github.com/korniichuk/rk), which rely on SSH or other mechanisms to communicate with kernels.

The extension requires Jupyter Notebook 4.2 or later, with support for server extensions.

```
jupyter serverextension list
```

## Install

To install the _released_ **nb2kg** extension in an existing Notebook server environment:

```
pip install nb2kg
```

To install the _latest_ **nb2kg** extension in an existing Notebook server environment:
```
pip install "git+https://github.com/jupyter-incubator/nb2kg.git#egg=nb2kg"
```

Once the package has been installed, it must then be registered as an extension:
```
jupyter serverextension enable --py nb2kg --sys-prefix
```
## Run Notebook server

When you run the Notebook server with the **nb2kg** extension enabled, you must set the `KG_URL` environment variable to the URL of the kernel or enterprise gateway _and_ you must override the default kernel, kernel spec, and session managers:

```
export KG_URL=http://kg-host:port
jupyter notebook \
  --NotebookApp.session_manager_class=nb2kg.managers.SessionManager \
  --NotebookApp.kernel_manager_class=nb2kg.managers.RemoteKernelManager \
  --NotebookApp.kernel_spec_manager_class=nb2kg.managers.RemoteKernelSpecManager 
```

## Try It

You can use the included Dockerfiles to build and run a Notebook server with **nb2kg** enabled and a Kernel Gateway in separate Docker containers.

```
git clone https://github.com/jupyter-incubator/nb2kg.git
cd nb2kg
```

Build Notebook server and Kernel Gateway Docker images.

```
docker-compose build
```

Run the containers.

```
docker-compose up -d
```

Launch a web browser to the Notebook server.  On Mac OS X:

```
open http://my.docker.host:9888
```

## Develop

If you want to modify the extension, you can develop it within your Jupyter Notebook dev environment.

Clone this repo.

```
git clone https://github.com/jupyter-incubator/nb2kg.git
cd nb2kg
```

Install and enable the extension.

```
make install
```

Run the Jupyter Notebook server.

```
make dev
```

## Uninstall

To uninstall the **nb2kg** extension:

```
jupyter serverextension disable --py nb2kg --sys-prefix
pip uninstall -y nb2kg
```

## Caveats

* When you enable the extension, **all** kernels run on (are managed by) the configured Gateway, instead of on the Notebook server host.  The extension does not support local kernels.
* When you enable the extension, notebooks and other files reside on the Notebook server, which means that remote kernels may not have access to them.
* If your kernel gateway instance is using a self-signed certificate in your development environment, you can turn off certificate validation by setting `VALIDATE_KG_CERT=no` in your environment before starting the notebook server.
