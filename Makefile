
.PHONY: install uninstall dev clean check-env bdist sdist release
.DEFAULT_GOAL=dev

install:
	pip install -e . --user
	jupyter serverextension enable --py nb2kg --sys-prefix

uninstall:
	jupyter serverextension disable --py nb2kg --sys-prefix 2&>/dev/null || true
	pip uninstall -y nb2kg || true

check-env:
	@test -n "$(KG_URL)" || echo "Must set KG_URL to Kernel Gateway URL"; exit 1

dev: NB_OPTS=--NotebookApp.session_manager_class=nb2kg.managers.SessionManager \
	--NotebookApp.kernel_manager_class=nb2kg.managers.RemoteKernelManager \
	--NotebookApp.kernel_spec_manager_class=nb2kg.managers.RemoteKernelSpecManager 
dev: check-env
	jupyter notebook \
		--no-browser \
		--ip=0.0.0.0 \
		--log-level=DEBUG \
		$(NB_OPTS)

clean: ## Make a clean source tree
	rm -rf dist
	rm -rf build
	rm -rf *.egg-info

bdist: ## Make a dist/*.whl binary distribution
	python setup.py bdist_wheel $(POST_SDIST) \
		&& rm -rf *.egg-info

sdist: ## Make a dist/*.tar.gz source distribution
	python setup.py sdist $(POST_SDIST) \
		&& rm -rf *.egg-info

release: POST_SDIST=upload
release: bdist sdist ## Make a wheel + source release on PyPI

