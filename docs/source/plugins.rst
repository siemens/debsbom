Plugins
=======

``debsbom`` provides plugin capability for select functionality.

Resolver Plugin
---------------

In the ``download`` command ``debsbom`` is downloading packages described by an SBOM. For this it needs to resolve from the package to a download location. What resolver to use can be controlled by the ``--resolver`` flag. ``debsbom`` per default provides a resolver for the Debian snapshot mirror (snapshot.debian.org).

Builders of custom Debian distributions might have different repositories where packages can be downloaded from. Some of these solutions might not be publicly available, or its implementation not relevant for the general public for some other reason. In these cases code for a resolver for these repositories should not land in ``debsbom`` proper, but we still want to give the option to use it as a fully integrated part of ``debsbom``.

A resolver plugin provides an additional choice for the ``--resolver`` option, which can be selected in the CLI once the plugin is loaded.

Implementing a Resolver Plugin
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Plugin discovery happens by entry points. ``debsbom`` specifically looks for the ``debsbom.download.resolver`` entry point. The name of the entry point is the name of the resolver, and its content is a setup function for a resolver. The signature of the setup function looks like this:

.. code-block:: python

    from request import Session
    from debsbom.download.plugin import Resolver

    def setup_resolver(session: Session) -> Resolver
        pass

The passed in ``request.Session`` is later used by ``debsbom`` to download the packages. It is not required to use it, but consider reusing it instead of opening a new session.

The resolver itself needs to inherit from the ``Resolver`` class. See the documentation here: :ref:`package-resolving-label`. The important part here is implementing the ``resolve`` function, which takes a package representation and returns a list of ``RemoteFile``, the locations from where files associated with the package can be downloaded. A minimal implementation could look like this:

.. code-block:: python

    from request import Session
    from debsbom.download.plugin import Package, RemoteFile, Resolver, ResolveError

    class MyResolver(Resolver):

        def resolve(self, pkg: Package) -> list[RemoteFile]:
            try:
                my_remotefile = get_remotefile(pkg)
            except Exception as e:
                raise ResolveError
            return my_remotefile

All functionality required for implementing a plugin is exposed in the ``debsbom.download.plugin`` module.

A full example implementation can be found in the `debsbom-plugin-examples <https://github.com/Urist-McGit/debsbom-plugin-examples>`_ repository, which is kept up to date for all releases.
