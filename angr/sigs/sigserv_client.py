from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request

from angr.errors import AngrRuntimeError

_l = logging.getLogger(name=__name__)


# The version of the sigserv REST protocol this client implements. sigserv exports the same number as
# sigserv.PROTOCOL_VERSION and reports it from GET /version; it is bumped whenever the shape of a request or a
# response changes in a way an older peer cannot handle, so the two must match exactly.
SIGSERV_PROTOCOL_VERSION = 1

DEFAULT_TIMEOUT = 30.0

# how much of an error response body is quoted back in an exception message
MAX_ERROR_DETAIL_LEN = 200


class SigservClient:
    """
    A client for a remote sigserv signature suggestion server, talking to it over its HTTP REST API.

    It offers the same query interface as ``sigserv.SigServer``, the in-process Python binding of sigserv, so
    :class:`SuggestSignatureAnalysis` can use the two interchangeably. Unlike the binding, it does not require the
    sigserv extension module to be installed: only the standard library is used.

    On top of the shared interface it provides :meth:`fetch_signature`, which downloads the .sig file of a
    suggestion. A remote consumer needs it because the ``sig_path`` of a suggestion is a path on the server.

    Unless ``check_protocol_version`` is disabled, the protocol version of the server is fetched and compared
    against :data:`SIGSERV_PROTOCOL_VERSION` when the client is created; a mismatch raises immediately instead of
    failing later in a confusing way.
    """

    def __init__(self, url: str, timeout: float = DEFAULT_TIMEOUT, check_protocol_version: bool = True):
        """
        :param url:                     Base URL of the sigserv server, e.g. "http://localhost:8080". A missing
                                        scheme is assumed to be http.
        :param timeout:                 Timeout of each request, in seconds.
        :param check_protocol_version:  Whether to verify that the server speaks the protocol version this client
                                        implements.
        """
        url = url.strip()
        if "://" not in url:
            url = "http://" + url
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.protocol_version: int | None = None
        self.server_version: str | None = None

        if check_protocol_version:
            self.check_protocol_version()

    def __repr__(self):
        return f"<SigservClient {self.url}>"

    #
    # Endpoints
    #

    def version(self) -> dict:
        """
        Query the version information of the server.

        :return:    A dict with keys protocol_version and server_version.
        """
        return self._get_json("/version")

    def check_protocol_version(self) -> int:
        """
        Verify that the server speaks the protocol version this client implements, and remember what it reported.

        :return:    The protocol version of the server.
        """
        info = self.version()
        try:
            version = int(info["protocol_version"])
        except (KeyError, TypeError, ValueError) as ex:
            raise AngrRuntimeError(
                f"The server at {self.url} did not report a sigserv protocol version; it is probably not a sigserv "
                f"server."
            ) from ex

        self.protocol_version = version
        self.server_version = info.get("server_version")

        if version != SIGSERV_PROTOCOL_VERSION:
            raise AngrRuntimeError(
                f"The sigserv server at {self.url} speaks protocol version {version}, but angr speaks protocol "
                f"version {SIGSERV_PROTOCOL_VERSION}. Please upgrade whichever of the two is older."
            )
        return version

    def query(
        self,
        strings: list[str] | None = None,
        integers: list[int] | None = None,
        arch: str | None = None,
        platform: str | None = None,
    ) -> list[dict]:
        """
        Query for signatures matching the given constants, best-scored first.

        :param strings:     String constants to match.
        :param integers:    Integer constants to match.
        :param arch:        Optional architecture filter.
        :param platform:    Optional platform filter.
        :return:            A list of dicts with keys library_name, sig_path, score, matched_strings,
                            matched_integers, and meta.
        """
        body = {
            "strings": list(strings) if strings else [],
            "integers": list(integers) if integers else [],
            "arch": arch,
            "platform": platform,
        }
        result = self._post_json("/query", body)
        if not isinstance(result, list):
            raise AngrRuntimeError(f"The sigserv server at {self.url} returned a malformed response to a query.")
        return result

    def libraries(self) -> list[dict]:
        """
        List all libraries known to the server, with their metadata.
        """
        return self._get_json("/libraries")

    def library_count(self) -> int:
        """
        The number of libraries known to the server.
        """
        return len(self.libraries())

    def library_names(self) -> list[str]:
        """
        The names of all libraries known to the server.
        """
        return [lib["name"] for lib in self.libraries()]

    def fetch_signature(
        self, library_name: str, dest_dir: str, arch: str | None = None, platform: str | None = None
    ) -> str:
        """
        Download the .sig file of a library into a local directory.

        :param library_name:    Name of the library, i.e. the library_name of a suggestion.
        :param dest_dir:        Directory to write the .sig file into.
        :param arch:            Optional architecture, to disambiguate between signatures sharing a name.
        :param platform:        Optional platform, to disambiguate between signatures sharing a name.
        :return:                Path of the downloaded .sig file.
        """
        path = "/signature/" + urllib.parse.quote(library_name, safe="")
        params = [(key, value) for key, value in (("arch", arch), ("platform", platform)) if value]
        if params:
            path += "?" + urllib.parse.urlencode(params)
        data = self._request(path)

        # the file name is derived from a server-provided name; keep only what is safe in a path component
        filename = "".join(ch if ch.isalnum() or ch in "._-+" else "_" for ch in library_name)
        dest_path = os.path.join(dest_dir, filename + ".sig")
        with open(dest_path, "wb") as f:
            f.write(data)
        _l.debug("Downloaded signature %s from %s to %s.", library_name, self.url, dest_path)
        return dest_path

    #
    # Private methods
    #

    def _request(self, path: str, body: bytes | None = None) -> bytes:
        url = self.url + path
        req = urllib.request.Request(url, data=body, method="GET" if body is None else "POST")
        if body is not None:
            req.add_header("Content-Type", "application/json")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as ex:
            detail = ""
            try:
                message = ex.read().decode("utf-8", errors="replace").strip()
                if message:
                    detail = ": " + message[:MAX_ERROR_DETAIL_LEN]
            except OSError:
                pass
            raise AngrRuntimeError(
                f"The sigserv request to {url} failed with HTTP {ex.code} {ex.reason}{detail}"
            ) from ex
        except (urllib.error.URLError, TimeoutError, OSError) as ex:
            raise AngrRuntimeError(f"Cannot reach the sigserv server at {url}: {ex}") from ex

    def _get_json(self, path: str):
        return self._decode_json(self._request(path), path)

    def _post_json(self, path: str, body):
        return self._decode_json(self._request(path, json.dumps(body).encode("utf-8")), path)

    def _decode_json(self, data: bytes, path: str):
        try:
            return json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError) as ex:
            raise AngrRuntimeError(f"The sigserv server at {self.url} returned a malformed response to {path}.") from ex
