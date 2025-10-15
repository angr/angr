from __future__ import annotations

from collections import defaultdict
from enum import Enum

from angr.utils.strings import decode_utf16_string
from angr.knowledge_plugins.cfg import MemoryDataSort
from .base import InsightBase


class AppFeature(Enum):
    AUTH = 1
    WEBSERVER = 2
    CRYPTO = 3
    COMPRESSION = 4
    MMIO = 5
    LOGGING = 6
    WIFI = 7
    USB = 8
    UART = 9


FEATURE_STRINGS = {
    AppFeature.AUTH: {
        "auth",
        "login",
        "log in",
        "sign in",
        "signin",
        "password",
        "username",
    },
    AppFeature.WEBSERVER: {
        "http",
        "https",
        "www",
        "html",
        "css",
        "js",
        "javascript",
        "xml",
        "json",
        "request",
        "response",
        "cookie",
        "session",
        "url",
        "uri",
        "host",
        "server",
        "client",
        "port",
        "get",
        "post",
        "put",
    },
    AppFeature.CRYPTO: {
        "crypto",
        "encrypt",
        "decrypt",
        "cipher",
        "aes",
        "rsa",
        "md5",
        "sha1",
        "sha256",
        "hash",
        "key",
        "signature",
        "cert",
        "ssl",
        "tls",
        "hmac",
        "pbkdf2",
        "scrypt",
        "argon2",
    },
    AppFeature.COMPRESSION: {
        "compress",
        "decompress",
        "zip",
        "gzip",
        "deflate",
        "inflate",
        "bzip2",
        "lzma",
        "xz",
        "tar",
        "archive",
        "unarchive",
        "7z",
        "rar",
    },
    AppFeature.USB: {
        "usb",
    },
    AppFeature.UART: {
        "uart",
    },
    AppFeature.MMIO: {
        "mmio",
        "ioport",
        "ioread",
        "iowrite",
        "memread",
        "memwrite",
        "peripheral",
        "bus",
        "pci",
        "spi",
        "i2c",
        "gpio",
    },
    AppFeature.LOGGING: {
        "failed",
        "error",
    },
    AppFeature.WIFI: {
        "wifi",
        "wlan",
        "ssid",
        "bssid",
        "mac address",
        "access point",
        "ap",
        "station",
        "sta",
        "wpa",
        "wpa2",
        "wpa3",
        "wep",
        "psk",
        "eap",
        "peap",
        "eap-tls",
        "eap-ttls",
        "eap-aka",
    },
}

STRING_TO_FEATURE = {}


def _fill_string_to_feature():
    for feature, strings in FEATURE_STRINGS.items():
        for s in strings:
            STRING_TO_FEATURE[s] = feature


class FeaturesInsight(InsightBase):
    """
    Find interesting semantic features in a binary and report the related strings, constants, and functions.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.result = []

        self.analyze()

    def analyze(self):
        # scans all the strings in the binary to find features
        if not STRING_TO_FEATURE:
            _fill_string_to_feature()

        # find features
        self.feature_to_evidence = self._candidate_features()
        # map feature evidence to functions
        self.feature_to_funcs = self._map_feature_to_functions(self.feature_to_evidence)

    def _candidate_features(self):

        feature_to_evidence = defaultdict(list)

        cfg = self.kb.cfgs.get_most_accurate()
        if cfg is None:
            return None
        for _addr, md in cfg.memory_data.items():
            if md.sort == MemoryDataSort.String:
                s = md.content.decode("ascii")
            elif md.sort == MemoryDataSort.UnicodeString:
                try:
                    s = md.content.decode("utf-8")
                except UnicodeDecodeError:
                    s = decode_utf16_string(md.content)
            else:
                continue
            s_lower = s.lower()
            for feature_str, feature in STRING_TO_FEATURE.items():
                if feature_str in s_lower:
                    feature_to_evidence[feature].append((md, s))

        return feature_to_evidence

    def _map_feature_to_functions(self, feature_to_evidence):
        feature_to_funcs = defaultdict(set)

        cfg = self.kb.cfgs.get_most_accurate()
        if cfg is None:
            return feature_to_funcs

        xrefs = self.kb.xrefs

        for feature, evd_list in feature_to_evidence.items():
            for md, _ in evd_list:
                # where is it referenced?
                refs = xrefs.get_xrefs_by_dst(md.addr)
                for ref in refs:
                    func = self.kb.functions.floor_func(ref.block_addr)
                    if func is not None:
                        feature_to_funcs[feature].add(func.addr)

        return feature_to_funcs


from angr.analyses import AnalysesHub

AnalysesHub.register_default("Insight_Features", FeaturesInsight)
