#!/usr/bin/env python

from spyne.decorator import srpc
from spyne.model.primitive import Unicode, Integer, String
from spyne.model.complex import Iterable, ComplexModel
from spyne.model.binary import File, ByteArray
from spyne.protocol.http import HttpRpc
from spyne.protocol.json import JsonDocument
from jsonp import JsonP
from spyne.service import ServiceBase
from spyne.application import Application

import binary
import standard_logging

binaries = { }

class AngrAPI(ServiceBase):
	__tns__ = "ucsb.angr.ui"

	@srpc(String, String, _returns=String)
	def load_binary(bin_name, filename):
		if bin_name in binaries:
			return "already loaded"

		binaries[bin_name] = binary.Binary(filename)
		return "success"

	@srpc(String, _returns=Iterable(String))
	def list_functions(bin_name):
		funcs = [ f.name for f in binaries[bin_name].functions().values() ]
		print funcs
		return funcs

	@srpc(String, String, String, _returns=String)
	def name_function(bin_name, func_addr, new_name):
		binaries[bin_name].functions()[func_addr].name = new_name
		return "success"

	@srpc(_returns=Iterable(String))
	def list_binaries():
		return binaries.keys()

	@classmethod
	def dispatch(cls):
		application = Application([cls], tns=cls.__tns__, in_protocol=HttpRpc(validator="soft"), out_protocol=JsonP())
		return application

if __name__ == "__main__":
	angr_interface = AngrAPI.dispatch()

	from spyne.server.twisted import TwistedWebResource
	from twisted.internet import reactor
	from twisted.web.server import Site

	angr_resource = TwistedWebResource(angr_interface)
	angr_site = Site(angr_resource)
	reactor.listenTCP(5000, angr_site)
	reactor.run()
