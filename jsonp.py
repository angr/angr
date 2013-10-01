#!/usr/bint/env python

from spyne.protocol.json import JsonDocument
from spyne.protocol.dictdoc import HierDictDocument
from itertools import chain

class JsonP(JsonDocument):
	"""The JsonP protocol puts the reponse document inside a designated
	javascript function call. The input protocol is identical to the
	JsonDocument protocol.

	:param callback_name: The name of the function call that will wrapp all
		response documents.

	For other arguents, see :class:`spyne.protocol.json.JsonDocument`.
	"""

	type = set(HierDictDocument.type)
	type.add('jsonp')

	def __init__(self, *args, **kwargs):
		super(JsonP, self).__init__(*args, **kwargs)

	def create_out_string(self, ctx):
		super(JsonP, self).create_out_string(ctx)

		if "callback" in ctx.in_body_doc:
			ctx.out_string = chain(
					[ctx.in_body_doc["callback"][0], '('],
						ctx.out_string,
					[');'],
				)
