import networkx
from collections import defaultdict

import logging

l = logging.getLogger(name="angr.cdg")

# Control dependency graph

class TempNode(object):
	def __init__(self, label):
		self._label = label

	def __repr__(self):
		return self._label

class CDG(object):
	def __init__(self, binary, project, cfg, initial_state):
		self._binary = binary
		self._project = project
		self._cfg = cfg
		self._initial_state = initial_state

		self._ancestor = None
		self._semi = None
		self._post_dom = None

		self._cdg = None

	def construct(self):
		# Construct post-dominator tree
		self.pd_construct()
		l.debug("Post dominators: \n%s", self._post_dom)

		self._cdg = networkx.DiGraph()
		# For each node (A,B), traverse back from B until the parent node of A,
		# and label them as control dependent on A
		for a in self._cfg.nodes():
			successors = self._cfg.successors(a)
			for b in successors:
				if self._post_dom[a] != b:
					# B doesn't post-dominate A
					tmp = b
					while tmp != self._post_dom[a]:
						self._cdg.add_edge(a, tmp) # tmp is dependent on A
						if b in self._post_dom:
							tmp = self._post_dom[tmp]
						else:
							break

		print self._cdg.edges()

	def pd_construct(self):
		normalized_graph, vertices, parent = self.pd_normalize_graph()

		bucket = defaultdict(set)
		dom = [None] * (len(vertices))
		self._ancestor = [None] * (len(vertices) + 1)

		range_ = range(2, len(vertices))
		range_.reverse()
		for i in range_:
			w = vertices[i]
			predecessors = normalized_graph.predecessors(w)
			for v in predecessors:
				u = self.pd_eval(v)
				if self._semi[u.index].index < self._semi[w.index].index:
					self._semi[w.index] = self._semi[u.index]
			bucket[vertices[self._semi[w.index].index].index].add(w)
			self.pd_link(parent[w], w)
			for v in bucket[parent[w].index]:
				u = self.pd_eval(v)
				if self._semi[u.index].index < self._semi[v.index].index:
					dom[v.index] = u
				else:
					dom[v.index] = parent[w]
			bucket[parent[w].index].clear()

		for i in range(2, len(vertices)):
			w = vertices[i]
			if dom[w.index] != vertices[self._semi[w.index].index]:
				dom[w.index] = dom[dom[w.index].index]

		self._post_dom = {}
		for i in range(1, len(vertices)):
			self._post_dom[vertices[i]] = dom[i]

	def pd_normalize_graph(self):
		# We want to reverse the CFG, and label each node according to its
		# order in a DFS
		graph = networkx.DiGraph()

		n = None
		for nn in self._cfg.nodes():
			if nn._label == "1":
				n = nn
				break
		queue = [n]
		start_node = TempNode("start_node")
		traversed_nodes = set()
		while len(queue) > 0:
			node = queue.pop()
			traversed_nodes.add(node)
			successors = self._cfg.successors(node)
			if len(successors) == 0:
				# Add an edge between this node and our start node
				graph.add_edge(start_node, node)
			for s in successors:
				graph.add_edge(s, node) # Reversed
				if s not in traversed_nodes:
					queue.append(s)

		# Add a start node and an end node
		graph.add_edge(n, TempNode("end_node"))
		# TODO: Add the start node

		# DFS from the start node
		stack = [start_node]
		counter = 1
		scanned_nodes = set()
		vertices = ["placeholder"]
		parent = {}
		while len(stack) > 0:
			node = stack.pop()
			node.index = counter
			scanned_nodes.add(node)
			vertices.append(node)
			counter += 1
			successors = graph.successors(node)
			for s in successors:
				if s not in scanned_nodes:
					stack.append(s)
					parent[s] = node
					scanned_nodes.add(s)
		self._semi = vertices[::]
		self._label = vertices[::]

		return (graph, vertices, parent)

	def pd_link(self, v, w):
		self._ancestor[w.index] = v

	def pd_eval(self, v):
		if self._ancestor[v.index] == None:
			return v
		else:
			self.pd_compress(v)
			return self._label[v.index]

	def pd_compress(self, v):
		if self._ancestor[self._ancestor[v.index].index] != None:
			self.pd_compress(self._ancestor[v.index])
			if self._semi[self._label[self._ancestor[v.index].index].index].index < self._semi[self._label[v.index].index].index:
				self._label[v.index] = self._label[self._ancestor[v.index].index]
			self._ancestor[v.index] = self._ancestor[self._ancestor[v.index].index]
