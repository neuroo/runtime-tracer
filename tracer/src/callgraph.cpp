/*
    Dynamic tracing and IDA integration
    by Romain Gaucher <r@rgaucher.info> - http://rgaucher.info

    Copyright (c) 2011 Romain Gaucher <r@rgaucher.info>

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/
#include <vector>
#include <string>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <boost/graph/graph_traits.hpp>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/graph_traits.hpp>
#include <boost/graph/graphviz.hpp>


#include "callgraph.h"
using namespace boost;
using namespace std;

ofstream out("graph-internal.txt");


CallGraphNodeId CallGraph::addNode(const CallGraphNode& n) {
	const CallGraphNodeId nId = getNode(n.address);
	if (nId == Graph::null_vertex()) {
		const CallGraphNodeId nId2 = add_vertex(graph);
		vertex_info[nId2] = n;
		vertexCache[n.address] = nId2;
		return nId2;
	}
	else {
		//out << "Existing vertex for address = "  << " id=" << dec << nId << endl;
	}
	return nId;
}

CallGraphNodeId CallGraph::getNode(unsigned int address) const {
	map<unsigned int, CallGraphNodeId>::const_iterator cacheIterator = vertexCache.find(address);
	if (cacheIterator != vertexCache.end())
		return cacheIterator->second;
	return Graph::null_vertex();
}

bool CallGraph::addEdgeNodeId(const CallGraphNodeId& n1, const CallGraphNodeId& n2) {
	if (n1 == Graph::null_vertex() || n2 == Graph::null_vertex())
		return false;
	pair<CallGraphEdgeId, bool> edgePair = edge(n1, n2, graph);	
	if (!edgePair.second) {
		// Need to add the edge
		pair<CallGraphEdgeId, bool> e = add_edge(n1, n2, graph);
		// out << "new edge- " << e.first << " (E=" << dec << num_edges(graph) << ")" << flush << endl;
		if (e.second) {
			edge_info[e.first].flow = 1;
		}
		return e.second;
	}
	else {
		edge_info[edgePair.first].flow += 1;
		//out << "existing edge- " << edgePair.first << " (E=" << dec << num_edges(graph) << ")" << endl;	
	}
	return edgePair.second;
}


bool CallGraph::addEdge(unsigned int a1, unsigned int a2) {
	// Get the nodes by address, then add an edge
	CallGraphNodeId n1 = getNode(a1);
	CallGraphNodeId n2 = getNode(a2);

	return addEdgeNodeId(n1, n2);
}


unsigned int CallGraph::max_cycles() const {
	unsigned int local_max = 1;
	for (map<CallGraphEdgeId, CallGraphEdge>::const_iterator iter=edge_info.begin(); iter!=edge_info.end(); ++iter) {
		if (iter->second.flow > local_max)
			local_max = iter->second.flow;
	}
	return local_max;
}