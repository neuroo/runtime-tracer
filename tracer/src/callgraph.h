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
#ifndef CALLGRAPH_H
#define CALLGRAPH_H

#include <boost/config.hpp>
#include <string>
#include <vector>
#include <utility>
#include <algorithm>
#include <fstream>
#include <boost/graph/graph_traits.hpp>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/adjacency_matrix.hpp>
#include <boost/graph/graph_traits.hpp>
#include <boost/graph/graphviz.hpp>

struct CallGraphNode {
	unsigned int address;
	
	CallGraphNode(unsigned int a=0)
	 : address(a)
	{}
};

struct CallGraphEdge {
	unsigned int flow;
};

typedef boost::adjacency_list<boost::vecS, boost::setS, boost::directedS> Graph;
//typedef boost::adjacency_matrix<boost::directedS> Graph;
typedef boost::graph_traits<Graph>::vertex_descriptor CallGraphNodeId;
typedef boost::graph_traits<Graph>::edge_descriptor   CallGraphEdgeId;
typedef boost::graph_traits<Graph>::vertex_iterator   CallGraphNodeIterator;


class CallGraph {
	std::map<unsigned int, CallGraphNodeId> vertexCache;
	std::map<CallGraphNodeId, CallGraphNode> vertex_info;
	std::map<CallGraphEdgeId, CallGraphEdge> edge_info;
	
	Graph graph;
	
public:
	CallGraph() {};	
	CallGraph(const CallGraph& c) {
		*this = c;
	}
	CallGraph& operator=(const CallGraph& c) {
		vertexCache = c.vertexCache;
		vertex_info = c.vertex_info;
		edge_info = c.edge_info;
		graph = c.graph;
		return *this;
	}

	CallGraphNodeId getNode(unsigned int address) const;
	CallGraphNodeId addNode(const CallGraphNode& n);
	
	bool addEdgeNodeId(const CallGraphNodeId&, const CallGraphNodeId&);
	bool addEdge(unsigned int, unsigned int);
	
	unsigned int count_nodes() const {
		return num_vertices(graph);
	}
	
	unsigned int count_edges() const {
		return num_edges(graph);
	}

	unsigned int max_cycles() const;

	void write(const std::string& fname);

	~CallGraph(){}
};

#endif
