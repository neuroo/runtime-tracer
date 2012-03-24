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
#ifndef __TRACE_H
#define __TRACE_H

#include "pin.H"
#include <map>

#include "config.h"
#include "database.h"
#ifndef NO_CALLGRAPH
    #include "callgraph.h"
#endif
#include "disasm.h"
#include "memorystore.h"


// Generic trace handler
// Contains and correlate the entire data model
struct TraceHandler {
    Database database;
    ADDRINT default_addr;
    DisasmRegistry disasm;
    MemoryStore mem;

    // MemoryMap memmap;

    ADDRINT callerList[0xff]; // threadid -> addrint

#ifndef NO_CALLGRAPH
    std::map<THREADID, CallGraph *> callGraphs;
#endif

    TraceHandler()
    : default_addr(0x0) {
        disasm.setDatabase(&database);
        mem.setDatabase(&database);
    }

#ifndef NO_CALLGRAPH
    inline CallGraph * getCallGraph(const THREADID thread_id) {
    	if (callGraphs.find(thread_id) == callGraphs.end()) {
    		callGraphs[thread_id] = new CallGraph();
    	}
    	return callGraphs[thread_id];
    }
#endif

    void addCallee(THREADID threadid, ADDRINT addr);

    inline void save() {
        database.save();
    }

    void stats() {
#ifndef NO_CALLGRAPH
        probelog << "################### Graph stats #######################" << endl << flush;
        for (std::map<THREADID, CallGraph *>::iterator iter=callGraphs.begin(); iter!=callGraphs.end(); ++iter) {
            probelog << "ThreadID=" << dec << iter->first << endl << flush;
            probelog << "Nodes: " << iter->second->count_nodes() << endl << flush;
            probelog << "Edges: " << iter->second->count_edges() << endl << flush;
            probelog << "Max cycles: " << iter->second->max_cycles() << endl << flush;
        }
#endif
    }

    ~TraceHandler() {
#ifndef NO_CALLGRAPH
    	for (std::map<THREADID, CallGraph *>::iterator iter=callGraphs.begin(); iter!=callGraphs.end(); ++iter) {
            delete iter->second;
        }
#endif
    }

private:
private:
    TraceHandler(const TraceHandler& t) {}
    TraceHandler& operator=(const TraceHandler& t) {
        return *this;
    }

};

#endif