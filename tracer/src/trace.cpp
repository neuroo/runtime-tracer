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
#include "pin.H"
#include <map>
#include <iostream>

#include "config.h"
#include "trace.h"
#ifndef NO_CALLGRAPH
    #include "callgraph.h"
#endif
using namespace std;


void TraceHandler::addCallee(THREADID threadid, ADDRINT addr) {
    ADDRINT last_addr = callerList[threadid];

#ifndef NO_DATABASE
    database.trace(threadid, last_addr, addr);
#endif

    callerList[threadid] = addr;

#ifndef NO_CALLGRAPH
    map<THREADID, CallGraph *>::iterator callGraphPos = callGraphs.find(threadid);
    if (callGraphPos == callGraphs.end()) {
        pair<map<THREADID, CallGraph *>::iterator, bool> p = callGraphs.insert(pair<THREADID, CallGraph *>(threadid, new CallGraph()));
        callGraphPos = p.first;
    }

    CallGraph& cg = *(callGraphPos->second);
    CallGraphNodeId prev = cg.addNode(last_addr);
    CallGraphNodeId cur = cg.addNode(addr);

    cg.addEdgeNodeId(prev, cur);
#endif


}