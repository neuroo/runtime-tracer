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
#ifndef __MEMORYSTORE_H
#define __MEMORYSTORE_H

#include "snapshot.h"
#include <vector>

typedef map<ADDRINT, TraceId> LastTraceStore;
typedef map<TraceId, MemorySnapshot *> TraceMemorySlice;
typedef map<ADDRINT, TraceMemorySlice *> TraceMemoryStore;


struct MemoryStore {

    Database *database;
    TraceMemoryStore store;
    LastTraceStore trace;

    void setDatabase(Database* db) {
        database = db;
    }

    // after = 0 or 1
    void setSlice(ADDRINT addr, THREADID threadid, const CONTEXT* ctxt, ADDRINT min_img_addr, ADDRINT max_img_addr) {
        TraceMemorySlice *tms = 0;
        TraceMemoryStore::iterator pos = store.find(addr);
        TraceId last_trace = 0;

        bool empty_slice = false;
        if (pos != store.end()) {
            tms = pos->second;
            last_trace = trace[addr];
        }
        else {
            // Need to create a new tms
            tms = new TraceMemorySlice();
            empty_slice = true;
        }

        ++last_trace;

        store[addr] = tms;
        trace[addr] = last_trace;
        TraceMemorySlice& tms_ref = *tms;

        tms_ref[last_trace] = new MemorySnapshot(database);
        if (tms_ref[last_trace])
            tms_ref[last_trace]->take(addr, last_trace, ctxt, min_img_addr, max_img_addr);
    }

    ~MemoryStore() {
        for (TraceMemoryStore::iterator iter=store.begin(); iter!=store.end(); ++iter)
            delete iter->second;
    }

};

#endif