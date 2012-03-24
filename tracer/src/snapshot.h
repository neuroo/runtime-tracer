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
#ifndef __SNAPSHOT_H
#define __SNAPSHOT_H

#include "config.h"

// Hold the memory snapshot per register:
//   eax -> {0x41414141, 0xCC9090909090...}
struct MemorySnapshot {
    Database *database;
    map<REG, pair<ADDRINT, string *> > snapshot;

    MemorySnapshot(Database *db) {
        database = db;
    }

    pair<ADDRINT, string *> operator[](REG reg) {
        if (snapshot.find(reg) != snapshot.end())
            return snapshot[reg];
        return make_pair((ADDRINT)0x0, &EMPTY_STRING);
    }

    inline bool dont_store_memory(ADDRINT value, ADDRINT min_img_addr, ADDRINT max_img_addr) const {
        if (value < 0xFFFF) return true;
        if (value >= min_img_addr && value <= max_img_addr) return true;
        return false;
    }

    inline void load_reg_value(REG reg_id, ADDRINT addr, TraceId traceid, const CONTEXT *ctxt, ADDRINT min_img_addr, ADDRINT max_img_addr) {
        char value[size_capture];
        ADDRINT v = 0x0;

        v = PIN_GetContextReg(ctxt, reg_id);
        
        if (!dont_store_memory(v, min_img_addr, max_img_addr)) {
            PIN_SafeCopy(&value, (void *)PIN_GetContextReg(ctxt, reg_id), sizeof(value));
            //snapshot[reg_id] = make_pair(v, new string(value));
            //skip_reg_str = false;
            database->snapshot(addr, traceid, reg_id, v, value, false);
        }
        else  {
            //snapshot[reg_id] = make_pair(v, new string(" "));
            database->snapshot(addr, traceid, reg_id, v, " ", true);
        }
    }


    // Only capture eax/ebx for debugging purpose
    void take(ADDRINT addr, TraceId traceid, const CONTEXT *ctxt, ADDRINT min_img_addr, ADDRINT max_img_addr) {
        if (!ctxt) {
#ifdef MY_DEBUG
            probelog << "take() has NULL ptr for contxt." << endl << flush;
#endif
            return;
        }

#ifndef NO_DATABASE
        database->instr(addr, traceid);
#endif

        load_reg_value(REG_EAX, addr, traceid, ctxt, min_img_addr, max_img_addr);
        load_reg_value(REG_EBX, addr, traceid, ctxt, min_img_addr, max_img_addr);
        load_reg_value(REG_ECX, addr, traceid, ctxt, min_img_addr, max_img_addr);
        load_reg_value(REG_EDX, addr, traceid, ctxt, min_img_addr, max_img_addr);
        load_reg_value(REG_ESI, addr, traceid, ctxt, min_img_addr, max_img_addr);
        load_reg_value(REG_EDI, addr, traceid, ctxt, min_img_addr, max_img_addr);
        load_reg_value(REG_ESP, addr, traceid, ctxt, min_img_addr, max_img_addr);
    }

    ~MemorySnapshot() {
        for(map<REG, pair<ADDRINT, string *> >::iterator iter=snapshot.begin(); iter!=snapshot.end(); ++iter) 
            delete (iter->second).second;
    }

};

#endif