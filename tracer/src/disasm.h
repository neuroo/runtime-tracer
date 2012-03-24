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
#ifndef __DISASM_H
#define __DISASM_H

// Hold the disassembly of the call/jump instruction
struct DisasmRegistry {
    Database *database;
    map<ADDRINT, string *> reg;

    string& operator[](ADDRINT addr) {
        if (reg.find(addr) != reg.end())
            return *(reg[addr]);
        return EMPTY_STRING;
    }

    void setDatabase(Database* db) {
        database = db;
    }

    void setDisasm(ADDRINT addr, const string& disasm) {
        // Already went here...
        if (reg.find(addr) != reg.end())
            return;
        reg[addr] = new string(disasm);
#ifndef NO_DATABASE
        database->disasm(addr, disasm);
#endif
    }

    ~DisasmRegistry() {
        for(map<ADDRINT, string *>::iterator iter=reg.begin(); iter!=reg.end(); ++iter) 
            delete iter->second;
    }
};


#endif