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
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <stdio.h>
#include <ctime>
#include <map>
#include <list>
#include <ctime>
#include "pin.H"


#include "config.h"
#include "database.h"
#ifndef NO_CALLGRAPH
    #include "callgraph.h"
#endif
#include "trace.h"
using namespace std;

typedef BOOL (* FPTR)(INS);

static TraceHandler trace_handler;
static TraceId trace_id = 0;
static unsigned long routine_call = 0;

// Options for the pintool
bool imageNameProvided = false;
bool traceInsideDLLs = false;
bool traceCallOnly = false;
bool traceEachBBL = false;
bool traceEachINS = false;
ADDRINT start_address = 0x6E200000;//0x400000;
ADDRINT end_address = 0x6E2fffff; //0xFFFFFF;
KNOB<string> KnobImageName(KNOB_MODE_WRITEONCE, "pintool", "i", "", "specify image name");
KNOB<string> KnobIncludeDLLs(KNOB_MODE_WRITEONCE, "pintool", "d", "false", "trace inside dynamic libraries");
KNOB<string> KnobAddressStart(KNOB_MODE_WRITEONCE, "pintool", "s", "0x6E200000", "first tracing address");
KNOB<string> KnobAddressEnd(KNOB_MODE_WRITEONCE, "pintool", "e", "0x6E2fffff", "last tracing address");
KNOB<string> KnobTraceCalls(KNOB_MODE_WRITEONCE, "pintool", "c", "true", "trace only calls");
KNOB<string> KnobTraceBBLs(KNOB_MODE_WRITEONCE, "pintool", "b", "false", "trace each branch (bbl, call, etc.)");
KNOB<string> KnobTraceINSs(KNOB_MODE_WRITEONCE, "pintool", "n", "false", "trace each instruction");


void replace(string& where, const string& what, const string& by) {
    for (string::size_type i = where.find(what); i != string::npos; i = where.find(what, i + by.size()))
        where.replace(i, what.size(), by);
}

string no_0x(const string& str) {
    string nstr(str);
    replace(nstr, " ", "");
    replace(nstr, "0x", "");
    return nstr;
}

// str(0xbad) -> int(0xbad)
ADDRINT string_to16(const string& address) {
    ADDRINT x;   
    stringstream ss;
    ss << hex << no_0x(address);
    ss >> x;
    return x;
}

BOOL True_INS(INS ins) {
    return true;
}

// Generic taken branch instruction callback.
// We only add stuff to the model
void InsBranchTaken(ADDRINT ins_ptr, ADDRINT min_img_addr, ADDRINT max_img_addr, THREADID threadid, const CONTEXT *ctxt) {
    trace_handler.mem.setSlice(ins_ptr, threadid, ctxt, min_img_addr, max_img_addr);

    trace_handler.addCallee(threadid, ins_ptr);

}

// Trace every call instruction
void TraceHandler_func(TRACE trace, VOID *v) {
    RTN rtn = TRACE_Rtn(trace);

    if (!RTN_Valid(rtn)) {
#ifdef MY_DEBUG
        probelog << "Invalid routine" << endl << flush;
#endif
        return;        
    }
    else {
        IMG img = SEC_Img(RTN_Sec(TRACE_Rtn(trace)));
        const string img_name = IMG_Name(img);

        if ((!traceInsideDLLs && IMG_Type(img) == IMG_TYPE_SHAREDLIB)
        ||  (imageNameProvided && img_name.find(KnobImageName.Value()) == string::npos)) {
#ifdef MY_DEBUG
            probelog << "Ignored ImageName: " << img_name << endl << flush;
#endif
            return;
        }

        ADDRINT rtn_address = 0;
        const char *rtn_name = 0;
        int rtn_num = 0;
        FPTR My_INS_Instrumentation = traceEachINS ? True_INS : (traceEachBBL ? INS_IsBranchOrCall : INS_IsCall);

        rtn_num = RTN_Id(rtn);
        rtn_address = RTN_Address(rtn);
        rtn_name = RTN_Name(rtn).c_str();

        // Get the relative information for the current img.
        // Could cache this info for better performences?
        ADDRINT offset = IMG_LoadOffset(img);
        ADDRINT min_addr = min(IMG_StartAddress(img), IMG_LowAddress(img));
        ADDRINT max_addr = IMG_HighAddress(img);

#ifdef MY_DEBUG
            probelog << "[OFFSET]: " << offset <<  " for: " << img_name << endl << flush;
#endif  

#ifdef MY_DEBUG
        probelog << dec << trace_id << " <-tr Th-> "<< dec << PIN_ThreadId() << " 0x" << hex << (int)rtn_address << ": " << PIN_UndecorateSymbolName(rtn_name, UNDECORATION_COMPLETE) << endl << flush;
#endif

        for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
            unsigned int bbl_num = 0;
            for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {

                // Only instrument the calls in the blls for now
                if (My_INS_Instrumentation(ins)) {
                    // Normalize the binary image base for ASLR, and IDA mapping
                    ADDRINT ins_addr = 0x6E200000 + (INS_Address(ins) - offset);
                    if (start_address <= ins_addr && ins_addr <= end_address) {
#ifndef NO_DISASM
                        const string ins_asm = INS_Disassemble(ins);
                        trace_handler.disasm.setDisasm(ins_addr, ins_asm);
#endif
                        INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)InsBranchTaken, IARG_ADDRINT, ins_addr, IARG_ADDRINT, min_addr, IARG_ADDRINT, max_addr, IARG_THREAD_ID, IARG_CONTEXT, IARG_END);
                    }
                    else {
#ifdef MY_DEBUG
                        probelog << hex << ins_addr << " is outside of the image trace focus :" << hex << start_address << "," << end_address << endl << flush;
#endif
                    }
                }

            }
        }
    }

    if (++routine_call > 500) {
        trace_handler.save();
        routine_call = 0;
    }
}


void Fini(INT32 code, VOID *v) {
    trace_handler.stats();
    trace_handler.save();
    probelog << flush << endl;
    probelog.close();
}


INT32 Usage() {
    PIN_ERROR("This Pintool records the trace of an application\n"
              + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}


int main( INT32 argc, CHAR *argv[]) {
    probelog.open("C:\\log-tracer.txt");

    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) {
        return Usage();
    }

    if (KnobImageName.Value().size() > 0)
        imageNameProvided = true;

    if (KnobIncludeDLLs.Value() == "true")
        traceInsideDLLs = true;

    if (KnobTraceCalls.Value() == "true")
        traceCallOnly = true;

    if (KnobTraceBBLs.Value() == "true")
        traceEachBBL = true;

    if (KnobTraceINSs.Value() == "true")
        traceEachINS = true;


    start_address = string_to16(KnobAddressStart.Value());
    end_address = string_to16(KnobAddressEnd.Value());

    probelog << KnobImageName.Value() << " -> " << boolalpha << imageNameProvided << endl << flush;
    probelog << KnobIncludeDLLs.Value() << " -> " << boolalpha << traceInsideDLLs << endl << flush;
    probelog << "Start Address" << " -> " << hex << start_address << endl << flush;
    probelog << "End Address" << " -> " << hex << end_address << endl << flush;
    probelog << "traceCallOnly" << " -> " << boolalpha << traceCallOnly << endl << flush;
    probelog << "traceEachBBL" << " -> " << boolalpha << traceEachBBL << endl << flush;
    probelog << "traceEachINS" << " -> " << boolalpha << traceEachINS << endl << flush;

    TRACE_AddInstrumentFunction(TraceHandler_func, 0);
    PIN_AddFiniFunction(Fini, 0);
    
   	PIN_StartProgram();

    return 0;
}

