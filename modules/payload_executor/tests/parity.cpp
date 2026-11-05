#include "../internal/types.hpp"
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include <array>
#include <fstream>
#include <iterator>
#include <string>

using namespace vac;
using namespace vac::workers::payload_executor;
using Worker = int (__cdecl*)(const u8*, u8*, u32*);
using Packer = bool (__cdecl*)(const u8*, u32, u8*, u32*, u32*);
static unsigned cases = 0, failures = 0;
static u8 seed[32];
static u8 scratch[4096];
static LONG CALLBACK exceptionLog(PEXCEPTION_POINTERS e) {
    std::printf("exception %08lx at %p\n",e->ExceptionRecord->ExceptionCode,e->ExceptionRecord->ExceptionAddress);
    std::fflush(stdout); return EXCEPTION_CONTINUE_SEARCH;
}

static void check(const char* name, bool ok) {
    ++cases; if (!ok) ++failures;
    std::printf("%s %s\n", ok ? "OK" : "DIFF", name); std::fflush(stdout);
}
static Worker worker(HMODULE dll) {
    auto* base = reinterpret_cast<u8*>(dll);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    const auto* sections = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) continue;
        for (unsigned j = 0; j + 48 <= sections[i].Misc.VirtualSize; j += 4) {
            auto* p = base + sections[i].VirtualAddress + j;
            if (*reinterpret_cast<u32*>(p+4) == k_unModuleId && *reinterpret_cast<u32*>(p+8) == 1) {
                auto fn = *reinterpret_cast<Worker*>(p+12);
                if (reinterpret_cast<u8*>(fn) >= base && reinterpret_cast<u8*>(fn) < base + nt->OptionalHeader.SizeOfImage) return fn;
            }
        }
    }
    return nullptr;
}
static std::vector<u8> tlv(u8 tag, const std::vector<u8>& body) {
    std::vector<u8> result{tag};
    if (body.size()<128) result.push_back(static_cast<u8>(body.size()));
    else if (body.size()<256) { result.push_back(0x81); result.push_back(static_cast<u8>(body.size())); }
    else { result.push_back(0x82); result.push_back(static_cast<u8>(body.size()>>8)); result.push_back(static_cast<u8>(body.size())); }
    result.insert(result.end(),body.begin(),body.end()); return result;
}
static void append(std::vector<u8>& a, const std::vector<u8>& b) { a.insert(a.end(),b.begin(),b.end()); }
static std::vector<u8> packed(const std::vector<u8>& mod, const std::vector<u8>& exp) {
    auto inner = tlv(2,{0}); append(inner,tlv(2,mod)); append(inner,tlv(2,{3})); append(inner,tlv(2,exp));
    std::vector<u8> outer{2,1,0,0x30,0x0D,6,9,0x2A,0x86,0x48,0x86,0xF7,0x0D,1,1,1,5,0};
    append(outer,tlv(4,tlv(0x30,inner))); return tlv(0x30,outer);
}
static void __cdecl callback(ModuleSession_t* session, u32* pointer, Report_t* out) {
    std::memcpy(out->m_rgubReserved,session,sizeof(*session));
    std::memcpy(out->m_rgubReserved+sizeof(*session),pointer,4);
    *pointer = 0x1234ABCD;
    out->m_rgubReserved[sizeof(*session)+4] = 0x5A;
}
static bool initOriginal(HMODULE dll) {
    auto fn = reinterpret_cast<u8*>(dll)+0x35CE;
    Input_t input{}; std::memcpy(input.m_rgubBootstrap,seed,32);
    auto p = &input;
    bool ok;
    __asm { mov ecx,p
            call fn
            mov ok,al }
    return ok;
}
int main(int argc, char** argv) {
    std::puts("executor parity runner starting"); std::fflush(stdout);
    AddVectoredExceptionHandler(1,exceptionLog);
    if (argc!=4) return 2;
    // Keep the SDK's library set loaded on both sides. Otherwise loader holes
    // can change VirtualAlloc's returned address between sequential calls.
    for (const char* name : {"advapi32.dll","crypt32.dll","version.dll","psapi.dll",
                            "wintrust.dll","setupapi.dll","secur32.dll","userenv.dll",
                            "iphlpapi.dll","dbghelp.dll"}) LoadLibraryA(name);
    std::ifstream inputFile(argv[3],std::ios::binary);
    inputFile.read(reinterpret_cast<char*>(seed),32);
    if (!inputFile) return 3;
    HMODULE original=LoadLibraryA(argv[1]);
    std::printf("original=%p\n",original); std::fflush(stdout);
    HMODULE rebuild=LoadLibraryA(argv[2]);
    std::printf("rebuild=%p\n",rebuild); std::fflush(stdout);
    if (!original || !rebuild) { std::printf("load error %lu\n",GetLastError()); return 4; }
    Worker oldWorker=worker(original), newWorker=worker(rebuild);
    std::printf("workers %p %p\n",oldWorker,newWorker); std::fflush(stdout);
    if (!oldWorker || !newWorker) return 5;
    auto oldPacker=reinterpret_cast<Packer>(reinterpret_cast<u8*>(original)+0x2435);
    auto cleanup=reinterpret_cast<void(__cdecl*)()>(reinterpret_cast<u8*>(original)+0x368E);
    auto* stubPage=static_cast<u8*>(VirtualAlloc(nullptr,4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    if (!stubPage) return 6;
    // __cdecl stub: write a fixed marker to output.m_rgubReserved and return.
    const u8 stub[]={0x8B,0x44,0x24,0x0C,0xC7,0x40,0x30,0x5A,0x5A,0xA5,0xA5,0xC3};
    std::memcpy(stubPage+32,stub,sizeof(stub));
    auto runWorker=[&](const char* name, u32 flags, u32 allocSize, u32 cap,
                       const std::vector<u8>& blob, bool useCallback=false) {
        Input_t initial{}; std::memcpy(initial.m_rgubBootstrap,seed,32);
        initial.m_eFlags=static_cast<EPayloadFlags>(flags); initial.m_cubAllocation=allocSize;
        initial.m_unDataPointer=static_cast<u32>(reinterpret_cast<uptr>(useCallback ? reinterpret_cast<void*>(callback) : scratch));
        const bool stubCall = (flags & static_cast<u32>(EPayloadFlags::Call)) && !useCallback;
        if (stubCall) { initial.m_unDataPointer=static_cast<u32>(reinterpret_cast<uptr>(stubPage)); initial.m_ibEntry=32; }
        initial.m_cubPacked=static_cast<u32>(blob.size());
        if (blob.size()>100) return;
        std::memcpy(initial.m_rgubPackedBlob,blob.data(),blob.size());
        Input_t a=initial,b=initial;
        std::array<u8,8192> left{},right{};
        u32 sa=cap,sb=cap;
        std::memset(scratch,0xA5,sizeof(scratch));
        if (stubCall) { DWORD old; VirtualProtect(stubPage,4096,PAGE_READWRITE,&old); }
        int ra=oldWorker(reinterpret_cast<u8*>(&a),left.data(),&sa);
        if (cap>=0xFD0) {
            auto& out=*reinterpret_cast<Report_t*>(left.data());
            if (out.m_unAllocatedMemory) VirtualFree(reinterpret_cast<void*>(static_cast<uptr>(out.m_unAllocatedMemory)),0,MEM_RELEASE);
        }
        std::memset(scratch,0xA5,sizeof(scratch));
        if (stubCall) { DWORD old; VirtualProtect(stubPage,4096,PAGE_READWRITE,&old); }
        int rb=newWorker(reinterpret_cast<u8*>(&b),right.data(),&sb);
        if (cap>=0xFD0) {
            auto& out=*reinterpret_cast<Report_t*>(right.data());
            if (out.m_unAllocatedMemory) VirtualFree(reinterpret_cast<void*>(static_cast<uptr>(out.m_unAllocatedMemory)),0,MEM_RELEASE);
        }
        bool ok=ra==rb && sa==sb && left==right && std::memcmp(&a,&b,sizeof(a))==0;
        if (!ok) {
            std::printf("ret=%d/%d size=%u/%u\n",ra,rb,sa,sb);
            unsigned shown=0;
            for (unsigned i=0;i<4096 && shown<16;++i) if(left[i]!=right[i]) {
                std::printf("  +%x %02x/%02x\n",i,left[i],right[i]); ++shown;
            }
        }
        check(name,ok);
    };
    // Warm both import resolvers before comparing address-bearing allocations.
    runWorker("noop",0,0,4096,{});
    for (u32 cap : {0u,0xFCFu,0xFD0u,4096u,8192u}) runWorker(("capacity_"+std::to_string(cap)).c_str(),0,0,cap,{});
    for (u32 flags : {1u,0x80u,0xFFFFFF81u,4u,16u,64u,4u|16u,4u|64u})
        runWorker(("flags_"+std::to_string(flags)).c_str(),flags,0,4096,{});
    for (u32 size : {0u,1u,4096u,0x4000u,0xFFFFFFFFu})
        runWorker(("allocate_"+std::to_string(size)).c_str(),2,size,4096,{});
    for (u32 flags : {2u|16u,2u|64u,2u|16u|64u,2u|4u,2u|4u|16u})
        runWorker(("combined_"+std::to_string(flags)).c_str(),flags,4096,4096,{});
    runWorker("callback_session",4|32,0,4096,{},true);
    runWorker("protect_and_call_stub",4|16|32,4096,4096,{});
    runWorker("protect_call_failed_release",4|16|32|64,4096,4096,{});
    for (auto bytes : {std::vector<u8>{},std::vector<u8>{0},std::vector<u8>{0x30,0},
                       std::vector<u8>{0x30,0x80},std::vector<u8>{0x30,0x82,0xFF,0xFF}})
        runWorker(("worker_bad_blob_"+std::to_string(bytes.size())+"_"+std::to_string(cases)).c_str(),8,0,4096,bytes);
    for (u8 n : {u8(1),u8(2),u8(3),u8(17),u8(251)})
        runWorker(("worker_rsa_"+std::to_string(n)).c_str(),4|8,4096,4096,packed({n},{3}));

    auto runPacker=[&](const std::string& name,const std::vector<u8>& blob,u32 cap) {
        if (!initOriginal(original)) { check("original bootstrap",false); return; }
        std::array<u8,2048> a,b; a.fill(0xA5); b.fill(0xA5);
        u32 sa=cap,sb=cap,ea=0x77777777,eb=ea;
        bool ra=oldPacker(blob.data(),static_cast<u32>(blob.size()),a.data(),&sa,&ea);
        cleanup();
        bool rb=DecryptPayload(blob.data(),static_cast<u32>(blob.size()),b.data(),&sb,&eb);
        if (ra!=rb || sa!=sb || ea!=eb || a!=b)
            std::printf("packer ret=%d/%d size=%u/%u err=%u/%u\n",ra,rb,sa,sb,ea,eb);
        check(name.c_str(),ra==rb && sa==sb && ea==eb && a==b);
    };
    for (u8 n : {u8(0),u8(1),u8(2),u8(3),u8(17),u8(251)})
        for (u8 d : {u8(0),u8(1),u8(3),u8(17)})
            for (u32 cap : {0u,1u,16u})
                runPacker("rsa_"+std::to_string(n)+"_"+std::to_string(d)+"_"+std::to_string(cap),packed({n},{d}),cap);
    auto good=packed({0,0x80,1},{1,0,1});
    for (unsigned length=0;length<good.size();++length)
        runPacker("truncated_"+std::to_string(length),std::vector<u8>(good.begin(),good.begin()+length),16);
    for (unsigned pos=0;pos<good.size();++pos) {
        auto bad=good; bad[pos]^=0x80;
        runPacker("mutated_"+std::to_string(pos),bad,16);
    }
    std::vector<u8> huge(1025,0); huge[0]=1;
    runPacker("modulus_8193_bits",packed(huge,{1}),16);
    VirtualFree(stubPage,0,MEM_RELEASE);
    std::printf("RESULT %u cases, %u failures\n",cases,failures);
    return failures ? 1 : 0;
}
