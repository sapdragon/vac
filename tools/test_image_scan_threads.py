import argparse
import json
import struct
import subprocess
from pathlib import Path

import compare_vac_worker as cmp
from test_image_scan_edges import file_id_and_volume, write_test_files

ROOT=Path(__file__).resolve().parents[1]
ORIGINAL=ROOT.parent/'vac-research/ptr_0x0D2534F8_crc_74aa703a_ProcessBaseInfo_unk/module.dll'
REBUILD=ROOT/'build/Release/Win32/image_scan_threads.dll'
THREAD_ID=0x0122C7DA
PE_ID=0x05A52008

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--only',default='')
    args=ap.parse_args()
    dest=ROOT/'build/74aa703a_parity'; dest.mkdir(exist_ok=True)
    pe1,pe2=cmp.PeImage(ORIGINAL),cmp.PeImage(REBUILD)
    nodes={mid:(cmp.find_single_node(pe1,mid,1,'original'),cmp.find_single_node(pe2,mid,1,'rebuild')) for mid in (THREAD_ID,PE_ID)}
    packet=cmp.read_packet(ORIGINAL.parent/'inputVacPacket_ScanId_4.bin')
    pn=cmp.find_single_node(pe1,packet.module_id,packet.version,'packet')
    seed=cmp.ice_decrypt_buffer(pn.ice_key[:8],packet.encrypted_payload)
    if cmp.crc32_ieee(seed)!=packet.crc32: raise ValueError('packet CRC')
    results=[]
    def payload(pid=0):
        p=bytearray(160); p[:32]=seed[:32]; struct.pack_into('<I',p,96,pid); return p
    def run(name,mid,p,cap=4096):
        if args.only and args.only not in name: return
        a,b=nodes[mid]
        info,original,rebuild=cmp.invoke_workers_with_powershell(ORIGINAL,a.worker_rva,REBUILD,b.worker_rva,bytes(p),cap)
        n,first,ranges=cmp.diff_ranges(original,rebuild,4096)
        equal=all(info['original'][k]==info['rebuild'][k] for k in ('ret','size'))
        d=dest/name; d.mkdir(exist_ok=True)
        (d/'original.bin').write_bytes(original); (d/'rebuild.bin').write_bytes(rebuild); (d/'payload.bin').write_bytes(p)
        result=dict(case=name,diff=n,first=first,ranges=ranges,envelope_equal=equal,
                    original_return=info['original']['ret'],rebuild_return=info['rebuild']['ret'],
                    original_size=info['original']['size'],rebuild_size=info['rebuild']['size'])
        results.append(result); print(json.dumps(dict(result,ranges=ranges[:12])),flush=True)
    run('captured_packet',packet.module_id,seed)
    for pid in (0,4,0xffffffff,0x7ffffffe):
        run(f'threads_pid_{pid}',THREAD_ID,payload(pid))
        p=payload(pid); p[32]=1
        run(f'pe_pid_{pid}',PE_ID,p)
    for cap in (0,4095,4096,8192): run(f'threads_capacity_{cap}',THREAD_ID,payload(),cap)
    for cap in (0xFB7,0xFB8):
        p=payload(0xffffffff); p[32]=1
        run(f'pe_capacity_{cap}',PE_ID,p,cap)
    for arch in ('Win32','x64'):
        for count in (1,4,252,253,300):
            name=f'{arch}_{count}'
            if args.only and args.only not in name: continue
            exe=ROOT/f'build/tests/{arch}/thread_fixture.exe'
            proc=subprocess.Popen([str(exe),str(count)],stdout=subprocess.PIPE,text=True,
                                  creationflags=subprocess.CREATE_NO_WINDOW)
            try:
                if proc.stdout.readline().strip()!='ready': raise RuntimeError('fixture failed')
                run('threads_'+name,THREAD_ID,payload(proc.pid))
                if count==4:
                    p=payload(proc.pid); p[32]=1
                    run('pe_'+name,PE_ID,p)
            finally:
                proc.terminate(); proc.wait(timeout=5)
    files=write_test_files(dest/'fixtures')
    files['rebuilt_pe']=REBUILD
    for name,path in files.items():
        fid,volume=file_id_and_volume(path)
        p=payload(); struct.pack_into('<QI',p,100,fid,volume)
        run('pe_local_'+name,PE_ID,p)
    (dest/'results.json').write_text(json.dumps(results,indent=2))
    return int(any(r['diff'] or not r['envelope_equal'] for r in results))

if __name__=='__main__': raise SystemExit(main())
